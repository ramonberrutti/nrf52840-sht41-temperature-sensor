#![no_std]
#![no_main]

use aes::Aes128;
use ccm::{
    Ccm,
    aead::{AeadInPlace, KeyInit},
    consts::{U4, U13},
};
use defmt::*;
use embassy_executor::Spawner;
use embassy_nrf::radio;
use embassy_nrf::radio::ieee802154::{Packet, Radio};
use embassy_nrf::{
    bind_interrupts,
    interrupt::Priority,
    peripherals,
    twim::{self, Twim},
};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_hal_async::i2c::I2c;
use heapless::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
    TWISPI0 => twim::InterruptHandler<peripherals::TWISPI0>;
});

const SHT41_ADDR: u8 = 0x44;
const CMD_MEASURE_HIGH_PRECISION: u8 = 0xFD;
static TWIM_BUFFER: StaticCell<[u8; 16]> = StaticCell::new();

const DEFAULT_CHANNEL: u8 = 15;
const DEFAULT_PAN_ID: u16 = 0x06e6;
const MAX_ROUTERS: usize = 8;
const MAX_NETWORK_NAME_LEN: usize = 32;
const THREAD_DATASET_HEX: Option<&str> = option_env!("THREAD_DATASET");

const LOCAL_EXT_ADDR: u64 = 0x0200_0000_0000_0001;
const LOCAL_MLE_FRAME_COUNTER_START: u32 = 1;
const THREAD_VERSION_1_4: u16 = 5;
const MLE_UDP_PORT: u16 = 19788;
const MLE_SECURITY_SUITE_154: u8 = 0x00;
const IEEE802154_SECURITY_LEVEL_ENC_MIC32: u8 = 5;
const MLE_AUX_SECURITY_CONTROL: u8 = 0x15;
const MAC_AUX_SECURITY_CONTROL_KEYIDMODE1: u8 = 0x0d;
const MLE_SECURITY_HEADER_LEN: usize = 10;
const MLE_SECURITY_TAG_LEN: usize = 4;
const BEACON_REQUEST_INTERVAL: Duration = Duration::from_secs(2);
const DISCOVERY_SETTLE_TIME: Duration = Duration::from_secs(5);
const PARENT_RESPONSE_WINDOW: Duration = Duration::from_secs(3);
const SECOND_PARENT_REQUEST_DELAY: Duration = Duration::from_millis(200);
const TABLE_LOG_INTERVAL: Duration = Duration::from_secs(5);
const RX_POLL_TIMEOUT: Duration = Duration::from_millis(250);

const MLE_CMD_PARENT_REQUEST: u8 = 9;
const MLE_CMD_PARENT_RESPONSE: u8 = 10;

const MLE_TLV_SOURCE_ADDRESS: u8 = 0;
const MLE_TLV_MODE: u8 = 1;
const MLE_TLV_CHALLENGE: u8 = 3;
const MLE_TLV_RESPONSE: u8 = 4;
const MLE_TLV_SCAN_MASK: u8 = 12;
const MLE_TLV_LINK_MARGIN: u8 = 14;
const MLE_TLV_VERSION: u8 = 16;

const SCAN_MASK_ROUTER: u8 = 1 << 7;
const SCAN_MASK_END_DEVICE: u8 = 1 << 6;
const SCAN_MASK_ROUTER_AND_END_DEVICE: u8 = SCAN_MASK_ROUTER | SCAN_MASK_END_DEVICE;
const DEVICE_MODE_RX_ON_WHEN_IDLE: u8 = 1 << 3;
const DEVICE_MODE_SECURE_DATA_REQUESTS: u8 = 1 << 2;
const DEVICE_MODE_FULL_NETWORK_DATA: u8 = 1 << 0;
const DEVICE_MODE_MED: u8 = DEVICE_MODE_RX_ON_WHEN_IDLE
    | DEVICE_MODE_SECURE_DATA_REQUESTS
    | DEVICE_MODE_FULL_NETWORK_DATA;

type HmacSha256 = Hmac<Sha256>;
type AesCcmMic4 = Ccm<Aes128, U4, U13>;

#[derive(Clone, Copy)]
struct ActiveDataset {
    channel: Option<u8>,
    pan_id: Option<u16>,
    ext_pan_id: Option<[u8; 8]>,
    network_key: Option<[u8; 16]>,
    network_name: NetworkName,
}

impl ActiveDataset {
    fn channel_or_default(&self) -> u8 {
        self.channel.unwrap_or(DEFAULT_CHANNEL)
    }

    fn pan_id_or_default(&self) -> u16 {
        self.pan_id.unwrap_or(DEFAULT_PAN_ID)
    }
}

#[derive(Clone, Copy)]
struct NetworkName {
    bytes: [u8; MAX_NETWORK_NAME_LEN],
    len: usize,
}

impl NetworkName {
    const fn empty() -> Self {
        Self {
            bytes: [0; MAX_NETWORK_NAME_LEN],
            len: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct ThreadKeyMaterial {
    key_sequence: u32,
    key_id: u8,
    mle_key: [u8; 16],
    mac_key: [u8; 16],
}

#[derive(Clone, Copy)]
struct RouterInfo {
    ext_addr: u64,
    pan_id: u16,
    last_lqi: u8,
    beacon_count: u32,
}

#[derive(Clone, Copy, defmt::Format)]
struct ParentResponseInfo {
    ext_addr: u64,
    rloc16: Option<u16>,
    link_margin: Option<u8>,
    version: Option<u16>,
    response_matches: bool,
}

#[derive(Clone, Copy)]
struct LocalThreadDevice {
    ext_addr: u64,
    seq: u8,
    mle_frame_counter: u32,
}

impl LocalThreadDevice {
    fn next_seq(&mut self) -> u8 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn next_mle_frame_counter(&mut self) -> u32 {
        let value = self.mle_frame_counter;
        self.mle_frame_counter = self.mle_frame_counter.wrapping_add(1);
        value
    }
}

#[derive(Clone, Copy)]
enum AttachPhase {
    Discovering {
        started_at: Instant,
    },
    WaitingParentResponse {
        challenge: [u8; 8],
        sent_at: Instant,
        preferred_parent: Option<u64>,
        best_response: Option<ParentResponseInfo>,
    },
    ParentAccepted {
        parent: ParentResponseInfo,
    },
}

#[derive(Clone, Copy, defmt::Format)]
enum FrameType {
    Beacon,
    Data,
    Ack,
    MacCommand,
    Unknown(u8),
}

impl FrameType {
    fn is_ack(self) -> bool {
        matches!(self, FrameType::Ack)
    }

    fn is_beacon(self) -> bool {
        matches!(self, FrameType::Beacon)
    }

    fn is_data(self) -> bool {
        matches!(self, FrameType::Data)
    }
}

#[derive(Clone, Copy, defmt::Format)]
enum AddrMode {
    None,
    Short,
    Extended,
    Reserved,
}

#[derive(Clone, Copy)]
struct ParsedSrcAddr {
    pan_id: Option<u16>,
    short_addr: Option<u16>,
    ext_addr: Option<u64>,
}

struct Cursor<'a> {
    frame: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(frame: &'a [u8]) -> Self {
        Self { frame, i: 0 }
    }

    fn remaining(&self) -> usize {
        self.frame.len().saturating_sub(self.i)
    }

    fn remaining_slice(&self) -> &'a [u8] {
        &self.frame[self.i..]
    }

    fn u8(&mut self) -> Option<u8> {
        if self.remaining() < 1 {
            return None;
        }
        let value = self.frame[self.i];
        self.i += 1;
        Some(value)
    }

    fn u16_le(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let value = u16::from_le_bytes([self.frame[self.i], self.frame[self.i + 1]]);
        self.i += 2;
        Some(value)
    }

    fn u16_be(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let value = u16::from_be_bytes([self.frame[self.i], self.frame[self.i + 1]]);
        self.i += 2;
        Some(value)
    }

    fn u64_le(&mut self) -> Option<u64> {
        if self.remaining() < 8 {
            return None;
        }
        let value = u64::from_le_bytes([
            self.frame[self.i],
            self.frame[self.i + 1],
            self.frame[self.i + 2],
            self.frame[self.i + 3],
            self.frame[self.i + 4],
            self.frame[self.i + 5],
            self.frame[self.i + 6],
            self.frame[self.i + 7],
        ]);
        self.i += 8;
        Some(value)
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.remaining() < len {
            return None;
        }
        let slice = &self.frame[self.i..self.i + len];
        self.i += len;
        Some(slice)
    }
}

struct FrameControl {
    frame_type: FrameType,
    security_enabled: bool,
    pan_compression: bool,
    frame_version: u16,
    dst_mode: AddrMode,
    src_mode: AddrMode,
}

#[derive(Clone, Copy)]
struct MacSecurityHeader {
    security_control: u8,
    security_level: u8,
    key_id_mode: u8,
    frame_counter: Option<u32>,
}

#[derive(Debug)]
pub enum Sht41Error<E> {
    I2c(E),
    Crc,
}

pub struct Sht41<I2C> {
    i2c: I2C,
}

impl<I2C> Sht41<I2C>
where
    I2C: I2c,
{
    pub fn new(i2c: I2C) -> Self {
        Self { i2c }
    }

    pub async fn read(&mut self) -> Result<(f32, f32), Sht41Error<I2C::Error>> {
        trace!("sending measurement command");

        self.i2c
            .write(SHT41_ADDR, &[CMD_MEASURE_HIGH_PRECISION])
            .await
            .map_err(|e| {
                warn!("i2c write failed");
                Sht41Error::I2c(e)
            })?;

        Timer::after(Duration::from_millis(20)).await;

        let mut buf = [0u8; 6];

        self.i2c.read(SHT41_ADDR, &mut buf).await.map_err(|e| {
            warn!("i2c read failed");
            Sht41Error::I2c(e)
        })?;

        let temp_crc = crc8(&buf[0..2]);
        let rh_crc = crc8(&buf[3..5]);

        if temp_crc != buf[2] || rh_crc != buf[5] {
            warn!("crc mismatch");
            return Err(Sht41Error::Crc);
        }

        let raw_t = u16::from_be_bytes([buf[0], buf[1]]) as f32;
        let raw_rh = u16::from_be_bytes([buf[3], buf[4]]) as f32;

        let temperature_c = -45.0 + 175.0 * raw_t / 65535.0;
        let humidity_rh = -6.0 + 125.0 * raw_rh / 65535.0;

        Ok((temperature_c, humidity_rh.clamp(0.0, 100.0)))
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.gpiote_interrupt_priority = Priority::P2;
    config.time_interrupt_priority = Priority::P2;
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;

    let p = embassy_nrf::init(config);

    let active_dataset = parse_thread_dataset_from_env();
    log_active_dataset(&active_dataset);

    let Some(thread_keys) = derive_thread_key_material(&active_dataset, 0) else {
        warn!("network key missing from dataset; cannot build MLE Parent Request");
        defmt::panic!("Thread Active Dataset must include network key");
    };
    log_thread_key_material(&thread_keys);

    let mut radio = Radio::new(p.RADIO, Irqs);
    radio.set_channel(active_dataset.channel_or_default());

    info!(
        "radio enabled on channel={} pan_id={=u16:04x}",
        active_dataset.channel_or_default(),
        active_dataset.pan_id_or_default()
    );

    let sda = p.P0_20;
    let scl = p.P0_22;
    let mut twim_config = twim::Config::default();
    twim_config.frequency = twim::Frequency::K100;
    let twim_buffer = TWIM_BUFFER.init([0u8; 16]);
    let i2c = Twim::new(p.TWISPI0, Irqs, sda, scl, twim_config, twim_buffer);
    let sht41 = Sht41::new(i2c);
    spawner.spawn(temperature_measurement(sht41).unwrap());

    info!("Thread child attach experiment started");

    let mut routers: [Option<RouterInfo>; MAX_ROUTERS] = [None; MAX_ROUTERS];
    let mut local = LocalThreadDevice {
        ext_addr: LOCAL_EXT_ADDR,
        seq: 0,
        mle_frame_counter: LOCAL_MLE_FRAME_COUNTER_START,
    };
    let mut attach_phase = AttachPhase::Discovering {
        started_at: Instant::now(),
    };
    send_beacon_request(&mut radio).await;
    let mut last_beacon_request = Instant::now();
    let mut last_table_log = Instant::now();
    let mut rx_ok: u32 = 0;
    let mut rx_err: u32 = 0;

    loop {
        let mut packet = Packet::new();

        match with_timeout(RX_POLL_TIMEOUT, radio.receive(&mut packet)).await {
            Ok(Ok(())) => {
                rx_ok = rx_ok.wrapping_add(1);
                process_received_frame(
                    &packet,
                    packet.lqi(),
                    active_dataset.pan_id_or_default(),
                    &thread_keys,
                    &mut routers,
                    &mut attach_phase,
                );
            }
            Ok(Err(_)) => {
                rx_err = rx_err.wrapping_add(1);
            }
            Err(_) => {}
        }

        if last_beacon_request.elapsed() >= BEACON_REQUEST_INTERVAL {
            send_beacon_request(&mut radio).await;
            last_beacon_request = Instant::now();
        }

        if last_table_log.elapsed() >= TABLE_LOG_INTERVAL {
            print_router_table(active_dataset.pan_id_or_default(), &routers);
            info!("attach phase={}", attach_phase_name(&attach_phase));
            info!("rx_ok={} rx_err={}", rx_ok, rx_err);
            last_table_log = Instant::now();
        }

        match attach_phase {
            AttachPhase::Discovering { started_at } => {
                if started_at.elapsed() >= DISCOVERY_SETTLE_TIME {
                    let preferred_parent = select_best_parent(&routers);

                    if let Some(parent) = preferred_parent {
                        let challenge = build_parent_request_challenge(local.next_seq());
                        info!(
                            "selected parent ext={=u64:016x} lqi={} beacons={}",
                            parent.ext_addr, parent.last_lqi, parent.beacon_count
                        );

                        send_mle_parent_request(
                            &mut radio,
                            &active_dataset,
                            &thread_keys,
                            &mut local,
                            challenge,
                        )
                        .await;

                        attach_phase = AttachPhase::WaitingParentResponse {
                            challenge,
                            sent_at: Instant::now(),
                            preferred_parent: Some(parent.ext_addr),
                            best_response: None,
                        };
                    } else {
                        info!("no routers discovered yet; continuing active scan");
                    }
                }
            }

            AttachPhase::WaitingParentResponse {
                challenge,
                sent_at,
                preferred_parent,
                best_response,
            } => {
                if sent_at.elapsed() >= PARENT_RESPONSE_WINDOW {
                    if let Some(parent) = best_response {
                        info!(
                            "parent accepted ext={=u64:016x} rloc16={=?} version={=?} link_margin={=?}",
                            parent.ext_addr, parent.rloc16, parent.version, parent.link_margin
                        );
                        attach_phase = AttachPhase::ParentAccepted { parent };
                    } else {
                        warn!("no valid Parent Response received; retrying attach scan");
                        attach_phase = AttachPhase::Discovering {
                            started_at: Instant::now(),
                        };
                    }
                } else {
                    let _ = (challenge, preferred_parent);
                }
            }

            AttachPhase::ParentAccepted { parent } => {
                let _ = parent;
            }
        }
    }
}

#[embassy_executor::task]
async fn temperature_measurement(mut sht41: Sht41<Twim<'static>>) -> ! {
    loop {
        match sht41.read().await {
            Ok((temp_c, rh)) => {
                info!("temperature: {} C, humidity: {} %RH", temp_c, rh);
            }
            Err(e) => {
                warn!("SHT41 read failed: {:?}", defmt::Debug2Format(&e));
            }
        }

        Timer::after(Duration::from_secs(10)).await;
    }
}

async fn send_beacon_request(radio: &mut Radio<'_>) {
    let mut tx = Packet::new();
    let seq = 1u8;
    let frame = [
        0x03, 0x08, // MAC command frame
        seq, 0xff, 0xff, // dst PAN
        0xff, 0xff, // broadcast short address
        0x07, // Beacon Request
    ];

    tx.copy_from_slice(&frame);

    match radio.try_send(&mut tx).await {
        Ok(_) => info!("TX Beacon Request"),
        Err(_) => warn!("Beacon Request TX failed"),
    }
}

async fn send_mle_parent_request(
    radio: &mut Radio<'_>,
    dataset: &ActiveDataset,
    keys: &ThreadKeyMaterial,
    local: &mut LocalThreadDevice,
    challenge: [u8; 8],
) {
    let seq = local.next_seq();
    let mle_frame_counter = local.next_mle_frame_counter();

    let multicast_dst = link_local_all_routers();
    let Some(mle_payload) = build_mle_parent_request_payload(
        local.ext_addr,
        multicast_dst,
        mle_frame_counter,
        keys,
        challenge,
        SCAN_MASK_ROUTER,
    )
    else {
        warn!("failed building MLE Parent Request payload");
        return;
    };

    let src_addr = link_local_from_ext_addr(local.ext_addr);
    let Some(lowpan_payload) = build_uncompressed_ipv6_udp_packet(
        src_addr,
        multicast_dst,
        MLE_UDP_PORT,
        MLE_UDP_PORT,
        mle_payload.as_slice(),
    ) else {
        warn!("failed building IPv6 Parent Request");
        return;
    };

    let pan_id = dataset.pan_id_or_default();
    let fcf: u16 = 0xd841; // Data frame, PAN compression, dst short/broadcast, src extended.

    let mut frame: Vec<u8, 127> = Vec::new();
    push_u16_le(&mut frame, fcf);
    frame.push(seq).ok();
    push_u16_le(&mut frame, pan_id);
    push_u16_le(&mut frame, 0xffff);
    frame.extend_from_slice(&local.ext_addr.to_le_bytes()).ok();
    frame.extend_from_slice(lowpan_payload.as_slice()).ok();

    let mut tx = Packet::new();
    tx.copy_from_slice(frame.as_slice());

    info!(
        "TX MLE Parent Request seq={} mle_frame_counter={} src_ext={=u64:016x}",
        seq, mle_frame_counter, local.ext_addr
    );

    match radio.try_send(&mut tx).await {
        Ok(_) => info!("MLE Parent Request router-only multicast sent"),
        Err(_) => warn!("MLE Parent Request multicast TX failed"),
    }

    Timer::after(SECOND_PARENT_REQUEST_DELAY).await;

    let Some(second_mle_payload) = build_mle_parent_request_payload(
        local.ext_addr,
        multicast_dst,
        mle_frame_counter,
        keys,
        challenge,
        SCAN_MASK_ROUTER_AND_END_DEVICE,
    ) else {
        warn!("failed building second MLE Parent Request payload");
        return;
    };

    let Some(second_lowpan_payload) = build_uncompressed_ipv6_udp_packet(
        src_addr,
        multicast_dst,
        MLE_UDP_PORT,
        MLE_UDP_PORT,
        second_mle_payload.as_slice(),
    ) else {
        warn!("failed building second IPv6 Parent Request");
        return;
    };

    let mut second_frame: Vec<u8, 127> = Vec::new();
    push_u16_le(&mut second_frame, fcf);
    second_frame.push(seq.wrapping_add(1)).ok();
    push_u16_le(&mut second_frame, pan_id);
    push_u16_le(&mut second_frame, 0xffff);
    second_frame
        .extend_from_slice(&local.ext_addr.to_le_bytes())
        .ok();
    second_frame
        .extend_from_slice(second_lowpan_payload.as_slice())
        .ok();

    let mut second_tx = Packet::new();
    second_tx.copy_from_slice(second_frame.as_slice());

    match radio.try_send(&mut second_tx).await {
        Ok(_) => info!("MLE Parent Request router+reed multicast sent"),
        Err(_) => warn!("second MLE Parent Request multicast TX failed"),
    }
}

fn build_mle_parent_request_payload(
    src_ext_addr: u64,
    dst_addr: [u8; 16],
    mle_frame_counter: u32,
    keys: &ThreadKeyMaterial,
    challenge: [u8; 8],
    scan_mask: u8,
) -> Option<Vec<u8, 128>> {
    let src_addr = link_local_from_ext_addr(src_ext_addr);

    let mut payload: Vec<u8, 128> = Vec::new();
    payload.push(MLE_SECURITY_SUITE_154).ok()?;
    payload.push(MLE_AUX_SECURITY_CONTROL).ok()?;
    payload
        .extend_from_slice(&mle_frame_counter.to_le_bytes())
        .ok()?;
    payload
        .extend_from_slice(&keys.key_sequence.to_be_bytes())
        .ok()?;
    payload.push(keys.key_id).ok()?;

    let aad = build_mle_aad(src_addr, dst_addr, &payload[1..1 + MLE_SECURITY_HEADER_LEN])?;

    let mut plaintext: Vec<u8, 64> = Vec::new();
    plaintext.push(MLE_CMD_PARENT_REQUEST).ok()?;
    push_tlv(&mut plaintext, MLE_TLV_MODE, &[DEVICE_MODE_MED])?;
    push_tlv(&mut plaintext, MLE_TLV_CHALLENGE, &challenge)?;
    push_tlv(&mut plaintext, MLE_TLV_SCAN_MASK, &[scan_mask])?;
    push_tlv(
        &mut plaintext,
        MLE_TLV_VERSION,
        &THREAD_VERSION_1_4.to_be_bytes(),
    )?;

    let nonce = build_mle_nonce(src_ext_addr, mle_frame_counter);
    let cipher = AesCcmMic4::new_from_slice(&keys.mle_key).ok()?;
    let mut encrypted = plaintext;
    let tag = cipher
        .encrypt_in_place_detached((&nonce).into(), aad.as_slice(), &mut encrypted)
        .ok()?;

    payload.extend_from_slice(encrypted.as_slice()).ok()?;
    payload.extend_from_slice(tag.as_slice()).ok()?;
    Some(payload)
}

fn build_uncompressed_ipv6_udp_packet(
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> Option<Vec<u8, 128>> {
    let udp_len = 8usize.checked_add(udp_payload.len())?;
    let ipv6_payload_len = u16::try_from(udp_len).ok()?;

    let mut packet: Vec<u8, 128> = Vec::new();
    packet.push(0x41).ok()?; // 6LoWPAN uncompressed IPv6

    packet
        .extend_from_slice(&[
            0x60, 0x00, 0x00, 0x00, // version + traffic class + flow label
        ])
        .ok()?;
    packet
        .extend_from_slice(&ipv6_payload_len.to_be_bytes())
        .ok()?;
    packet.push(17).ok()?; // UDP
    packet.push(255).ok()?; // hop limit
    packet.extend_from_slice(&src_addr).ok()?;
    packet.extend_from_slice(&dst_addr).ok()?;

    let mut udp_header = [0u8; 8];
    udp_header[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp_header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp_header[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());

    let checksum = udp_checksum(src_addr, dst_addr, &udp_header, udp_payload);
    udp_header[6..8].copy_from_slice(&checksum.to_be_bytes());

    packet.extend_from_slice(&udp_header).ok()?;
    packet.extend_from_slice(udp_payload).ok()?;
    Some(packet)
}

fn process_received_frame(
    packet: &Packet,
    lqi: u8,
    active_pan_id: u16,
    keys: &ThreadKeyMaterial,
    routers: &mut [Option<RouterInfo>; MAX_ROUTERS],
    attach_phase: &mut AttachPhase,
) {
    let frame: &[u8] = packet;
    let mut cursor = Cursor::new(frame);

    let Some(fcf_raw) = cursor.u16_le() else {
        warn!("short frame missing FCF");
        return;
    };
    let Some(seq) = cursor.u8() else {
        warn!("short frame missing sequence");
        return;
    };

    let fcf = parse_fcf(fcf_raw);

    if fcf.frame_type.is_ack() {
        debug!("ACK seq={}", seq);
        return;
    }

    debug!(
        "802.15.4 type={} seq={} security={} ver={} dst_mode={} src_mode={}",
        fcf.frame_type, seq, fcf.security_enabled, fcf.frame_version, fcf.dst_mode, fcf.src_mode
    );

    let dst_pan = match parse_dst_addr(&mut cursor, fcf.dst_mode) {
        Some(v) => v,
        None => return,
    };

    if let Some(pan) = dst_pan {
        if pan != 0xffff && pan != active_pan_id {
            return;
        }
    }

    let Some(src) = parse_src_addr(&mut cursor, fcf.src_mode, fcf.pan_compression, dst_pan) else {
        return;
    };

    if fcf.frame_type.is_beacon() {
        if let (Some(pan_id), Some(ext_addr)) = (src.pan_id, src.ext_addr) {
            if pan_id == active_pan_id {
                remember_router(routers, ext_addr, pan_id, lqi);
            }
        }
        return;
    }

    if !fcf.frame_type.is_data() {
        return;
    }

    let (payload, effective_src_ext) = if fcf.security_enabled {
        let Some(security) = parse_security_header(&mut cursor) else {
            if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
                debug!("drop secured MAC frame: failed parsing aux security header");
            }
            return;
        };

        let aad = &frame[..cursor.i];

        match src.ext_addr {
            Some(src_ext_addr) => {
                match decrypt_mac_payload(
                    cursor.remaining_slice(),
                    aad,
                    src_ext_addr,
                    security,
                    keys,
                ) {
                    Some(plaintext) => (plaintext, Some(src_ext_addr)),
                    None => return,
                }
            }
            None => {
                let mut decrypted = None;
                let mut matched_src_ext = None;
                let preferred_parent = match *attach_phase {
                    AttachPhase::WaitingParentResponse {
                        preferred_parent, ..
                    } => preferred_parent,
                    _ => None,
                };

                if let Some(parent_ext) = preferred_parent {
                    decrypted = decrypt_mac_payload(
                        cursor.remaining_slice(),
                        aad,
                        parent_ext,
                        security,
                        keys,
                    );

                    if decrypted.is_some() {
                        matched_src_ext = Some(parent_ext);
                        if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
                            info!(
                                "secured MAC decrypt matched preferred parent ext={=u64:016x} short_src={=?}",
                                parent_ext, src.short_addr
                            );
                        }
                    }
                }

                if decrypted.is_none() {
                    for router in routers.iter().flatten() {
                        if Some(router.ext_addr) == preferred_parent {
                            continue;
                        }

                        decrypted = decrypt_mac_payload(
                            cursor.remaining_slice(),
                            aad,
                            router.ext_addr,
                            security,
                            keys,
                        );

                        if decrypted.is_some() {
                            matched_src_ext = Some(router.ext_addr);
                            if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
                                info!(
                                    "secured MAC decrypt matched router ext={=u64:016x} short_src={=?}",
                                    router.ext_addr, src.short_addr
                                );
                            }
                            break;
                        }
                    }
                }

                let Some(plaintext) = decrypted else {
                    if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
                        debug!(
                            "drop secured MAC frame: no ext nonce candidate matched short_src={=?}",
                            src.short_addr
                        );
                    }
                    return;
                };

                (plaintext, matched_src_ext)
            }
        }
    } else {
        let mut out: Vec<u8, 127> = Vec::new();
        out.extend_from_slice(cursor.remaining_slice()).ok();
        (out, src.ext_addr)
    };

    decode_lowpan_payload(
        payload.as_slice(),
        src.short_addr,
        effective_src_ext,
        keys,
        attach_phase,
    );
}

fn decode_lowpan_payload(
    payload: &[u8],
    mac_src_short: Option<u16>,
    mac_src_ext: Option<u64>,
    keys: &ThreadKeyMaterial,
    attach_phase: &mut AttachPhase,
) {
    if payload.is_empty() {
        return;
    }

    let payload = strip_lowpan_mesh_header(payload);

    if payload.is_empty() {
        return;
    }

    if payload[0] == 0x41 {
        decode_uncompressed_ipv6(payload, mac_src_short, mac_src_ext, keys, attach_phase);
        return;
    }

    if payload.len() >= 2 && (payload[0] & 0xe0) == 0x60 {
        decode_iphc_ipv6(payload, mac_src_short, mac_src_ext, keys, attach_phase);
        return;
    }

    if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
        let preview_len = payload.len().min(8);
        debug!(
            "unknown 6LoWPAN dispatch first={=u8:02x} preview={:02x}",
            payload[0],
            &payload[..preview_len]
        );
    }
}

fn strip_lowpan_mesh_header(mut payload: &[u8]) -> &[u8] {
    loop {
        if payload.is_empty() {
            return payload;
        }

        // RFC 4944 mesh header dispatch pattern: `10xxxxxx`.
        if (payload[0] & 0xc0) != 0x80 {
            return payload;
        }

        let mut index = 1usize;
        let first = payload[0];
        let origin_is_short = (first & 0x20) == 0;
        let final_is_short = (first & 0x10) == 0;
        let hops_inline = (first & 0x0f) != 0x0f;

        if !hops_inline {
            index += 1;
        }

        index += if origin_is_short { 2 } else { 8 };
        index += if final_is_short { 2 } else { 8 };

        if index > payload.len() {
            return &[];
        }

        payload = &payload[index..];
    }
}

fn decode_uncompressed_ipv6(
    payload: &[u8],
    mac_src_short: Option<u16>,
    mac_src_ext: Option<u64>,
    keys: &ThreadKeyMaterial,
    attach_phase: &mut AttachPhase,
) {
    if payload.len() < 1 + 40 + 8 {
        return;
    }

    let ipv6 = &payload[1..];
    if ipv6[6] != 17 || ipv6[7] != 255 {
        return;
    }

    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&ipv6[8..24]);
    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(&ipv6[24..40]);

    let udp = &ipv6[40..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if src_port != MLE_UDP_PORT || dst_port != MLE_UDP_PORT {
        return;
    }

    if mac_src_ext.is_none() {
        debug!(
            "RX MLE over uncompressed IPv6 from MAC short={=?}, IPv6 src IID={:02x}",
            mac_src_short,
            &src_addr[8..16]
        );
    }

    decode_mle_message(src_addr, dst_addr, &udp[8..], keys, attach_phase);
}

fn decode_iphc_ipv6(
    payload: &[u8],
    mac_src_short: Option<u16>,
    mac_src_ext: Option<u64>,
    keys: &ThreadKeyMaterial,
    attach_phase: &mut AttachPhase,
) {
    let mut cursor = Cursor::new(payload);
    let Some(b0) = cursor.u8() else {
        return;
    };
    let Some(b1) = cursor.u8() else {
        return;
    };

    let tf = (b0 >> 3) & 0b11;
    let nh_compressed = (b0 & (1 << 2)) != 0;
    let hlim = b0 & 0b11;

    let cid = (b1 & (1 << 7)) != 0;
    let sac = (b1 & (1 << 6)) != 0;
    let sam = (b1 >> 4) & 0b11;
    let multicast = (b1 & (1 << 3)) != 0;
    let dac = (b1 & (1 << 2)) != 0;
    let dam = b1 & 0b11;

    if cid {
        cursor.u8();
    }

    let tf_inline_len = match tf {
        0 => 4,
        1 => 3,
        2 => 1,
        _ => 0,
    };
    cursor.take(tf_inline_len);

    let next_header = if nh_compressed { None } else { cursor.u8() };

    let hop_limit = match hlim {
        0 => cursor.u8(),
        1 => Some(1),
        2 => Some(64),
        3 => Some(255),
        _ => None,
    };

    if hop_limit != Some(255) {
        return;
    }

    let local_ext_addr = iid_to_ext_addr(&link_local_from_ext_addr(LOCAL_EXT_ADDR)[8..16]);
    let Some(src_addr) =
        decode_iphc_unicast_addr(&mut cursor, sac, sam, mac_src_short, mac_src_ext)
    else {
        return;
    };
    let dst_addr = if multicast {
        let Some(addr) = decode_iphc_multicast_addr(&mut cursor, dam) else {
            return;
        };
        addr
    } else {
        let Some(addr) =
            decode_iphc_unicast_addr(&mut cursor, dac, dam, None, Some(local_ext_addr))
        else {
            return;
        };
        addr
    };

    let nh = if let Some(nh) = next_header {
        nh
    } else {
        let Some(udp_ctl) = cursor.u8() else {
            return;
        };

        if (udp_ctl & 0xf8) != 0xf0 {
            return;
        }

        let Some((src_port, dst_port)) = decode_compressed_udp_ports(&mut cursor, udp_ctl) else {
            return;
        };

        if (udp_ctl & 0x04) != 0 {
            return;
        }

        let Some(_checksum) = cursor.u16_be() else {
            return;
        };
        if src_port != MLE_UDP_PORT || dst_port != MLE_UDP_PORT {
            return;
        }

        if mac_src_ext.is_none() {
            debug!(
                "RX MLE over IPHC from MAC short={=?}, IPv6 src IID={:02x}",
                mac_src_short,
                &src_addr[8..16]
            );
        }

        decode_mle_message(
            src_addr,
            dst_addr,
            cursor.remaining_slice(),
            keys,
            attach_phase,
        );
        return;
    };

    if nh != 17 {
        return;
    }

    let Some(src_port) = cursor.u16_be() else {
        return;
    };
    let Some(dst_port) = cursor.u16_be() else {
        return;
    };
    let Some(_udp_len) = cursor.u16_be() else {
        return;
    };
    let Some(_checksum) = cursor.u16_be() else {
        return;
    };

    if src_port != MLE_UDP_PORT || dst_port != MLE_UDP_PORT {
        return;
    }

    if mac_src_ext.is_none() {
        debug!(
            "RX inline-UDP MLE from MAC short={=?}, IPv6 src IID={:02x}",
            mac_src_short,
            &src_addr[8..16]
        );
    }

    decode_mle_message(
        src_addr,
        dst_addr,
        cursor.remaining_slice(),
        keys,
        attach_phase,
    );
}

fn decode_mle_message(
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    payload: &[u8],
    keys: &ThreadKeyMaterial,
    attach_phase: &mut AttachPhase,
) {
    if payload.len() < 1 + MLE_SECURITY_HEADER_LEN + 1 + MLE_SECURITY_TAG_LEN {
        if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
            debug!("drop MLE candidate: too short len={}", payload.len());
        }
        return;
    }

    if payload[0] != MLE_SECURITY_SUITE_154 {
        if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
            debug!(
                "drop MLE candidate: unsupported security suite={=u8:02x}",
                payload[0]
            );
        }
        return;
    }

    let security_header = &payload[1..1 + MLE_SECURITY_HEADER_LEN];
    let security_control = security_header[0];
    if security_control != MLE_AUX_SECURITY_CONTROL {
        if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
            debug!(
                "drop MLE candidate: security control mismatch={=u8:02x}",
                security_control
            );
        }
        return;
    }

    let frame_counter = u32::from_le_bytes([
        security_header[1],
        security_header[2],
        security_header[3],
        security_header[4],
    ]);
    let key_sequence = u32::from_be_bytes([
        security_header[5],
        security_header[6],
        security_header[7],
        security_header[8],
    ]);

    if key_sequence != keys.key_sequence {
        if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
            debug!(
                "drop MLE candidate: key sequence mismatch rx={} expected={}",
                key_sequence, keys.key_sequence
            );
        }
        return;
    }

    let src_ext_addr = iid_to_ext_addr(&src_addr[8..16]);
    let nonce = build_mle_nonce(src_ext_addr, frame_counter);
    let Some(aad) = build_mle_aad(src_addr, dst_addr, security_header) else {
        return;
    };

    let encrypted = &payload[1 + MLE_SECURITY_HEADER_LEN..payload.len() - MLE_SECURITY_TAG_LEN];
    let mic = &payload[payload.len() - MLE_SECURITY_TAG_LEN..];

    let mut plaintext: Vec<u8, 96> = Vec::new();
    plaintext.extend_from_slice(encrypted).ok();

    let cipher = match AesCcmMic4::new_from_slice(&keys.mle_key) {
        Ok(cipher) => cipher,
        Err(_) => return,
    };

    if cipher
        .decrypt_in_place_detached((&nonce).into(), aad.as_slice(), &mut plaintext, mic.into())
        .is_err()
    {
        if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
            warn!(
                "MLE decrypt failed src_iid={:02x} frame_counter={} key_seq={}",
                &src_addr[8..16],
                frame_counter,
                key_sequence
            );
        }
        return;
    }

    if plaintext.is_empty() {
        return;
    }

    if matches!(attach_phase, AttachPhase::WaitingParentResponse { .. }) {
        info!(
            "RX MLE cmd={=u8:02x} src_iid={:02x} len={}",
            plaintext[0],
            &src_addr[8..16],
            plaintext.len()
        );
    }

    match plaintext[0] {
        MLE_CMD_PARENT_RESPONSE => {
            if let Some(response) =
                parse_parent_response(src_ext_addr, &plaintext[1..], attach_phase)
            {
                info!(
                    "RX Parent Response ext={=u64:016x} response_matches={} rloc16={=?}",
                    response.ext_addr, response.response_matches, response.rloc16
                );
            }
        }
        MLE_CMD_PARENT_REQUEST => {
            debug!("RX MLE Parent Request from ext={=u64:016x}", src_ext_addr);
        }
        cmd => {
            debug!(
                "RX other MLE cmd={=u8:02x} from ext={=u64:016x}",
                cmd, src_ext_addr
            );
        }
    }
}

fn parse_parent_response(
    src_ext_addr: u64,
    tlvs: &[u8],
    attach_phase: &mut AttachPhase,
) -> Option<ParentResponseInfo> {
    let (expected_challenge, preferred_parent, current_best) = match *attach_phase {
        AttachPhase::WaitingParentResponse {
            challenge,
            preferred_parent,
            best_response,
            ..
        } => (challenge, preferred_parent, best_response),
        _ => return None,
    };

    let mut cursor = Cursor::new(tlvs);
    let mut response_matches = false;
    let mut rloc16 = None;
    let mut link_margin = None;
    let mut version = None;

    while cursor.remaining() >= 2 {
        let tlv_type = cursor.u8()?;
        let tlv_len = cursor.u8()? as usize;
        let value = cursor.take(tlv_len)?;

        match tlv_type {
            MLE_TLV_SOURCE_ADDRESS if tlv_len == 2 => {
                rloc16 = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            MLE_TLV_RESPONSE if tlv_len == expected_challenge.len() => {
                response_matches = value == expected_challenge;
            }
            MLE_TLV_LINK_MARGIN if tlv_len == 1 => {
                link_margin = Some(value[0]);
            }
            MLE_TLV_VERSION if tlv_len == 2 => {
                version = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            _ => {}
        }
    }

    let response = ParentResponseInfo {
        ext_addr: src_ext_addr,
        rloc16,
        link_margin,
        version,
        response_matches,
    };

    if !response_matches {
        warn!(
            "Parent Response challenge mismatch from ext={=u64:016x} rloc16={=?}",
            response.ext_addr, response.rloc16
        );
    }

    if response_matches {
        let preferred = preferred_parent == Some(src_ext_addr);
        let better_than_current = match current_best {
            None => true,
            Some(current) => {
                preferred || current.ext_addr != preferred_parent.unwrap_or(current.ext_addr)
            }
        };

        if better_than_current {
            if let AttachPhase::WaitingParentResponse {
                challenge,
                sent_at,
                preferred_parent,
                best_response: _,
            } = *attach_phase
            {
                *attach_phase = AttachPhase::WaitingParentResponse {
                    challenge,
                    sent_at,
                    preferred_parent,
                    best_response: Some(response),
                };
            }
        }
    }

    Some(response)
}

fn parse_thread_dataset_from_env() -> ActiveDataset {
    let mut dataset = ActiveDataset {
        channel: None,
        pan_id: None,
        ext_pan_id: None,
        network_key: None,
        network_name: NetworkName::empty(),
    };

    let Some(hex) = THREAD_DATASET_HEX else {
        warn!("THREAD_DATASET not set; using default channel/PAN for discovery only");
        return dataset;
    };

    let bytes = hex.as_bytes();
    let mut i = 0usize;

    while i + 4 <= bytes.len() {
        let Some(tlv_type) = parse_hex_u8(bytes, i) else {
            return dataset;
        };
        i += 2;

        let Some(tlv_len) = parse_hex_u8(bytes, i) else {
            return dataset;
        };
        i += 2;

        let value_hex_len = (tlv_len as usize) * 2;
        if i + value_hex_len > bytes.len() {
            return dataset;
        }

        parse_dataset_tlv(&mut dataset, tlv_type, tlv_len as usize, bytes, i);
        i += value_hex_len;
    }

    dataset
}

fn parse_dataset_tlv(
    dataset: &mut ActiveDataset,
    tlv_type: u8,
    tlv_len: usize,
    hex: &[u8],
    value_start: usize,
) {
    match tlv_type {
        0x00 if tlv_len == 3 => {
            if let Some(ch) = parse_hex_u16_be(hex, value_start + 2) {
                dataset.channel = Some(ch as u8);
            }
        }
        0x01 if tlv_len == 2 => {
            dataset.pan_id = parse_hex_u16_be(hex, value_start);
        }
        0x02 if tlv_len == 8 => {
            let mut out = [0u8; 8];
            if parse_hex_array(hex, value_start, &mut out) {
                dataset.ext_pan_id = Some(out);
            }
        }
        0x03 => {
            let copy_len = tlv_len.min(MAX_NETWORK_NAME_LEN);
            let mut name = NetworkName::empty();

            for n in 0..copy_len {
                if let Some(byte) = parse_hex_u8(hex, value_start + n * 2) {
                    name.bytes[n] = byte;
                    name.len += 1;
                }
            }

            dataset.network_name = name;
        }
        0x05 if tlv_len == 16 => {
            let mut out = [0u8; 16];
            if parse_hex_array(hex, value_start, &mut out) {
                dataset.network_key = Some(out);
            }
        }
        _ => {}
    }
}

fn log_active_dataset(dataset: &ActiveDataset) {
    info!("=== Thread Active Dataset ===");
    info!("channel={}", dataset.channel_or_default());
    info!("pan_id={=u16:04x}", dataset.pan_id_or_default());

    if let Some(ext_pan_id) = dataset.ext_pan_id {
        info!("ext_pan_id={:02x}", ext_pan_id);
    }

    if dataset.network_name.len > 0 {
        info!(
            "network_name_bytes={:02x}",
            &dataset.network_name.bytes[..dataset.network_name.len]
        );
    }

    info!("network_key_present={}", dataset.network_key.is_some());
}

fn derive_thread_key_material(
    dataset: &ActiveDataset,
    key_sequence: u32,
) -> Option<ThreadKeyMaterial> {
    let network_key = dataset.network_key?;

    let mut hmac = <HmacSha256 as Mac>::new_from_slice(&network_key).ok()?;
    hmac.update(&key_sequence.to_be_bytes());
    hmac.update(b"Thread");
    let hash = hmac.finalize().into_bytes();

    let mut mle_key = [0u8; 16];
    let mut mac_key = [0u8; 16];
    mle_key.copy_from_slice(&hash[..16]);
    mac_key.copy_from_slice(&hash[16..32]);

    Some(ThreadKeyMaterial {
        key_sequence,
        key_id: ((key_sequence & 0x7f) as u8).wrapping_add(1),
        mle_key,
        mac_key,
    })
}

fn log_thread_key_material(keys: &ThreadKeyMaterial) {
    info!("=== Thread Key Material ===");
    info!(
        "key_sequence={=u32} key_id={}",
        keys.key_sequence, keys.key_id
    );
    debug!("mle_key_debug={:02x}", keys.mle_key);
    debug!("mac_key_debug={:02x}", keys.mac_key);
}

fn remember_router(
    routers: &mut [Option<RouterInfo>; MAX_ROUTERS],
    ext_addr: u64,
    pan_id: u16,
    lqi: u8,
) {
    for slot in routers.iter_mut() {
        if let Some(router) = slot {
            if router.ext_addr == ext_addr {
                router.last_lqi = lqi;
                router.beacon_count = router.beacon_count.wrapping_add(1);
                return;
            }
        }
    }

    for slot in routers.iter_mut() {
        if slot.is_none() {
            *slot = Some(RouterInfo {
                ext_addr,
                pan_id,
                last_lqi: lqi,
                beacon_count: 1,
            });
            info!(
                "router discovered ext={=u64:016x} pan={=u16:04x} lqi={}",
                ext_addr, pan_id, lqi
            );
            return;
        }
    }

    warn!("router table full");
}

fn select_best_parent(routers: &[Option<RouterInfo>; MAX_ROUTERS]) -> Option<RouterInfo> {
    let mut best: Option<RouterInfo> = None;

    for router in routers.iter().flatten() {
        match best {
            Some(current) if current.last_lqi >= router.last_lqi => {}
            _ => best = Some(*router),
        }
    }

    best
}

fn print_router_table(active_pan_id: u16, routers: &[Option<RouterInfo>; MAX_ROUTERS]) {
    info!("=== Routers on PAN {=u16:04x} ===", active_pan_id);

    let mut count = 0u8;
    for router in routers.iter().flatten() {
        count = count.wrapping_add(1);
        info!(
            "router {} ext={=u64:016x} pan={=u16:04x} lqi={} beacons={}",
            count, router.ext_addr, router.pan_id, router.last_lqi, router.beacon_count
        );
    }

    if count == 0 {
        info!("no routers seen yet");
    }
}

fn attach_phase_name(phase: &AttachPhase) -> &'static str {
    match phase {
        AttachPhase::Discovering { .. } => "discovering",
        AttachPhase::WaitingParentResponse { .. } => "waiting-parent-response",
        AttachPhase::ParentAccepted { .. } => "parent-accepted",
    }
}

fn parse_fcf(fcf: u16) -> FrameControl {
    FrameControl {
        frame_type: match (fcf & 0b111) as u8 {
            0 => FrameType::Beacon,
            1 => FrameType::Data,
            2 => FrameType::Ack,
            3 => FrameType::MacCommand,
            other => FrameType::Unknown(other),
        },
        security_enabled: (fcf & (1 << 3)) != 0,
        pan_compression: (fcf & (1 << 6)) != 0,
        frame_version: (fcf >> 12) & 0b11,
        dst_mode: parse_addr_mode((fcf >> 10) & 0b11),
        src_mode: parse_addr_mode((fcf >> 14) & 0b11),
    }
}

fn parse_addr_mode(bits: u16) -> AddrMode {
    match bits {
        0 => AddrMode::None,
        2 => AddrMode::Short,
        3 => AddrMode::Extended,
        _ => AddrMode::Reserved,
    }
}

fn parse_dst_addr(c: &mut Cursor, mode: AddrMode) -> Option<Option<u16>> {
    match mode {
        AddrMode::None => Some(None),
        AddrMode::Short => {
            let pan = c.u16_le()?;
            c.u16_le()?;
            Some(Some(pan))
        }
        AddrMode::Extended => {
            let pan = c.u16_le()?;
            c.u64_le()?;
            Some(Some(pan))
        }
        AddrMode::Reserved => None,
    }
}

fn parse_src_addr(
    c: &mut Cursor,
    mode: AddrMode,
    pan_compression: bool,
    dst_pan: Option<u16>,
) -> Option<ParsedSrcAddr> {
    match mode {
        AddrMode::None => Some(ParsedSrcAddr {
            pan_id: None,
            short_addr: None,
            ext_addr: None,
        }),
        AddrMode::Short => {
            let pan_id = if pan_compression {
                dst_pan
            } else {
                Some(c.u16_le()?)
            };
            let short_addr = c.u16_le()?;
            Some(ParsedSrcAddr {
                pan_id,
                short_addr: Some(short_addr),
                ext_addr: None,
            })
        }
        AddrMode::Extended => {
            let pan_id = if pan_compression {
                dst_pan
            } else {
                Some(c.u16_le()?)
            };
            let ext_addr = c.u64_le()?;
            Some(ParsedSrcAddr {
                pan_id,
                short_addr: None,
                ext_addr: Some(ext_addr),
            })
        }
        AddrMode::Reserved => None,
    }
}

fn decode_iphc_unicast_addr(
    cursor: &mut Cursor,
    context_compressed: bool,
    addr_mode: u8,
    mac_short_addr: Option<u16>,
    mac_ext_addr: Option<u64>,
) -> Option<[u8; 16]> {
    if context_compressed {
        return None;
    }

    match addr_mode {
        0 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(cursor.take(16)?);
            Some(addr)
        }
        1 => {
            let mut addr = [0u8; 16];
            addr[0] = 0xfe;
            addr[1] = 0x80;
            addr[8..16].copy_from_slice(cursor.take(8)?);
            Some(addr)
        }
        2 => {
            let short = cursor.u16_be()?;
            let mut addr = [0u8; 16];
            addr[0] = 0xfe;
            addr[1] = 0x80;
            addr[11] = 0xff;
            addr[12] = 0xfe;
            addr[14..16].copy_from_slice(&short.to_be_bytes());
            Some(addr)
        }
        3 => {
            if let Some(ext_addr) = mac_ext_addr {
                Some(link_local_from_ext_addr(ext_addr))
            } else if let Some(short_addr) = mac_short_addr {
                let mut addr = [0u8; 16];
                addr[0] = 0xfe;
                addr[1] = 0x80;
                addr[11] = 0x00;
                addr[12] = 0xff;
                addr[13] = 0xfe;
                addr[14..16].copy_from_slice(&short_addr.to_be_bytes());
                Some(addr)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn decode_iphc_multicast_addr(cursor: &mut Cursor, dam: u8) -> Option<[u8; 16]> {
    match dam {
        0 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(cursor.take(16)?);
            Some(addr)
        }
        1 => {
            let bytes = cursor.take(6)?;
            let mut addr = [0u8; 16];
            addr[0] = 0xff;
            addr[1] = bytes[0];
            addr[11] = bytes[1];
            addr[12] = bytes[2];
            addr[13] = bytes[3];
            addr[14] = bytes[4];
            addr[15] = bytes[5];
            Some(addr)
        }
        2 => {
            let bytes = cursor.take(4)?;
            let mut addr = [0u8; 16];
            addr[0] = 0xff;
            addr[1] = bytes[0];
            addr[13] = bytes[1];
            addr[14] = bytes[2];
            addr[15] = bytes[3];
            Some(addr)
        }
        3 => {
            let group = cursor.u8()?;
            let mut addr = [0u8; 16];
            addr[0] = 0xff;
            addr[1] = 0x02;
            addr[15] = group;
            Some(addr)
        }
        _ => None,
    }
}

fn parse_security_header(c: &mut Cursor) -> Option<MacSecurityHeader> {
    let security_control = c.u8()?;
    let security_level = security_control & 0x07;
    let key_id_mode = (security_control >> 3) & 0x03;
    let frame_counter_suppressed = (security_control & (1 << 5)) != 0;

    let frame_counter = if frame_counter_suppressed {
        None
    } else {
        Some(u32::from_le_bytes(c.take(4)?.try_into().ok()?))
    };

    match key_id_mode {
        0 => {}
        1 => {
            c.u8()?;
        }
        2 => {
            c.take(4)?;
            c.u8()?;
        }
        3 => {
            c.take(8)?;
            c.u8()?;
        }
        _ => return None,
    }

    Some(MacSecurityHeader {
        security_control,
        security_level,
        key_id_mode,
        frame_counter,
    })
}

fn mic_len_for_security_level(level: u8) -> Option<usize> {
    match level {
        0 => Some(0),
        1 | 5 => Some(4),
        2 | 6 => Some(8),
        3 | 7 => Some(16),
        4 => Some(0),
        _ => None,
    }
}

fn decrypt_mac_payload(
    payload: &[u8],
    aad: &[u8],
    src_ext_addr: u64,
    security: MacSecurityHeader,
    keys: &ThreadKeyMaterial,
) -> Option<Vec<u8, 127>> {
    let mic_len = mic_len_for_security_level(security.security_level)?;
    let frame_counter = security.frame_counter?;

    if security.key_id_mode != 1 || security.security_control != MAC_AUX_SECURITY_CONTROL_KEYIDMODE1
    {
        return None;
    }

    if payload.len() < mic_len {
        return None;
    }

    let split = payload.len() - mic_len;
    let encrypted = &payload[..split];
    let mic = &payload[split..];

    let mut nonce = [0u8; 13];
    nonce[0..8].copy_from_slice(&src_ext_addr.to_be_bytes());
    nonce[8..12].copy_from_slice(&frame_counter.to_be_bytes());
    nonce[12] = security.security_level;

    let mut plaintext: Vec<u8, 127> = Vec::new();
    plaintext.extend_from_slice(encrypted).ok()?;

    let cipher = AesCcmMic4::new_from_slice(&keys.mac_key).ok()?;
    cipher
        .decrypt_in_place_detached((&nonce).into(), aad, &mut plaintext, mic.into())
        .ok()?;

    Some(plaintext)
}

fn decode_compressed_udp_ports(cursor: &mut Cursor, udp_ctl: u8) -> Option<(u16, u16)> {
    match udp_ctl & 0x03 {
        0 => Some((cursor.u16_be()?, cursor.u16_be()?)),
        1 => Some((cursor.u16_be()?, 0xf000 | cursor.u8()? as u16)),
        2 => Some((0xf000 | cursor.u8()? as u16, cursor.u16_be()?)),
        3 => {
            let value = cursor.u8()?;
            Some((
                0xf0b0 | ((value >> 4) as u16),
                0xf0b0 | ((value & 0x0f) as u16),
            ))
        }
        _ => None,
    }
}

fn link_local_from_ext_addr(ext_addr: u64) -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0xfe;
    addr[1] = 0x80;
    let mut iid = ext_addr.to_be_bytes();
    iid[0] ^= 0x02;
    addr[8..16].copy_from_slice(&iid);
    addr
}

fn link_local_all_routers() -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0xff;
    addr[1] = 0x02;
    addr[15] = 0x02;
    addr
}

fn iid_to_ext_addr(iid: &[u8]) -> u64 {
    let mut ext = [0u8; 8];
    ext.copy_from_slice(iid);
    ext[0] ^= 0x02;
    u64::from_be_bytes(ext)
}

fn build_mle_nonce(src_ext_addr: u64, frame_counter: u32) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0..8].copy_from_slice(&src_ext_addr.to_be_bytes());
    nonce[8..12].copy_from_slice(&frame_counter.to_be_bytes());
    nonce[12] = IEEE802154_SECURITY_LEVEL_ENC_MIC32;
    nonce
}

fn build_mle_aad(
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    security_header: &[u8],
) -> Option<Vec<u8, 64>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&src_addr).ok()?;
    aad.extend_from_slice(&dst_addr).ok()?;
    aad.extend_from_slice(security_header).ok()?;
    Some(aad)
}

fn build_parent_request_challenge(seed: u8) -> [u8; 8] {
    [
        0xa5,
        0x5a,
        seed,
        seed.wrapping_add(1),
        seed.wrapping_add(2),
        seed ^ 0x55,
        seed ^ 0xaa,
        0x11,
    ]
}

fn udp_checksum(
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    udp_header: &[u8; 8],
    payload: &[u8],
) -> u16 {
    let mut sum = 0u32;

    for chunk in src_addr.chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    for chunk in dst_addr.chunks(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    let udp_len = (udp_header.len() + payload.len()) as u32;
    sum = sum.wrapping_add((udp_len >> 16) & 0xffff);
    sum = sum.wrapping_add(udp_len & 0xffff);
    sum = sum.wrapping_add(17);

    for chunk in udp_header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    for chunk in payload.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

fn push_tlv<const N: usize>(out: &mut Vec<u8, N>, tlv_type: u8, value: &[u8]) -> Option<()> {
    out.push(tlv_type).ok()?;
    out.push(value.len() as u8).ok()?;
    out.extend_from_slice(value).ok()?;
    Some(())
}

fn push_u16_le<const N: usize>(out: &mut Vec<u8, N>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes()).ok();
}

fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0xffu8;

    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x31;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

fn parse_hex_array(hex: &[u8], value_start: usize, out: &mut [u8]) -> bool {
    for i in 0..out.len() {
        let Some(byte) = parse_hex_u8(hex, value_start + i * 2) else {
            return false;
        };
        out[i] = byte;
    }

    true
}

fn parse_hex_u16_be(hex: &[u8], offset: usize) -> Option<u16> {
    let hi = parse_hex_u8(hex, offset)?;
    let lo = parse_hex_u8(hex, offset + 2)?;
    Some(u16::from_be_bytes([hi, lo]))
}

fn parse_hex_u8(hex: &[u8], offset: usize) -> Option<u8> {
    if offset + 2 > hex.len() {
        return None;
    }

    let hi = hex_nibble(hex[offset])?;
    let lo = hex_nibble(hex[offset + 1])?;
    Some((hi << 4) | lo)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
