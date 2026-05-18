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
use embassy_time::{Duration, Timer, with_timeout};
use heapless::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use smoltcp::wire::{
    Ieee802154Frame, Ieee802154FrameType, Ieee802154Repr, SixlowpanIphcPacket, SixlowpanIphcRepr,
};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

mod sht41;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
    TWISPI0 => twim::InterruptHandler<peripherals::TWISPI0>;
});

static TWIM_BUFFER: StaticCell<[u8; 16]> = StaticCell::new();

const DEFAULT_CHANNEL: u8 = 15;
const DEFAULT_PAN_ID: u16 = 0x06e6;
const MAX_NETWORK_NAME_LEN: usize = 32;
const THREAD_DATASET_HEX: Option<&str> = option_env!("THREAD_DATASET");

const IEEE802154_SECURITY_LEVEL_ENC_MIC32: u8 = 5;
const RX_POLL_TIMEOUT: Duration = Duration::from_millis(250);

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
    let sht41 = sht41::Sht41::new(i2c);
    spawner.spawn(temperature_measurement(sht41).unwrap());

    info!("Thread child attach experiment started");

    let mut rx_ok: u32 = 0;
    let mut rx_err: u32 = 0;

    loop {
        let mut packet = Packet::new();

        match with_timeout(RX_POLL_TIMEOUT, radio.receive(&mut packet)).await {
            Ok(Ok(())) => {
                rx_ok = rx_ok.wrapping_add(1);

                let frame = Ieee802154Frame::new_unchecked(packet.as_ref());
                let repr = Ieee802154Repr::parse(&frame);
                info!("new frame {}: {:?}", rx_ok, repr);

                if frame.frame_type() != Ieee802154FrameType::Data {
                    continue;
                }

                let payload = if !frame.security_enabled() {
                    let mut plaintext: Vec<u8, 127> = Vec::new();
                    frame.payload().and_then(|payload| {
                        plaintext.extend_from_slice(payload).ok().map(|_| plaintext)
                    })
                } else if frame.payload().is_some() {
                    // lets decrypt here and then move to a function
                    let security_key = active_dataset.network_key.unwrap();
                    let level = frame.security_level();

                    if level == IEEE802154_SECURITY_LEVEL_ENC_MIC32 {
                        let fc = frame.frame_counter().unwrap();
                        let src_addr = frame.src_addr().unwrap();
                        let src = src_addr.as_bytes();

                        if src.len() != 8 {
                            warn!(
                                "secured MAC frame needs extended source for nonce, got {} bytes",
                                src.len()
                            );
                            None
                        } else {
                            let mut nonce = [0u8; 13];
                            nonce[0..8].copy_from_slice(src);
                            nonce[8..12].copy_from_slice(&fc.to_le_bytes());
                            nonce[12] = level;

                            let aad = frame.mac_header();
                            let payload = frame.payload().unwrap();
                            let mic = frame.message_integrity_code().unwrap(); // will be 4 because we already check level 5.
                            let encrypted_len = payload.len().checked_sub(mic.len()).unwrap();

                            let mut plaintext: Vec<u8, 127> = Vec::new();
                            if plaintext
                                .extend_from_slice(&payload[..encrypted_len])
                                .is_err()
                            {
                                None
                            } else {
                                let cipher = AesCcmMic4::new_from_slice(&security_key).unwrap();
                                cipher
                                    .decrypt_in_place_detached(
                                        (&nonce).into(),
                                        aad,
                                        &mut plaintext,
                                        mic.into(),
                                    )
                                    .unwrap();

                                Some(plaintext)
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(payload) = payload {
                    let iphc = SixlowpanIphcPacket::new_unchecked(&payload);

                    let iphc_repr =
                        SixlowpanIphcRepr::parse(&iphc, frame.src_addr(), frame.dst_addr(), &[]);

                    info!("iphc repr: {}", iphc_repr);
                }
            }
            Ok(Err(e)) => {
                rx_err = rx_err.wrapping_add(1);
                warn!("new receive error {}: {}", rx_err, e);
            }
            Err(_) => {}
        }
    }
}

#[embassy_executor::task]
async fn temperature_measurement(mut sht41: sht41::Sht41<Twim<'static>>) -> ! {
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
