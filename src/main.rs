#![no_std]
#![no_main]

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
use embassy_time::{Duration, Instant, Timer};
use embedded_hal_async::i2c::I2c;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
    TWISPI0 => twim::InterruptHandler<peripherals::TWISPI0>;
});

const SHT41_ADDR: u8 = 0x44;
const CMD_MEASURE_HIGH_PRECISION: u8 = 0xFD;
static TWIM_BUFFER: StaticCell<[u8; 16]> = StaticCell::new();

const CHANNEL: u8 = 15;
const PAN_ID: u16 = 0x06e6;
const MAX_ROUTERS: usize = 8;
const MAX_SHORT_DEVICES: usize = 16;

static mut TX_SEQ: u8 = 0;

#[derive(Clone, Copy)]
struct SeenRouter {
    ext_addr: u64,
    pan_id: u16,
    last_lqi: u8,
    count: u32,
}

#[derive(Clone, Copy)]
struct SeenShortDevice {
    short_addr: u16,
    pan_id: u16,
    last_lqi: u8,
    count: u32,
}

fn rloc16_child_id(addr: u16) -> u16 {
    addr & 0x003f
}

fn rloc16_parent(addr: u16) -> u16 {
    addr & 0xffc0
}

fn rloc16_is_router(addr: u16) -> bool {
    rloc16_child_id(addr) == 0
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

        trace!("measurement command sent");

        Timer::after(Duration::from_millis(20)).await;

        let mut buf = [0u8; 6];

        trace!("reading sensor data");

        self.i2c.read(SHT41_ADDR, &mut buf).await.map_err(|e| {
            warn!("i2c read failed");
            Sht41Error::I2c(e)
        })?;

        trace!(
            "raw bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
        );

        let temp_crc = crc8(&buf[0..2]);
        let rh_crc = crc8(&buf[3..5]);

        trace!("temp crc calc={}, sensor={}", temp_crc, buf[2]);
        trace!("rh crc calc={}, sensor={}", rh_crc, buf[5]);

        if temp_crc != buf[2] || rh_crc != buf[5] {
            warn!("crc mismatch");
            return Err(Sht41Error::Crc);
        }

        let raw_t = u16::from_be_bytes([buf[0], buf[1]]) as f32;
        let raw_rh = u16::from_be_bytes([buf[3], buf[4]]) as f32;

        trace!("raw temp={}", raw_t);
        trace!("raw humidity={}", raw_rh);

        let temperature_c = -45.0 + 175.0 * raw_t / 65535.0;
        let humidity_rh = -6.0 + 125.0 * raw_rh / 65535.0;

        trace!("computed temp={}", temperature_c);
        trace!("computed humidity={}", humidity_rh);

        Ok((temperature_c, humidity_rh.clamp(0.0, 100.0)))
    }
}

fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0xFFu8;

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

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.gpiote_interrupt_priority = Priority::P2;
    config.time_interrupt_priority = Priority::P2;
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;

    let p = embassy_nrf::init(config);

    let mut radio = Radio::new(p.RADIO, Irqs);
    radio.set_channel(CHANNEL);

    // Change these pins to match your board.
    let sda = p.P0_20;
    let scl = p.P0_22;

    let mut twim_config = twim::Config::default();
    twim_config.frequency = twim::Frequency::K100;

    let twim_buffer = TWIM_BUFFER.init([0u8; 16]);

    let i2c = Twim::new(p.TWISPI0, Irqs, sda, scl, twim_config, twim_buffer);

    let sht41 = Sht41::new(i2c);

    info!("SHT41 example started");

    spawner.spawn(temperature_measurement(sht41).unwrap());

    let mut rx_ok: u32 = 0;
    let mut rx_err: u32 = 0;
    let mut routers: [Option<SeenRouter>; MAX_ROUTERS] = [None; MAX_ROUTERS];
    let mut short_devices: [Option<SeenShortDevice>; MAX_SHORT_DEVICES] = [None; MAX_SHORT_DEVICES];

    let mut beacon_timer: u32 = 0;
    let mut last_router_table_print = Instant::now();

    loop {
        let mut packet = Packet::new();

        match radio.receive(&mut packet).await {
            Ok(()) => {
                rx_ok = rx_ok.wrapping_add(1);

                let frame: &[u8] = &packet;

                defmt::info!(
                    "RX ok={} err={} len={} lqi={}",
                    rx_ok,
                    rx_err,
                    frame.len(),
                    packet.lqi()
                );
                decode_802154(frame, packet.lqi(), &mut routers, &mut short_devices);
                defmt::debug!("raw={:02x}", frame);

                beacon_timer += 1;
                if beacon_timer % 50 == 0 {
                    send_beacon_request(&mut radio).await;
                }

                if last_router_table_print.elapsed() >= Duration::from_secs(5) {
                    print_router_table(&routers);
                    print_short_device_table(&short_devices);
                    last_router_table_print = Instant::now();
                }
            }
            Err(_) => {
                rx_err = rx_err.wrapping_add(1);

                if rx_err % 100 == 0 {
                    defmt::warn!("RX errors={} ok={}", rx_err, rx_ok);
                }
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
    let seq = unsafe {
        TX_SEQ = TX_SEQ.wrapping_add(1);
        TX_SEQ
    };

    let mut tx = Packet::new();

    let frame = [
        0x03, 0x08, // FCF = MAC Command
        seq,  // sequence
        0xff, 0xff, // broadcast PAN
        0xff, 0xff, // broadcast short addr
        0x07, // MAC command = Beacon Request
    ];

    tx.copy_from_slice(&frame);

    defmt::info!("TX Beacon Request seq={}", seq);

    match radio.try_send(&mut tx).await {
        Ok(_) => {
            defmt::info!("Beacon Request sent");
        }
        Err(_) => {
            defmt::warn!("Beacon Request TX failed");
        }
    }
}

fn remember_router(
    routers: &mut [Option<SeenRouter>; MAX_ROUTERS],
    ext_addr: u64,
    pan_id: u16,
    lqi: u8,
) {
    for slot in routers.iter_mut() {
        if let Some(router) = slot {
            if router.ext_addr == ext_addr {
                router.last_lqi = lqi;
                router.count = router.count.wrapping_add(1);

                defmt::info!(
                    "ROUTER update ext={=u64:016x} pan={=u16:04x} lqi={} count={}",
                    router.ext_addr,
                    router.pan_id,
                    router.last_lqi,
                    router.count
                );
                return;
            }
        }
    }

    for slot in routers.iter_mut() {
        if slot.is_none() {
            *slot = Some(SeenRouter {
                ext_addr,
                pan_id,
                last_lqi: lqi,
                count: 1,
            });

            defmt::info!(
                "ROUTER new ext={=u64:016x} pan={=u16:04x} lqi={} count=1",
                ext_addr,
                pan_id,
                lqi
            );
            return;
        }
    }

    defmt::warn!("router table full");
}

fn remember_short_device(
    short_devices: &mut [Option<SeenShortDevice>; MAX_SHORT_DEVICES],
    short_addr: u16,
    pan_id: u16,
    lqi: u8,
) {
    for slot in short_devices.iter_mut() {
        if let Some(device) = slot {
            if device.short_addr == short_addr {
                device.last_lqi = lqi;
                device.count = device.count.wrapping_add(1);

                defmt::info!(
                    "SHORT update addr={=u16:04x} pan={=u16:04x} lqi={} count={}",
                    device.short_addr,
                    device.pan_id,
                    device.last_lqi,
                    device.count
                );
                return;
            }
        }
    }

    for slot in short_devices.iter_mut() {
        if slot.is_none() {
            *slot = Some(SeenShortDevice {
                short_addr,
                pan_id,
                last_lqi: lqi,
                count: 1,
            });

            defmt::info!(
                "SHORT new addr={=u16:04x} pan={=u16:04x} lqi={} count=1",
                short_addr,
                pan_id,
                lqi
            );
            return;
        }
    }

    defmt::warn!("short device table full");
}

fn print_router_table(routers: &[Option<SeenRouter>; MAX_ROUTERS]) {
    defmt::info!("=== Thread routers on PAN {=u16:04x} ===", PAN_ID);

    let mut seen = 0u8;

    for router in routers.iter().flatten() {
        seen = seen.wrapping_add(1);

        defmt::info!(
            "router {} ext={=u64:016x} pan={=u16:04x} lqi={} count={}",
            seen,
            router.ext_addr,
            router.pan_id,
            router.last_lqi,
            router.count
        );
    }

    if seen == 0 {
        defmt::info!("no routers seen yet");
    }
}

fn print_short_device_table(short_devices: &[Option<SeenShortDevice>; MAX_SHORT_DEVICES]) {
    defmt::info!("=== Short addresses on PAN {=u16:04x} ===", PAN_ID);

    let mut seen = 0u8;

    for device in short_devices.iter().flatten() {
        seen = seen.wrapping_add(1);

        if rloc16_is_router(device.short_addr) {
            defmt::info!(
                "short {} addr={=u16:04x} role=router pan={=u16:04x} lqi={} count={}",
                seen,
                device.short_addr,
                device.pan_id,
                device.last_lqi,
                device.count
            );
        } else {
            defmt::info!(
                "short {} addr={=u16:04x} role=child parent={=u16:04x} child_id={} pan={=u16:04x} lqi={} count={}",
                seen,
                device.short_addr,
                rloc16_parent(device.short_addr),
                rloc16_child_id(device.short_addr),
                device.pan_id,
                device.last_lqi,
                device.count
            );
        }
    }

    if seen == 0 {
        defmt::info!("no short addresses seen yet");
    }
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

    fn pos(&self) -> usize {
        self.i
    }

    fn remaining_slice(&self) -> &'a [u8] {
        &self.frame[self.i..]
    }

    fn u8(&mut self) -> Option<u8> {
        if self.remaining() < 1 {
            return None;
        }
        let v = self.frame[self.i];
        self.i += 1;
        Some(v)
    }

    fn u16_le(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let v = u16::from_le_bytes([self.frame[self.i], self.frame[self.i + 1]]);
        self.i += 2;
        Some(v)
    }

    fn u32_le(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let v = u32::from_le_bytes([
            self.frame[self.i],
            self.frame[self.i + 1],
            self.frame[self.i + 2],
            self.frame[self.i + 3],
        ]);
        self.i += 4;
        Some(v)
    }

    fn u64_le(&mut self) -> Option<u64> {
        if self.remaining() < 8 {
            return None;
        }
        let v = u64::from_le_bytes([
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
        Some(v)
    }
}

fn parse_frame_type(fcf: u16) -> FrameType {
    match (fcf & 0b111) as u8 {
        0 => FrameType::Beacon,
        1 => FrameType::Data,
        2 => FrameType::Ack,
        3 => FrameType::MacCommand,
        x => FrameType::Unknown(x),
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

struct FrameControl {
    frame_type: FrameType,
    security_enabled: bool,
    frame_pending: bool,
    ack_request: bool,
    pan_compression: bool,
    frame_version: u16,
    dst_mode: AddrMode,
    src_mode: AddrMode,
}

fn parse_fcf(fcf: u16) -> FrameControl {
    FrameControl {
        frame_type: parse_frame_type(fcf),
        security_enabled: (fcf & (1 << 3)) != 0,
        frame_pending: (fcf & (1 << 4)) != 0,
        ack_request: (fcf & (1 << 5)) != 0,
        pan_compression: (fcf & (1 << 6)) != 0,
        dst_mode: parse_addr_mode((fcf >> 10) & 0b11),
        frame_version: (fcf >> 12) & 0b11,
        src_mode: parse_addr_mode((fcf >> 14) & 0b11),
    }
}

fn parse_dst_addr(c: &mut Cursor, mode: AddrMode) -> Option<Option<u16>> {
    match mode {
        AddrMode::None => Some(None),

        AddrMode::Short => {
            let pan = c.u16_le()?;
            let addr = c.u16_le()?;

            defmt::info!("dst_pan={=u16:04x} dst_short={=u16:04x}", pan, addr);
            Some(Some(pan))
        }

        AddrMode::Extended => {
            let pan = c.u16_le()?;
            let addr = c.u64_le()?;

            defmt::info!("dst_pan={=u16:04x} dst_ext={=u64:016x}", pan, addr);
            Some(Some(pan))
        }

        AddrMode::Reserved => {
            defmt::warn!("reserved dst addr mode");
            None
        }
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
            let pan_id = if !pan_compression {
                let src_pan = c.u16_le()?;
                defmt::info!("src_pan={=u16:04x}", src_pan);
                Some(src_pan)
            } else if let Some(pan) = dst_pan {
                defmt::info!("src_pan compressed={=u16:04x}", pan);
                Some(pan)
            } else {
                None
            };

            let addr = c.u16_le()?;
            defmt::info!("src_short={=u16:04x}", addr);

            Some(ParsedSrcAddr {
                pan_id,
                short_addr: Some(addr),
                ext_addr: None,
            })
        }

        AddrMode::Extended => {
            let pan_id = if !pan_compression {
                let src_pan = c.u16_le()?;
                defmt::info!("src_pan={=u16:04x}", src_pan);
                Some(src_pan)
            } else if let Some(pan) = dst_pan {
                defmt::info!("src_pan compressed={=u16:04x}", pan);
                Some(pan)
            } else {
                None
            };

            let addr = c.u64_le()?;
            defmt::info!("src_ext={=u64:016x}", addr);

            Some(ParsedSrcAddr {
                pan_id,
                short_addr: None,
                ext_addr: Some(addr),
            })
        }

        AddrMode::Reserved => {
            defmt::warn!("reserved src addr mode");
            None
        }
    }
}

fn parse_security_header(c: &mut Cursor) -> Option<()> {
    let security_control = c.u8()?;

    let security_level = security_control & 0b0000_0111;
    let key_id_mode = (security_control >> 3) & 0b11;
    let frame_counter_suppression = (security_control & (1 << 5)) != 0;
    let asn_in_nonce = (security_control & (1 << 6)) != 0;

    defmt::info!(
        "security_control={=u8:02x} level={} key_id_mode={} frame_counter_suppression={} asn_in_nonce={}",
        security_control,
        security_level,
        key_id_mode,
        frame_counter_suppression,
        asn_in_nonce
    );

    if !frame_counter_suppression {
        let frame_counter = c.u32_le()?;
        defmt::info!("frame_counter={=u32}", frame_counter);
    }

    match key_id_mode {
        0 => {
            defmt::info!("key_id_mode=implicit");
        }

        1 => {
            let key_index = c.u8()?;
            defmt::info!("key_index={}", key_index);
        }

        2 => {
            let key_source = c.u32_le()?;
            let key_index = c.u8()?;
            defmt::info!(
                "key_source_4={=u32:08x} key_index={}",
                key_source,
                key_index
            );
        }

        3 => {
            let key_source = c.u64_le()?;
            let key_index = c.u8()?;
            defmt::info!(
                "key_source_8={=u64:016x} key_index={}",
                key_source,
                key_index
            );
        }

        _ => {}
    }

    Some(())
}

fn decode_lowpan_payload(payload: &[u8]) {
    if payload.is_empty() {
        defmt::info!("6LoWPAN: empty payload");
        return;
    }

    let dispatch = payload[0];

    if dispatch == 0x41 {
        defmt::info!(
            "6LoWPAN: uncompressed IPv6 dispatch=0x41 len={}",
            payload.len()
        );
        return;
    }

    if dispatch & 0b1110_0000 == 0b0110_0000 {
        defmt::info!(
            "6LoWPAN: IPHC compressed IPv6 dispatch={=u8:02x} len={}",
            dispatch,
            payload.len()
        );
        decode_iphc_summary(payload);
        return;
    }

    if dispatch & 0b1111_1000 == 0b1100_0000 {
        defmt::info!(
            "6LoWPAN: fragmentation first dispatch={=u8:02x} len={}",
            dispatch,
            payload.len()
        );
        return;
    }

    if dispatch & 0b1111_1000 == 0b1110_0000 {
        defmt::info!(
            "6LoWPAN: fragmentation subsequent dispatch={=u8:02x} len={}",
            dispatch,
            payload.len()
        );
        return;
    }

    if dispatch & 0b1100_0000 == 0b1000_0000 {
        defmt::info!(
            "6LoWPAN: mesh header dispatch={=u8:02x} len={}",
            dispatch,
            payload.len()
        );
        return;
    }

    if dispatch & 0b1110_0000 == 0b1010_0000 {
        defmt::info!(
            "6LoWPAN: broadcast header dispatch={=u8:02x} len={}",
            dispatch,
            payload.len()
        );
        return;
    }

    defmt::info!(
        "6LoWPAN: unknown dispatch={=u8:02x} len={}",
        dispatch,
        payload.len()
    );
}

fn decode_iphc_summary(payload: &[u8]) {
    if payload.len() < 2 {
        defmt::warn!("IPHC: truncated header");
        return;
    }

    let b0 = payload[0];
    let b1 = payload[1];

    let tf = (b0 >> 3) & 0b11;
    let nh_compressed = (b0 & (1 << 2)) != 0;
    let hlim = b0 & 0b11;

    let cid = (b1 & (1 << 7)) != 0;
    let sac = (b1 & (1 << 6)) != 0;
    let sam = (b1 >> 4) & 0b11;
    let m = (b1 & (1 << 3)) != 0;
    let dac = (b1 & (1 << 2)) != 0;
    let dam = b1 & 0b11;

    defmt::info!(
        "IPHC: tf={} nh_compressed={} hlim={} cid={} sac={} sam={} multicast={} dac={} dam={}",
        tf,
        nh_compressed,
        hlim,
        cid,
        sac,
        sam,
        m,
        dac,
        dam
    );

    if nh_compressed {
        defmt::info!(
            "IPHC: next header is compressed, likely NHC follows after compressed IPv6 fields"
        );
    } else {
        defmt::info!("IPHC: next header is carried inline");
    }
}

fn decode_802154(
    frame: &[u8],
    lqi: u8,
    routers: &mut [Option<SeenRouter>; MAX_ROUTERS],
    short_devices: &mut [Option<SeenShortDevice>; MAX_SHORT_DEVICES],
) {
    let mut c = Cursor::new(frame);

    let fcf_raw = match c.u16_le() {
        Some(v) => v,
        None => {
            defmt::warn!("too short: missing FCF len={}", frame.len());
            return;
        }
    };

    let seq = match c.u8() {
        Some(v) => v,
        None => {
            defmt::warn!("too short: missing sequence len={}", frame.len());
            return;
        }
    };

    let fcf = parse_fcf(fcf_raw);

    if fcf.frame_type.is_ack() {
        defmt::info!("ACK seq={}", seq);
        return;
    }

    defmt::info!(
        "802.15.4 type={} seq={} security={} frame_pending={} ack_req={} pan_comp={} ver={} dst_mode={} src_mode={}",
        fcf.frame_type,
        seq,
        fcf.security_enabled,
        fcf.frame_pending,
        fcf.ack_request,
        fcf.pan_compression,
        fcf.frame_version,
        fcf.dst_mode,
        fcf.src_mode
    );

    let dst_pan = match parse_dst_addr(&mut c, fcf.dst_mode) {
        Some(v) => v,
        None => {
            defmt::warn!("failed parsing dst addr");
            return;
        }
    };

    if let Some(pan) = dst_pan {
        if pan != PAN_ID {
            defmt::debug!("ignore other PAN={=u16:04x}", pan);
            return;
        }
    }

    let src = match parse_src_addr(&mut c, fcf.src_mode, fcf.pan_compression, dst_pan) {
        Some(v) => v,
        None => {
            defmt::warn!("failed parsing src addr");
            return;
        }
    };

    if fcf.frame_type.is_beacon() {
        if let (Some(pan_id), Some(ext_addr)) = (src.pan_id, src.ext_addr) {
            if pan_id == PAN_ID {
                remember_router(routers, ext_addr, pan_id, lqi);
            }
        }
    }

    if let (Some(pan_id), Some(short_addr)) = (src.pan_id, src.short_addr) {
        if pan_id == PAN_ID {
            remember_short_device(short_devices, short_addr, pan_id, lqi);
        }
    }

    if fcf.security_enabled {
        if parse_security_header(&mut c).is_none() {
            defmt::warn!("failed parsing security header");
            return;
        }
    }

    defmt::info!("header_len={} remaining_len={}", c.pos(), c.remaining());

    if fcf.security_enabled {
        defmt::info!("payload is MAC-secured/encrypted; skipping 6LoWPAN decode");
    } else {
        decode_lowpan_payload(c.remaining_slice());
    }
}
