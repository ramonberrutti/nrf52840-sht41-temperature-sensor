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
use embassy_time::{Duration, Timer};
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
const EXT_PAN_ID: u64 = 0x297c_f951_98ae_4f6c;

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
                decode_802154(frame);
                defmt::debug!("raw={:02x}", frame);
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
}

#[derive(Clone, Copy, defmt::Format)]
enum AddrMode {
    None,
    Short,
    Extended,
    Reserved,
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
) -> Option<()> {
    match mode {
        AddrMode::None => Some(()),

        AddrMode::Short => {
            if !pan_compression {
                let src_pan = c.u16_le()?;
                defmt::info!("src_pan={=u16:04x}", src_pan);
            } else if let Some(pan) = dst_pan {
                defmt::info!("src_pan compressed={=u16:04x}", pan);
            }

            let addr = c.u16_le()?;
            defmt::info!("src_short={=u16:04x}", addr);

            Some(())
        }

        AddrMode::Extended => {
            if !pan_compression {
                let src_pan = c.u16_le()?;
                defmt::info!("src_pan={=u16:04x}", src_pan);
            } else if let Some(pan) = dst_pan {
                defmt::info!("src_pan compressed={=u16:04x}", pan);
            }

            let addr = c.u64_le()?;
            defmt::info!("src_ext={=u64:016x}", addr);

            Some(())
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

fn decode_802154(frame: &[u8]) {
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

    if parse_src_addr(&mut c, fcf.src_mode, fcf.pan_compression, dst_pan).is_none() {
        defmt::warn!("failed parsing src addr");
        return;
    }

    if fcf.security_enabled {
        if parse_security_header(&mut c).is_none() {
            defmt::warn!("failed parsing security header");
            return;
        }
    }

    defmt::info!("header_len={} remaining_len={}", c.pos(), c.remaining());
}
