#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_nrf::{
    bind_interrupts, peripherals,
    twim::{self, Twim},
};
use embassy_time::{Duration, Timer};
use embedded_hal_async::i2c::I2c;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    TWISPI0 => twim::InterruptHandler<peripherals::TWISPI0>;
});

const SHT41_ADDR: u8 = 0x44;
const CMD_MEASURE_HIGH_PRECISION: u8 = 0xFD;

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
async fn main(_spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

    // Change these pins to match your board.
    let sda = p.P0_20;
    let scl = p.P0_22;

    let mut config = twim::Config::default();
    config.frequency = twim::Frequency::K100;

    let mut twim_buffer = [0u8; 16];

    let i2c = Twim::new(p.TWISPI0, Irqs, sda, scl, config, &mut twim_buffer);

    let mut sht41 = Sht41::new(i2c);

    info!("SHT41 example started");

    loop {
        match sht41.read().await {
            Ok((temp_c, rh)) => {
                info!("temperature: {} C, humidity: {} %RH", temp_c, rh);
            }
            Err(e) => {
                warn!("SHT41 read failed: {:?}", defmt::Debug2Format(&e));
            }
        }

        Timer::after(Duration::from_secs(2)).await;
    }
}
