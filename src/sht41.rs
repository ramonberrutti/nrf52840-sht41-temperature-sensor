use defmt::{trace, warn};
use embassy_time::{Duration, Timer};
use embedded_hal_async::i2c::I2c;

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
