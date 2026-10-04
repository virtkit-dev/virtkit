// Copyright 2025 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;

use crate::bus::BusDevice;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;
/// Extended memory from 16 MiB to 4 GiB in 64 KiB units, low and high byte.
const EXT_MEM_LOW: u8 = 0x34;
const EXT_MEM_HIGH: u8 = 0x35;
/// Memory above 4 GiB in 64 KiB units, low to high byte.
const HIGH_MEM_LOW: u8 = 0x5b;
const HIGH_MEM_MID: u8 = 0x5c;
const HIGH_MEM_HIGH: u8 = 0x5d;

// The RTC (MC146818): the time registers read the host clock plus an offset the guest moves
// by writing them, in the format register B selects (BCD or binary, 12- or 24-hour). Upstream
// emulated it on Windows hosts only; elsewhere every time register read 0 and UEFI firmware
// (PcRtc) and Windows saw a dead clock (local patch, see VENDOR.md).
const RTC_SECONDS: u8 = 0x00;
const RTC_MINUTES: u8 = 0x02;
const RTC_HOURS: u8 = 0x04;
const RTC_DAY_OF_WEEK: u8 = 0x06;
const RTC_DAY_OF_MONTH: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_REG_A: u8 = 0x0a;
const RTC_REG_B: u8 = 0x0b;
const RTC_REG_C: u8 = 0x0c;
const RTC_REG_D: u8 = 0x0d;
const RTC_CENTURY: u8 = 0x32;
/// Register A: the update-in-progress bit. It reads 1 during the last `UIP_NANOS` of each
/// second, as on hardware, so a guest that waits for it to clear reads every field within the
/// same second.
const REG_A_UIP: u8 = 0x80;
const UIP_NANOS: u32 = 244_000;
/// Register B: SET, which holds the clock while the guest writes it; binary (not BCD) data
/// mode; and 24-hour (not 12-hour) mode.
const REG_B_SET: u8 = 0x80;
const REG_B_DM_BINARY: u8 = 0x04;
const REG_B_24H: u8 = 0x02;
/// Register D: valid RAM and time.
const REG_D_VRT: u8 = 0x80;
/// The PM flag in the hours register in 12-hour mode.
const HOURS_PM: u8 = 0x80;

fn to_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

fn from_bcd(value: u8) -> u8 {
    (value >> 4) * 10 + (value & 0x0f)
}

/// A broken-down UTC date and time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub struct DateTime {
    year: i64,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    /// 1 (Sunday) to 7.
    weekday: u8,
}

impl DateTime {
    fn from_epoch(epoch_secs: i64) -> Self {
        let days = epoch_secs.div_euclid(86_400);
        let secs = epoch_secs.rem_euclid(86_400);
        // Days since the Unix epoch to a proleptic Gregorian date (Howard Hinnant's algorithm).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        DateTime {
            year,
            month: month as u8,
            day: day as u8,
            hour: (secs / 3_600) as u8,
            minute: (secs / 60 % 60) as u8,
            second: (secs % 60) as u8,
            weekday: ((days + 4).rem_euclid(7) + 1) as u8,
        }
    }

    fn to_epoch(self) -> i64 {
        let y = self.year - i64::from(self.month <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = i64::from(self.month);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        days * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

fn host_time() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

fn host_epoch_secs() -> i64 {
    host_time().as_secs() as i64
}

pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
    /// The time the guest is writing while register B's SET bit is up: the clock it read when
    /// SET rose, with the fields written since. Clearing SET sets the clock to it at once, so
    /// a date that is invalid between two field writes (Feb 31 on the way from Feb 15 to Mar
    /// 31) is never normalized, and the clock does not tick between writes.
    pending: Option<DateTime>,
    /// Guest RTC time minus host time, in seconds.
    rtc_offset: i64,
}

/// [`Cmos::save_state`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub struct CmosState {
    pub index: u8,
    pub data: Vec<u8>,
    pub rtc_offset: i64,
    /// The time being written under register B's SET bit ([`Cmos`]'s `pending`).
    #[cfg_attr(feature = "snapshot", serde(default))]
    pub pending: Option<DateTime>,
}

impl Cmos {
    /// What a snapshot keeps: the selected index, the NVRAM, the clock's offset from the
    /// host's and a time being set (local patch).
    pub fn save_state(&self) -> CmosState {
        CmosState {
            index: self.index,
            data: self.data.to_vec(),
            rtc_offset: self.rtc_offset,
            pending: self.pending,
        }
    }

    /// Put back what [`Cmos::save_state`] returned.
    pub fn restore_state(&mut self, state: &CmosState) {
        self.index = state.index;
        let len = state.data.len().min(DATA_LEN);
        self.data[..len].copy_from_slice(&state.data[..len]);
        self.rtc_offset = state.rtc_offset;
        self.pending = state.pending;
    }

    pub fn new(mem_below_4g: u64, mem_above_4g: u64) -> Cmos {
        debug!("cmos: mem_below_4g={mem_below_4g} mem_above_4g={mem_above_4g}");

        let mut data = [0u8; DATA_LEN];

        // Extended memory from 16 MB to 4 GB in units of 64 KB
        let ext_mem = min(
            0xFFFF,
            mem_below_4g.saturating_sub(16 * 1024 * 1024) / (64 * 1024),
        );
        data[EXT_MEM_LOW as usize] = ext_mem as u8;
        data[EXT_MEM_HIGH as usize] = (ext_mem >> 8) as u8;

        // High memory (> 4GB) in units of 64 KB
        let high_mem = min(0xFFFFFF, mem_above_4g / (64 * 1024));
        data[HIGH_MEM_LOW as usize] = high_mem as u8;
        data[HIGH_MEM_MID as usize] = (high_mem >> 8) as u8;
        data[HIGH_MEM_HIGH as usize] = (high_mem >> 16) as u8;

        // 32.768 kHz time base, 1024 Hz rate; 24-hour BCD.
        data[RTC_REG_A as usize] = 0x26;
        data[RTC_REG_B as usize] = REG_B_24H;

        Cmos {
            index: 0,
            data,
            pending: None,
            rtc_offset: 0,
        }
    }

    fn now(&self) -> DateTime {
        DateTime::from_epoch(host_epoch_secs() + self.rtc_offset)
    }

    fn binary(&self) -> bool {
        self.data[RTC_REG_B as usize] & REG_B_DM_BINARY != 0
    }

    fn encode(&self, value: u8) -> u8 {
        if self.binary() { value } else { to_bcd(value) }
    }

    fn decode(&self, value: u8) -> u8 {
        if self.binary() {
            value
        } else {
            from_bcd(value)
        }
    }

    fn encode_hours(&self, hour: u8) -> u8 {
        if self.data[RTC_REG_B as usize] & REG_B_24H != 0 {
            return self.encode(hour);
        }
        let pm = if hour >= 12 { HOURS_PM } else { 0 };
        let h12 = match hour % 12 {
            0 => 12,
            h => h,
        };
        self.encode(h12) | pm
    }

    fn decode_hours(&self, value: u8) -> u8 {
        if self.data[RTC_REG_B as usize] & REG_B_24H != 0 {
            return self.decode(value);
        }
        let h12 = self.decode(value & !HOURS_PM) % 12;
        if value & HOURS_PM != 0 { h12 + 12 } else { h12 }
    }

    fn read_rtc(&self, index: u8) -> Option<u8> {
        let now = self.pending.unwrap_or_else(|| self.now());
        Some(match index {
            RTC_SECONDS => self.encode(now.second),
            RTC_MINUTES => self.encode(now.minute),
            RTC_HOURS => self.encode_hours(now.hour),
            RTC_DAY_OF_WEEK => self.encode(now.weekday),
            RTC_DAY_OF_MONTH => self.encode(now.day),
            RTC_MONTH => self.encode(now.month),
            RTC_YEAR => self.encode(now.year.rem_euclid(100) as u8),
            RTC_CENTURY => self.encode(now.year.div_euclid(100) as u8),
            RTC_REG_A => {
                let updating = self.pending.is_none()
                    && host_time().subsec_nanos() >= 1_000_000_000 - UIP_NANOS;
                self.data[RTC_REG_A as usize] | if updating { REG_A_UIP } else { 0 }
            }
            // No RTC interrupt is ever raised, so no flag is ever pending.
            RTC_REG_C => 0,
            RTC_REG_D => REG_D_VRT,
            _ => return None,
        })
    }

    /// A guest write to a time register sets the clock: the offset moves so that field reads
    /// back as written, the others keeping their current values. With SET up, the write goes to
    /// the pending time instead, which the clock takes when SET drops. Returns false for a
    /// register that is not part of the clock.
    fn write_rtc(&mut self, index: u8, value: u8) -> bool {
        let mut t = self.pending.unwrap_or_else(|| self.now());
        match index {
            RTC_SECONDS => t.second = self.decode(value).min(59),
            RTC_MINUTES => t.minute = self.decode(value).min(59),
            RTC_HOURS => t.hour = self.decode_hours(value).min(23),
            RTC_DAY_OF_MONTH => t.day = self.decode(value).clamp(1, 31),
            RTC_MONTH => t.month = self.decode(value).clamp(1, 12),
            RTC_YEAR => t.year = t.year.div_euclid(100) * 100 + i64::from(self.decode(value) % 100),
            RTC_CENTURY => t.year = i64::from(self.decode(value)) * 100 + t.year.rem_euclid(100),
            // The weekday follows from the date.
            RTC_DAY_OF_WEEK => return true,
            RTC_REG_A => {
                self.data[RTC_REG_A as usize] = value & !REG_A_UIP;
                return true;
            }
            RTC_REG_B => {
                self.data[RTC_REG_B as usize] = value;
                if value & REG_B_SET == 0 {
                    if let Some(t) = self.pending.take() {
                        self.rtc_offset = t.to_epoch() - host_epoch_secs();
                    }
                } else if self.pending.is_none() {
                    self.pending = Some(t);
                }
                return true;
            }
            RTC_REG_C | RTC_REG_D => return true,
            _ => return false,
        }
        if self.pending.is_some() {
            self.pending = Some(t);
        } else {
            // Without SET a field write applies at once, normalized: day 31 in February becomes
            // March 3, which a later month write cannot undo. Real guests (edk2's PcRtc, Linux,
            // the Windows HAL) raise SET first.
            self.rtc_offset = t.to_epoch() - host_epoch_secs();
        }
        true
    }
}

impl BusDevice for Cmos {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported read length");
            return;
        }

        data[0] = match offset {
            INDEX_OFFSET => {
                debug!("cmos: read index offset");
                self.index
            }
            DATA_OFFSET => {
                debug!("cmos: read data offset from index={:x}", self.index);
                let index = self.index & INDEX_MASK;
                self.read_rtc(index).unwrap_or(self.data[index as usize])
            }
            _ => {
                debug!("cmos: unsupported read offset");
                0
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported write length");
            return;
        }

        match offset {
            INDEX_OFFSET => {
                debug!("cmos: update index");
                self.index = data[0] & INDEX_MASK;
            }
            DATA_OFFSET => {
                let index = self.index & INDEX_MASK;
                // The memory sizes are the VMM's to report; the rest is guest NVRAM.
                if !self.write_rtc(index, data[0])
                    && !matches!(
                        index,
                        EXT_MEM_LOW | EXT_MEM_HIGH | HIGH_MEM_LOW | HIGH_MEM_MID | HIGH_MEM_HIGH
                    )
                {
                    self.data[index as usize] = data[0];
                }
            }
            _ => debug!("cmos: ignoring unsupported write to CMOS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(cmos: &mut Cmos, index: u8) -> u8 {
        cmos.write(0, INDEX_OFFSET, &[index]);
        let mut data = [0];
        cmos.read(0, DATA_OFFSET, &mut data);
        data[0]
    }

    fn write(cmos: &mut Cmos, index: u8, value: u8) {
        cmos.write(0, INDEX_OFFSET, &[index]);
        cmos.write(0, DATA_OFFSET, &[value]);
    }

    #[test]
    fn dates_round_trip_through_the_epoch() {
        for epoch in [0, 951_782_400, 1_790_000_000, 4_102_444_800] {
            assert_eq!(DateTime::from_epoch(epoch).to_epoch(), epoch);
        }
        let leap = DateTime::from_epoch(951_782_400); // 2000-02-29 00:00:00 UTC, a Tuesday
        assert_eq!(
            (leap.year, leap.month, leap.day, leap.weekday),
            (2000, 2, 29, 3)
        );
    }

    #[test]
    fn the_clock_reads_the_host_time_in_bcd_with_valid_status() {
        let mut cmos = Cmos::new(1 << 30, 0);
        let before = DateTime::from_epoch(host_epoch_secs());
        let century = from_bcd(read(&mut cmos, RTC_CENTURY));
        let month = from_bcd(read(&mut cmos, RTC_MONTH));
        let after = DateTime::from_epoch(host_epoch_secs());
        assert_eq!(read(&mut cmos, RTC_REG_D), REG_D_VRT);
        // A month or century boundary may pass between the samples.
        assert!(
            [before, after]
                .iter()
                .any(|host| (host.year / 100) as u8 == century)
        );
        assert!([before, after].iter().any(|host| host.month == month));
    }

    #[test]
    fn update_in_progress_shows_only_at_the_end_of_a_second() {
        let mut cmos = Cmos::new(1 << 30, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "no read landed inside the update-in-progress window within 5 s"
            );
            let start = host_time().subsec_nanos();
            let uip = read(&mut cmos, RTC_REG_A) & REG_A_UIP != 0;
            let end = host_time().subsec_nanos();
            // Only a read that did not straddle the window's edges says anything.
            if start <= end
                && (end < 1_000_000_000 - UIP_NANOS || start >= 1_000_000_000 - UIP_NANOS)
            {
                assert_eq!(uip, start >= 1_000_000_000 - UIP_NANOS);
                if uip {
                    break;
                }
            }
        }
    }

    #[test]
    fn set_holds_the_clock_until_every_field_is_written() {
        let mut cmos = Cmos::new(1 << 30, 0);
        let set_date = |cmos: &mut Cmos, year: u8, month: u8, day: u8| {
            write(cmos, RTC_REG_B, REG_B_SET | REG_B_24H | REG_B_DM_BINARY);
            assert_eq!(read(cmos, RTC_REG_A) & REG_A_UIP, 0);
            write(cmos, RTC_DAY_OF_MONTH, day);
            write(cmos, RTC_MONTH, month);
            write(cmos, RTC_YEAR, year);
            write(cmos, RTC_CENTURY, 20);
            write(cmos, RTC_HOURS, 12);
            write(cmos, RTC_MINUTES, 0);
            write(cmos, RTC_SECONDS, 0);
            // While SET is up, the clock reads what was written.
            assert_eq!(read(cmos, RTC_DAY_OF_MONTH), day);
            write(cmos, RTC_REG_B, REG_B_24H | REG_B_DM_BINARY);
        };
        set_date(&mut cmos, 26, 2, 15);
        assert_eq!(read(&mut cmos, RTC_MONTH), 2);
        assert_eq!(read(&mut cmos, RTC_DAY_OF_MONTH), 15);
        // Writing the day first goes through Feb 31, which must not become Mar 3.
        set_date(&mut cmos, 26, 3, 31);
        assert_eq!(read(&mut cmos, RTC_MONTH), 3);
        assert_eq!(read(&mut cmos, RTC_DAY_OF_MONTH), 31);
        assert_eq!(read(&mut cmos, RTC_YEAR), 26);
    }

    #[test]
    fn a_time_being_set_survives_save_and_restore() {
        let mut cmos = Cmos::new(1 << 30, 0);
        write(
            &mut cmos,
            RTC_REG_B,
            REG_B_SET | REG_B_24H | REG_B_DM_BINARY,
        );
        write(&mut cmos, RTC_DAY_OF_MONTH, 31);
        write(&mut cmos, RTC_MONTH, 2);
        let mut back = Cmos::new(1 << 30, 0);
        back.restore_state(&cmos.save_state());
        write(&mut back, RTC_MONTH, 3);
        write(&mut back, RTC_REG_B, REG_B_24H | REG_B_DM_BINARY);
        assert_eq!(read(&mut back, RTC_MONTH), 3);
        assert_eq!(read(&mut back, RTC_DAY_OF_MONTH), 31);
    }

    #[test]
    fn a_guest_write_sets_the_clock_and_binary_mode_reads_it_back() {
        let mut cmos = Cmos::new(1 << 30, 0);
        write(&mut cmos, RTC_REG_B, REG_B_24H | REG_B_DM_BINARY);
        write(&mut cmos, RTC_YEAR, 99);
        write(&mut cmos, RTC_CENTURY, 20);
        write(&mut cmos, RTC_MONTH, 12);
        write(&mut cmos, RTC_DAY_OF_MONTH, 31);
        write(&mut cmos, RTC_HOURS, 23);
        assert_eq!(read(&mut cmos, RTC_YEAR), 99);
        assert_eq!(read(&mut cmos, RTC_CENTURY), 20);
        assert_eq!(read(&mut cmos, RTC_MONTH), 12);
        assert_eq!(read(&mut cmos, RTC_HOURS), 23);
    }

    #[test]
    fn twelve_hour_mode_carries_the_pm_flag() {
        let mut cmos = Cmos::new(1 << 30, 0);
        write(&mut cmos, RTC_REG_B, REG_B_24H);
        write(&mut cmos, RTC_HOURS, to_bcd(15));
        write(&mut cmos, RTC_REG_B, 0);
        assert_eq!(read(&mut cmos, RTC_HOURS), HOURS_PM | to_bcd(3));
    }

    #[test]
    fn memory_sizes_stay_and_other_nvram_is_writable() {
        let mut cmos = Cmos::new(1 << 30, 0);
        let ext = read(&mut cmos, EXT_MEM_LOW);
        write(&mut cmos, EXT_MEM_LOW, ext.wrapping_add(1));
        assert_eq!(read(&mut cmos, EXT_MEM_LOW), ext);
        write(&mut cmos, 0x40, 0x5a);
        assert_eq!(read(&mut cmos, 0x40), 0x5a);
    }
}
