// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt;
use std::num::Wrapping;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, result};
use utils::eventfd::EventFd;

use crate::bus::BusDevice;

#[derive(Debug)]
pub enum Error {
    CloneCpuResetEvt(io::Error),
    KbdInterruptDisabled,
    KbdInterruptFailure(io::Error),
    InternalBufferFull,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::CloneCpuResetEvt(io_err) => {
                write!(f, "Could not clone CPU reset eventfd: {io_err}.")
            }
            Error::KbdInterruptDisabled => {
                write!(f, "Keyboard interrupt disabled by guest driver.",)
            }
            Error::KbdInterruptFailure(io_err) => {
                write!(f, "Could not trigger keyboard interrupt: {io_err}.")
            }
            Error::InternalBufferFull => write!(f, "i8042 internal buffer full."),
        }
    }
}

type Result<T> = result::Result<T, Error>;

/// Offset of the status port (port 0x64)
const OFS_STATUS: u64 = 4;

/// Offset of the data port (port 0x60)
const OFS_DATA: u64 = 0;

/// i8042 commands
/// These values are written by the guest driver to port 0x64.
const CMD_READ_CTR: u8 = 0x20; // Read control register
const CMD_WRITE_CTR: u8 = 0x60; // Write control register
const CMD_READ_OUTP: u8 = 0xD0; // Read output port
const CMD_WRITE_OUTP: u8 = 0xD1; // Write output port
const CMD_RESET_CPU: u8 = 0xFE; // Reset CPU
// Local patch (see VENDOR.md): the commands a Linux i8042/atkbd probe sends, answered as a
// controller with a keyboard and no AUX (mouse) port.
const CMD_DISABLE_AUX: u8 = 0xA7;
const CMD_ENABLE_AUX: u8 = 0xA8;
const CMD_SELF_TEST: u8 = 0xAA;
const CMD_KBD_TEST: u8 = 0xAB;
const CMD_DISABLE_KBD: u8 = 0xAD;
const CMD_ENABLE_KBD: u8 = 0xAE;
const CMD_WRITE_KBD_OUT: u8 = 0xD2; // the next data byte comes back as if the keyboard sent it
const CMD_WRITE_AUX_OUT: u8 = 0xD3; // ... as if the AUX port sent it: no AUX here, dropped
const CMD_WRITE_AUX: u8 = 0xD4; // the next data byte goes to the AUX device: dropped

/// i8042 status register bits
const SB_OUT_DATA_AVAIL: u8 = 0x0001; // Data available at port 0x60
const SB_I8042_CMD_DATA: u8 = 0x0008; // i8042 expecting command parameter at port 0x60
const SB_KBD_ENABLED: u8 = 0x0010; // 1 = kbd enabled, 0 = kbd locked

/// i8042 control register bits
const CB_KBD_INT: u8 = 0x0001; // kbd interrupt enabled
const CB_POST_OK: u8 = 0x0004; // POST ok (should always be 1)
const CB_KBD_DISABLE: u8 = 0x0010; // kbd interface disabled (local patch)
const CB_AUX_DISABLE: u8 = 0x0020; // AUX interface disabled (local patch)

/// Keyboard commands, written to port 0x60 (local patch).
const KBD_CMD_SET_LEDS: u8 = 0xED;
const KBD_CMD_ECHO: u8 = 0xEE;
const KBD_CMD_SCANCODE_SET: u8 = 0xF0;
const KBD_CMD_GET_ID: u8 = 0xF2;
const KBD_CMD_TYPEMATIC: u8 = 0xF3;
const KBD_CMD_ENABLE: u8 = 0xF4;
const KBD_CMD_DISABLE: u8 = 0xF5;
const KBD_CMD_RESET: u8 = 0xFF;
/// Keyboard replies.
const KBD_ACK: u8 = 0xFA;
const KBD_SELF_TEST_OK: u8 = 0xAA;
/// An MF2 keyboard, untranslated.
const KBD_ID: [u8; 2] = [0xAB, 0x83];
/// The scancode set the keyboard sends: set 2, the one `type_scancodes` callers use.
const KBD_SCANCODE_SET: u8 = 0x02;

/// Key scan codes
const KEY_CTRL: u16 = 0x0014;
const KEY_ALT: u16 = 0x0011;
const KEY_DEL: u16 = 0xE071;

/// Internal i8042 buffer size, in bytes
const BUF_SIZE: usize = 16;

/// A i8042 PS/2 controller that emulates just enough to shutdown the machine.
pub struct I8042Device {
    /// CPU reset eventfd. We will set this event when the guest issues CMD_RESET_CPU.
    reset_evt: EventFd,

    /// Shared with the Vmm and the ACPI PM device: set before firing `reset_evt`
    /// so a guest `reboot=kbd` is reported as a reset, not a clean power-off.
    reset_flag: Arc<AtomicBool>,

    /// Keyboard interrupt event (IRQ 1).
    kbd_interrupt_evt: EventFd,

    /// The i8042 status register.
    status: u8,

    /// The i8042 control register.
    control: u8,

    /// The i8042 output port.
    outp: u8,

    /// The last command sent to port 0x64.
    cmd: u8,

    /// The internal i8042 data buffer.
    buf: [u8; BUF_SIZE],
    bhead: Wrapping<usize>,
    btail: Wrapping<usize>,

    /// A keyboard command that takes a parameter, waiting for it (local patch).
    kbd_param: Option<u8>,
    /// Whether the keyboard scans, so typed keys reach the guest (local patch).
    kbd_scanning: bool,
}

/// [`I8042Device::save_state`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub struct I8042State {
    pub status: u8,
    pub control: u8,
    pub outp: u8,
    pub cmd: u8,
}

impl I8042Device {
    /// What a snapshot keeps: the controller's registers; queued bytes are dropped (local
    /// patch).
    pub fn save_state(&self) -> I8042State {
        I8042State {
            status: self.status,
            control: self.control,
            outp: self.outp,
            cmd: self.cmd,
        }
    }

    /// Put back what [`I8042Device::save_state`] returned.
    pub fn restore_state(&mut self, state: &I8042State) {
        self.status = state.status;
        self.control = state.control;
        self.outp = state.outp;
        self.cmd = state.cmd;
    }

    /// Constructs an i8042 device that will signal the given event when the guest requests it.
    pub fn new(
        reset_evt: EventFd,
        reset_flag: Arc<AtomicBool>,
        kbd_interrupt_evt: EventFd,
    ) -> I8042Device {
        I8042Device {
            reset_evt,
            reset_flag,
            kbd_interrupt_evt,
            control: CB_POST_OK | CB_KBD_INT,
            cmd: 0,
            outp: 0,
            status: SB_KBD_ENABLED,
            buf: [0; BUF_SIZE],
            bhead: Wrapping(0),
            btail: Wrapping(0),
            kbd_param: None,
            kbd_scanning: true,
        }
    }

    /// Type set-2 scancodes as the keyboard would send them (local patch, see VENDOR.md).
    /// Returns how many were taken: as many as the buffer has room for, so the caller types the
    /// rest once the guest has read some. A keyboard the guest disabled takes them all and drops
    /// them, as a real one ignores keys while it does not scan.
    pub fn type_scancodes(&mut self, codes: &[u8]) -> usize {
        if !self.kbd_scanning || self.control & CB_KBD_DISABLE != 0 {
            return codes.len();
        }
        let room = BUF_SIZE - self.buf_len();
        let taken = codes.len().min(room);
        for &code in codes.iter().take(taken) {
            // Cannot fail: `taken` fits in the buffer's room.
            let _ = self.push_byte(code);
        }
        if taken > 0
            && let Err(Error::KbdInterruptFailure(err)) = self.trigger_kbd_interrupt()
        {
            warn!("Failed to trigger i8042 kbd interrupt {err:?}");
        }
        taken
    }

    /// Answer a byte the guest sent the keyboard: queue the keyboard's reply (local patch).
    fn keyboard_command(&mut self, byte: u8) {
        let reply: &[u8] = match self.kbd_param.take() {
            // The parameter of a scancode-set query (0) is answered with the set in use.
            Some(KBD_CMD_SCANCODE_SET) if byte == 0 => &[KBD_ACK, KBD_SCANCODE_SET],
            Some(_) => &[KBD_ACK],
            None => match byte {
                KBD_CMD_SET_LEDS | KBD_CMD_SCANCODE_SET | KBD_CMD_TYPEMATIC => {
                    self.kbd_param = Some(byte);
                    &[KBD_ACK]
                }
                KBD_CMD_ECHO => &[KBD_CMD_ECHO],
                KBD_CMD_GET_ID => &[KBD_ACK, KBD_ID[0], KBD_ID[1]],
                KBD_CMD_ENABLE => {
                    self.kbd_scanning = true;
                    &[KBD_ACK]
                }
                KBD_CMD_DISABLE => {
                    self.kbd_scanning = false;
                    &[KBD_ACK]
                }
                KBD_CMD_RESET => {
                    self.kbd_scanning = true;
                    &[KBD_ACK, KBD_SELF_TEST_OK]
                }
                // Since we're emulating a pretty dumb keyboard, we can get away with blindly
                // ack-in anything else. Something along the lines of "Yeah, uhm-uhm, yeah,
                // okay, honey, that's great."
                _ => &[KBD_ACK],
            },
        };
        self.reply(reply);
    }

    /// Replace whatever the guest has not read with `bytes`, and raise the interrupt.
    fn reply(&mut self, bytes: &[u8]) {
        self.flush_buf();
        for &b in bytes {
            // Cannot fail: the buffer is empty and every reply is shorter than it.
            let _ = self.push_byte(b);
        }
        if let Err(Error::KbdInterruptFailure(err)) = self.trigger_kbd_interrupt() {
            warn!("Failed to trigger i8042 kbd interrupt {err:?}");
        }
    }

    /// Returns a clone of the CPU reset event fd
    pub fn get_reset_evt_clone(&self) -> Result<EventFd> {
        self.reset_evt.try_clone().map_err(Error::CloneCpuResetEvt)
    }

    pub fn trigger_kbd_interrupt(&self) -> Result<()> {
        if (self.control & CB_KBD_INT) == 0 {
            warn!("Failed to trigger i8042 kbd interrupt (disabled by guest OS)");
            return Err(Error::KbdInterruptDisabled);
        }
        self.kbd_interrupt_evt
            .write(1)
            .map_err(Error::KbdInterruptFailure)
    }

    pub fn trigger_key(&mut self, key: u16) -> Result<()> {
        if key & 0xff00 != 0 {
            // Check if there is enough room in the buffer, before pushing an extended (2-byte) key.
            if BUF_SIZE - self.buf_len() < 2 {
                return Err(Error::InternalBufferFull);
            }
            self.push_byte((key >> 8) as u8)?;
        }
        self.push_byte((key & 0xff) as u8)?;

        match self.trigger_kbd_interrupt() {
            Ok(_) | Err(Error::KbdInterruptDisabled) => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[inline]
    pub fn trigger_ctrl_alt_del(&mut self) -> Result<()> {
        // The CTRL+ALT+DEL sequence is 4 bytes in total (1 extended key + 2 normal keys).
        // Fail if we don't have room for the whole sequence.
        if BUF_SIZE - self.buf_len() < 4 {
            return Err(Error::InternalBufferFull);
        }
        self.trigger_key(KEY_CTRL)?;
        self.trigger_key(KEY_ALT)?;
        self.trigger_key(KEY_DEL)?;
        Ok(())
    }

    #[inline]
    fn push_byte(&mut self, byte: u8) -> Result<()> {
        self.status |= SB_OUT_DATA_AVAIL;
        if self.buf_len() == BUF_SIZE {
            return Err(Error::InternalBufferFull);
        }
        self.buf[self.btail.0 % BUF_SIZE] = byte;
        self.btail += Wrapping(1usize);
        Ok(())
    }

    #[inline]
    fn pop_byte(&mut self) -> Option<u8> {
        if self.buf_len() == 0 {
            return None;
        }
        let res = self.buf[self.bhead.0 % BUF_SIZE];
        self.bhead += Wrapping(1usize);
        if self.buf_len() == 0 {
            self.status &= !SB_OUT_DATA_AVAIL;
        }
        Some(res)
    }

    #[inline]
    fn flush_buf(&mut self) {
        self.bhead = Wrapping(0usize);
        self.btail = Wrapping(0usize);
        self.status &= !SB_OUT_DATA_AVAIL;
    }

    #[inline]
    fn buf_len(&self) -> usize {
        (self.btail - self.bhead).0
    }
}

impl BusDevice for I8042Device {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        // All our ports are byte-wide. We don't know how to handle any wider data.
        if data.len() != 1 {
            return;
        }

        match offset {
            OFS_STATUS => data[0] = self.status,
            OFS_DATA => {
                // The guest wants to read a byte from port 0x60. For the 8042, that means the top
                // byte in the internal buffer. If the buffer is empty, the guest will get a 0.
                data[0] = self.pop_byte().unwrap_or(0);

                // Check if we still have data in the internal buffer. If so, we need to trigger
                // another interrupt, to let the guest know they need to issue another read from
                // port 0x60.
                if (self.status & SB_OUT_DATA_AVAIL) != 0
                    && let Err(Error::KbdInterruptFailure(err)) = self.trigger_kbd_interrupt()
                {
                    warn!("Failed to trigger i8042 kbd interrupt {err:?}");
                }
            }
            _ => {}
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        // All our ports are byte-wide. We don't know how to handle any wider data.
        if data.len() != 1 {
            return;
        }

        match offset {
            OFS_STATUS if data[0] == CMD_RESET_CPU => {
                // The guest wants to assert the CPU reset line. We handle that by triggering
                // our exit event fd. Meaning Firecracker will be exiting as soon as the VMM
                // thread wakes up to handle this event.
                // Flag it as a reset first, so the Vmm reports a guest reset rather than a
                // clean exit (`reset_flag`; local patch, see VENDOR.md).
                self.reset_flag.store(true, Ordering::SeqCst);
                if let Err(e) = self.reset_evt.write(1) {
                    error!("Failed to trigger i8042 reset event: {e:?}");
                }
            }
            OFS_STATUS if data[0] == CMD_READ_CTR => {
                // The guest wants to read the control register.
                // Let's make sure only the control register will be available for reading from
                // the data port, for the next inb(0x60).
                self.flush_buf();
                let control = self.control;
                // Buffer is empty, push() will always succeed.
                self.push_byte(control).unwrap();
            }
            OFS_STATUS if data[0] == CMD_WRITE_CTR => {
                // The guest wants to write the control register. This is a two-step command:
                // 1. port 0x64 < CMD_WRITE_CTR
                // 2. port 0x60 < <control reg value>
                // Make sure we'll be expecting the control reg value on port 0x60 for the next
                // write.
                self.flush_buf();
                self.status |= SB_I8042_CMD_DATA;
                self.cmd = data[0];
            }
            OFS_STATUS if data[0] == CMD_READ_OUTP => {
                // The guest wants to read the output port (for lack of a better name - this is
                // just another register on the 8042, that happens to also have its bits connected
                // to some output pins of the 8042).
                self.flush_buf();
                let outp = self.outp;
                // Buffer is empty, push() will always succeed.
                self.push_byte(outp).unwrap();
            }
            OFS_STATUS if data[0] == CMD_WRITE_OUTP => {
                // Similar to writing the control register, this is a two-step command.
                // I.e. write CMD_WRITE_OUTP at port 0x64, then write the actual out port value
                // to port 0x60.
                self.status |= SB_I8042_CMD_DATA;
                self.cmd = data[0];
            }
            // Local patch (see VENDOR.md): the rest of a Linux i8042 probe.
            OFS_STATUS
                if matches!(
                    data[0],
                    CMD_WRITE_KBD_OUT | CMD_WRITE_AUX_OUT | CMD_WRITE_AUX
                ) =>
            {
                self.status |= SB_I8042_CMD_DATA;
                self.cmd = data[0];
            }
            OFS_STATUS if data[0] == CMD_SELF_TEST => {
                self.flush_buf();
                // Cannot fail: the buffer was just flushed.
                let _ = self.push_byte(0x55);
            }
            OFS_STATUS if data[0] == CMD_KBD_TEST => {
                self.flush_buf();
                // Cannot fail: the buffer was just flushed.
                let _ = self.push_byte(0x00);
            }
            OFS_STATUS if data[0] == CMD_DISABLE_KBD => self.control |= CB_KBD_DISABLE,
            OFS_STATUS if data[0] == CMD_ENABLE_KBD => self.control &= !CB_KBD_DISABLE,
            OFS_STATUS if data[0] == CMD_DISABLE_AUX => self.control |= CB_AUX_DISABLE,
            OFS_STATUS if data[0] == CMD_ENABLE_AUX => self.control &= !CB_AUX_DISABLE,
            OFS_DATA if (self.status & SB_I8042_CMD_DATA) != 0 => {
                // The guest is writing to port 0x60. This byte can either be:
                // 1. the payload byte of a CMD_WRITE_CTR or CMD_WRITE_OUTP command, in which case
                //    the status reg bit SB_I8042_CMD_DATA will be set, or
                // 2. a direct command sent to the keyboard
                // This match arm handles the first option (when the SB_I8042_CMD_DATA bit is set).
                self.status &= !SB_I8042_CMD_DATA;
                match self.cmd {
                    CMD_WRITE_CTR => self.control = data[0],
                    CMD_WRITE_OUTP => self.outp = data[0],
                    CMD_WRITE_KBD_OUT => self.reply(&[data[0]]),
                    _ => (),
                }
            }
            OFS_DATA => {
                // The guest is sending a command straight to the keyboard (so this byte is not
                // addressed to the 8042, but to the keyboard).
                self.keyboard_command(data[0]);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl PartialEq for Error {
        fn eq(&self, other: &Error) -> bool {
            self.to_string() == other.to_string()
        }
    }

    #[test]
    fn test_i8042_read_write_and_event() {
        let mut i8042 = I8042Device::new(
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicBool::new(false)),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        );
        let reset_evt = i8042.get_reset_evt_clone().unwrap();

        // Check if reading in a 2-length array doesn't have side effects.
        let mut data = [1, 2];
        i8042.read(0, 0, &mut data);
        assert_eq!(data, [1, 2]);
        i8042.read(0, 1, &mut data);
        assert_eq!(data, [1, 2]);

        // Check if reset works.
        // Write 1 to the reset event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(reset_evt.write(1).is_ok());
        let mut data = [CMD_RESET_CPU];
        i8042.write(0, OFS_STATUS, &data);
        assert_eq!(reset_evt.read().unwrap(), 2);

        // Check if reading with offset 1 doesn't have side effects.
        i8042.read(0, 1, &mut data);
        assert_eq!(data[0], CMD_RESET_CPU);
    }

    #[test]
    fn test_i8042_commands() {
        let mut i8042 = I8042Device::new(
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicBool::new(false)),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        );
        let mut data = [1];

        // Test reading/writing the control register.
        data[0] = CMD_WRITE_CTR;
        i8042.write(0, OFS_STATUS, &data);
        assert_ne!(i8042.status & SB_I8042_CMD_DATA, 0);
        data[0] = 0x52;
        i8042.write(0, OFS_DATA, &data);
        data[0] = CMD_READ_CTR;
        i8042.write(0, OFS_STATUS, &data);
        assert_ne!(i8042.status & SB_OUT_DATA_AVAIL, 0);
        i8042.read(0, OFS_DATA, &mut data);
        assert_eq!(data[0], 0x52);

        // Test reading/writing the output port.
        data[0] = CMD_WRITE_OUTP;
        i8042.write(0, OFS_STATUS, &data);
        assert_ne!(i8042.status & SB_I8042_CMD_DATA, 0);
        data[0] = 0x52;
        i8042.write(0, OFS_DATA, &data);
        data[0] = CMD_READ_OUTP;
        i8042.write(0, OFS_STATUS, &data);
        assert_ne!(i8042.status & SB_OUT_DATA_AVAIL, 0);
        i8042.read(0, OFS_DATA, &mut data);
        assert_eq!(data[0], 0x52);

        // Test kbd commands.
        data[0] = 0x52;
        i8042.write(0, OFS_DATA, &data);
        assert_ne!(i8042.status & SB_OUT_DATA_AVAIL, 0);
        i8042.read(0, OFS_DATA, &mut data);
        assert_eq!(data[0], 0xFA);
    }

    #[test]
    fn test_i8042_buffer() {
        let mut i8042 = I8042Device::new(
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicBool::new(false)),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        );

        // Test push/pop.
        i8042.push_byte(52).unwrap();
        assert_ne!(i8042.status & SB_OUT_DATA_AVAIL, 0);
        assert_eq!(i8042.pop_byte().unwrap(), 52);
        assert_eq!(i8042.status & SB_OUT_DATA_AVAIL, 0);

        // Test empty buffer pop.
        assert!(i8042.pop_byte().is_none());

        // Test buffer full.
        for i in 0..BUF_SIZE {
            i8042.push_byte(i as u8).unwrap();
            assert_eq!(i8042.buf_len(), i + 1);
        }
        assert_eq!(i8042.push_byte(0).unwrap_err(), Error::InternalBufferFull);
    }

    #[test]
    fn test_i8042_kbd() {
        let mut i8042 = I8042Device::new(
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicBool::new(false)),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        );

        fn expect_key(i8042: &mut I8042Device, key: u16) {
            let mut data = [1];

            // The interrupt line should be on.
            i8042.trigger_kbd_interrupt().unwrap();
            assert!(i8042.kbd_interrupt_evt.read().unwrap() > 1);

            // The "data available" flag should be on.
            i8042.read(0, OFS_STATUS, &mut data);

            let mut key_byte: u8;
            if key & 0xFF00 != 0 {
                // For extended keys, we should be able to read the MSB first.
                key_byte = ((key & 0xFF00) >> 8) as u8;
                i8042.read(0, OFS_DATA, &mut data);
                assert_eq!(data[0], key_byte);

                // And then do the same for the LSB.

                // The interrupt line should be on.
                i8042.trigger_kbd_interrupt().unwrap();
                assert!(i8042.kbd_interrupt_evt.read().unwrap() > 1);
                // The "data available" flag should be on.
                i8042.read(0, OFS_STATUS, &mut data);
            }
            key_byte = (key & 0xFF) as u8;
            i8042.read(0, OFS_DATA, &mut data);
            assert_eq!(data[0], key_byte);
        }

        // Test key trigger.
        i8042.trigger_key(KEY_CTRL).unwrap();
        expect_key(&mut i8042, KEY_CTRL);

        // Test extended key trigger.
        i8042.trigger_key(KEY_DEL).unwrap();
        expect_key(&mut i8042, KEY_DEL);

        // Test CTRL+ALT+DEL trigger.
        i8042.trigger_ctrl_alt_del().unwrap();
        expect_key(&mut i8042, KEY_CTRL);
        expect_key(&mut i8042, KEY_ALT);
        expect_key(&mut i8042, KEY_DEL);

        // Almost fill up the buffer, so we can test trigger failures.
        for _i in 0..BUF_SIZE - 1 {
            i8042.push_byte(1).unwrap();
        }

        // Test extended key trigger failure.
        assert_eq!(i8042.buf_len(), BUF_SIZE - 1);
        assert_eq!(
            i8042.trigger_key(KEY_DEL).unwrap_err(),
            Error::InternalBufferFull
        );

        // Test ctrl+alt+del trigger failure.
        i8042.pop_byte().unwrap();
        i8042.pop_byte().unwrap();
        assert_eq!(i8042.buf_len(), BUF_SIZE - 3);
        assert_eq!(
            i8042.trigger_ctrl_alt_del().unwrap_err(),
            Error::InternalBufferFull
        );

        // Test kbd interrupt disable.
        let mut data = [1];
        data[0] = CMD_WRITE_CTR;
        i8042.write(0, OFS_STATUS, &data);
        data[0] = i8042.control & !CB_KBD_INT;
        i8042.write(0, OFS_DATA, &data);
        i8042.trigger_key(KEY_CTRL).unwrap();
        assert_eq!(
            i8042.trigger_kbd_interrupt().unwrap_err(),
            Error::KbdInterruptDisabled
        )
    }

    fn device() -> I8042Device {
        I8042Device::new(
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicBool::new(false)),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
    }

    /// Everything the guest can read from port 0x60 now.
    fn drain(i8042: &mut I8042Device) -> Vec<u8> {
        let mut out = Vec::new();
        let mut status = [0u8];
        loop {
            i8042.read(0, OFS_STATUS, &mut status);
            if status[0] & SB_OUT_DATA_AVAIL == 0 {
                return out;
            }
            let mut data = [0u8];
            i8042.read(0, OFS_DATA, &mut data);
            out.push(data[0]);
        }
    }

    #[test]
    fn answers_a_linux_keyboard_probe() {
        let mut i8042 = device();
        i8042.write(0, OFS_STATUS, &[CMD_SELF_TEST]);
        assert_eq!(drain(&mut i8042), [0x55]);
        i8042.write(0, OFS_STATUS, &[CMD_KBD_TEST]);
        assert_eq!(drain(&mut i8042), [0x00]);
        i8042.write(0, OFS_DATA, &[KBD_CMD_RESET]);
        assert_eq!(drain(&mut i8042), [KBD_ACK, KBD_SELF_TEST_OK]);
        i8042.write(0, OFS_DATA, &[KBD_CMD_GET_ID]);
        assert_eq!(drain(&mut i8042), [KBD_ACK, 0xAB, 0x83]);
        // A command with a parameter is acknowledged twice, and the parameter is not taken
        // for a command of its own.
        i8042.write(0, OFS_DATA, &[KBD_CMD_SET_LEDS]);
        assert_eq!(drain(&mut i8042), [KBD_ACK]);
        i8042.write(0, OFS_DATA, &[KBD_CMD_RESET]);
        assert_eq!(drain(&mut i8042), [KBD_ACK]);
        i8042.write(0, OFS_DATA, &[KBD_CMD_SCANCODE_SET]);
        assert_eq!(drain(&mut i8042), [KBD_ACK]);
        i8042.write(0, OFS_DATA, &[0]);
        assert_eq!(drain(&mut i8042), [KBD_ACK, KBD_SCANCODE_SET]);
        i8042.write(0, OFS_DATA, &[KBD_CMD_ECHO]);
        assert_eq!(drain(&mut i8042), [KBD_CMD_ECHO]);
    }

    #[test]
    fn writes_for_the_aux_port_never_reach_the_keyboard() {
        let mut i8042 = device();
        i8042.write(0, OFS_STATUS, &[CMD_WRITE_AUX]);
        i8042.write(0, OFS_DATA, &[KBD_CMD_DISABLE]);
        assert_eq!(drain(&mut i8042), [] as [u8; 0]);
        assert_eq!(i8042.type_scancodes(&[0x1c]), 1);
        assert_eq!(drain(&mut i8042), [0x1c], "the keyboard still scans");
        // Writing the keyboard's output buffer reads back as if typed.
        i8042.write(0, OFS_STATUS, &[CMD_WRITE_KBD_OUT]);
        i8042.write(0, OFS_DATA, &[0x5a]);
        assert_eq!(drain(&mut i8042), [0x5a]);
    }

    #[test]
    fn typed_scancodes_fill_the_buffer_and_raise_the_interrupt() {
        let mut i8042 = device();
        let codes: Vec<u8> = (1..=BUF_SIZE as u8 + 4).collect();
        assert_eq!(i8042.type_scancodes(&codes), BUF_SIZE);
        assert!(i8042.kbd_interrupt_evt.read().unwrap() >= 1);
        assert_eq!(drain(&mut i8042), codes[..BUF_SIZE]);
        assert_eq!(i8042.type_scancodes(&codes[BUF_SIZE..]), 4);
        assert_eq!(drain(&mut i8042), codes[BUF_SIZE..]);
    }

    #[test]
    fn a_disabled_keyboard_drops_typed_scancodes() {
        let mut i8042 = device();
        i8042.write(0, OFS_DATA, &[KBD_CMD_DISABLE]);
        drain(&mut i8042);
        assert_eq!(i8042.type_scancodes(&[0x1c, 0xf0, 0x1c]), 3);
        assert_eq!(drain(&mut i8042), [] as [u8; 0]);
        i8042.write(0, OFS_DATA, &[KBD_CMD_ENABLE]);
        drain(&mut i8042);
        i8042.write(0, OFS_STATUS, &[CMD_DISABLE_KBD]);
        assert_eq!(i8042.type_scancodes(&[0x1c]), 1);
        assert_eq!(drain(&mut i8042), [] as [u8; 0]);
        i8042.write(0, OFS_STATUS, &[CMD_ENABLE_KBD]);
        assert_eq!(i8042.type_scancodes(&[0x1c]), 1);
        assert_eq!(drain(&mut i8042), [0x1c]);
    }

    #[test]
    fn the_registers_survive_save_and_restore() {
        let device = || {
            I8042Device::new(
                EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
                Arc::new(AtomicBool::new(false)),
                EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            )
        };
        let mut i8042 = device();
        // The guest writes the control byte and the output port, as a driver's init does.
        i8042.write(0, OFS_STATUS, &[CMD_WRITE_CTR]);
        i8042.write(0, OFS_DATA, &[CB_KBD_INT | CB_POST_OK]);
        i8042.write(0, OFS_STATUS, &[CMD_WRITE_OUTP]);
        i8042.write(0, OFS_DATA, &[0x03]);
        let saved = i8042.save_state();
        assert_eq!((saved.control, saved.outp), (CB_KBD_INT | CB_POST_OK, 0x03));

        let mut back = device();
        back.restore_state(&saved);
        assert_eq!(back.save_state(), saved);
        let mut data = [0u8];
        back.write(0, OFS_STATUS, &[CMD_READ_CTR]);
        back.read(0, OFS_DATA, &mut data);
        assert_eq!(data[0], CB_KBD_INT | CB_POST_OK);
        back.write(0, OFS_STATUS, &[CMD_READ_OUTP]);
        back.read(0, OFS_DATA, &mut data);
        assert_eq!(data[0], 0x03);
    }
}
