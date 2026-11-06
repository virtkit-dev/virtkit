// A VGA text console (local patch, see VENDOR.md): the colour VGA register file on I/O ports
// 0x3c0-0x3df, enough for Linux's vgacon to drive an 80x25 text screen, and a host-side handle
// that reads that screen back as text and types on the i8042 keyboard.
//
// The text itself is not emulated: vgacon writes character/attribute words straight into the
// 32 KiB at 0xb8000, which is ordinary guest RAM here (reserved in the e820 map). The registers
// only say where the visible page starts, where the cursor is and how big the screen is, which
// is all the host needs to read it back.

use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::bus::BusDevice;
use crate::legacy::I8042Device;

/// The first I/O port of the colour VGA register file (attribute controller).
pub const VGA_PORT_BASE: u16 = 0x3c0;
/// The register file spans 0x3c0-0x3df.
pub const VGA_PORT_LEN: u64 = 0x20;
/// Where colour text mode keeps its character/attribute words.
pub const VGA_TEXT_BASE: u64 = 0xb8000;
/// The text window: 32 KiB, as vgacon assumes for a VGA.
pub const VGA_TEXT_SIZE: usize = 0x8000;

// Offsets from VGA_PORT_BASE.
const OFS_ATT_W: u64 = 0x00;
const OFS_ATT_R: u64 = 0x01;
const OFS_MISC_W: u64 = 0x02; // write: misc output; read: input status 0
const OFS_SEQ_I: u64 = 0x04;
const OFS_SEQ_D: u64 = 0x05;
const OFS_PEL_MSK: u64 = 0x06;
const OFS_PEL_IR: u64 = 0x07; // write: DAC read index; read: DAC state
const OFS_PEL_IW: u64 = 0x08;
const OFS_PEL_D: u64 = 0x09;
const OFS_MISC_R: u64 = 0x0c;
const OFS_GFX_I: u64 = 0x0e;
const OFS_GFX_D: u64 = 0x0f;
const OFS_CRT_I: u64 = 0x14; // 0x3d4
const OFS_CRT_D: u64 = 0x15; // 0x3d5
const OFS_IS1: u64 = 0x1a; // 0x3da: read input status 1, write feature control

// CRTC registers vgacon and the screen read-back use.
const CRTC_H_DISP: usize = 0x01;
const CRTC_OVERFLOW: usize = 0x07;
const CRTC_MAX_SCAN: usize = 0x09;
const CRTC_CURSOR_START: usize = 0x0a;
const CRTC_START_HI: usize = 0x0c;
const CRTC_START_LO: usize = 0x0d;
const CRTC_CURSOR_HI: usize = 0x0e;
const CRTC_CURSOR_LO: usize = 0x0f;
const CRTC_V_DISP_END: usize = 0x12;
const CRTC_OFFSET: usize = 0x13;
/// Cursor Start bit 5: the cursor is off.
const CURSOR_DISABLE: u8 = 0x20;

/// The CRTC of BIOS mode 3 (80x25 colour text, 9x16 cells).
const MODE3_CRTC: [u8; 25] = [
    0x5f, 0x4f, 0x50, 0x82, 0x55, 0x81, 0xbf, 0x1f, 0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00,
    0x9c, 0x8e, 0x8f, 0x28, 0x1f, 0x96, 0xb9, 0xa3, 0xff,
];
const MODE3_SEQ: [u8; 5] = [0x03, 0x00, 0x03, 0x00, 0x02];
const MODE3_GFX: [u8; 9] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x00, 0xff];
const MODE3_ATT: [u8; 21] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x0c, 0x00, 0x0f, 0x08, 0x00,
];
/// Misc output of mode 3: colour I/O addresses (0x3dx), RAM enabled.
const MODE3_MISC: u8 = 0x67;

/// The largest screen read back, in cells per side: well past any text mode vgacon sets.
const MAX_COLS: usize = 256;
const MAX_ROWS: usize = 128;

struct Regs {
    crtc_index: u8,
    crtc: [u8; 25],
    seq_index: u8,
    seq: [u8; 5],
    gfx_index: u8,
    gfx: [u8; 9],
    att_index: u8,
    /// The attribute controller's flip-flop: the next write to 0x3c0 is data.
    att_data_next: bool,
    att: [u8; 21],
    misc: u8,
    pel_mask: u8,
    dac_read_index: u8,
    dac_write_index: u8,
    /// Which of red, green, blue the next DAC data access is.
    dac_component: u8,
    dac: [u8; 768],
    /// Input status 1 alternates, so a guest waiting for a retrace sees one.
    retrace: bool,
}

impl Regs {
    fn new() -> Regs {
        Regs {
            crtc_index: 0,
            crtc: MODE3_CRTC,
            seq_index: 0,
            seq: MODE3_SEQ,
            gfx_index: 0,
            gfx: MODE3_GFX,
            att_index: 0,
            att_data_next: false,
            att: MODE3_ATT,
            misc: MODE3_MISC,
            pel_mask: 0xff,
            dac_read_index: 0,
            dac_write_index: 0,
            dac_component: 0,
            dac: [0; 768],
            retrace: false,
        }
    }

    fn read(&mut self, offset: u64) -> u8 {
        match offset {
            OFS_ATT_W => self.att_index,
            OFS_ATT_R => self
                .att
                .get(usize::from(self.att_index & 0x1f))
                .copied()
                .unwrap_or(0),
            OFS_MISC_W => 0, // input status 0
            OFS_SEQ_I => self.seq_index,
            OFS_SEQ_D => self
                .seq
                .get(usize::from(self.seq_index))
                .copied()
                .unwrap_or(0),
            OFS_PEL_MSK => self.pel_mask,
            OFS_PEL_IR => 0, // DAC state: ready for writes
            OFS_PEL_IW => self.dac_write_index,
            OFS_PEL_D => {
                let at = usize::from(self.dac_read_index) * 3 + usize::from(self.dac_component);
                let value = self.dac.get(at).copied().unwrap_or(0);
                self.next_dac_component(true);
                value
            }
            OFS_MISC_R => self.misc,
            OFS_GFX_I => self.gfx_index,
            OFS_GFX_D => self
                .gfx
                .get(usize::from(self.gfx_index))
                .copied()
                .unwrap_or(0),
            OFS_CRT_I => self.crtc_index,
            OFS_CRT_D => self
                .crtc
                .get(usize::from(self.crtc_index))
                .copied()
                .unwrap_or(0),
            OFS_IS1 => {
                // Reading input status 1 resets the attribute flip-flop to "index".
                self.att_data_next = false;
                self.retrace = !self.retrace;
                // Bit 3: vertical retrace; bit 0: display disabled (either retrace).
                if self.retrace { 0x09 } else { 0x00 }
            }
            _ => 0xff,
        }
    }

    fn write(&mut self, offset: u64, value: u8) {
        match offset {
            OFS_ATT_W => {
                if self.att_data_next {
                    if let Some(r) = self.att.get_mut(usize::from(self.att_index & 0x1f)) {
                        *r = value;
                    }
                } else {
                    self.att_index = value;
                }
                self.att_data_next = !self.att_data_next;
            }
            OFS_MISC_W => self.misc = value,
            OFS_SEQ_I => self.seq_index = value,
            OFS_SEQ_D => {
                if let Some(r) = self.seq.get_mut(usize::from(self.seq_index)) {
                    *r = value;
                }
            }
            OFS_PEL_MSK => self.pel_mask = value,
            OFS_PEL_IR => {
                self.dac_read_index = value;
                self.dac_component = 0;
            }
            OFS_PEL_IW => {
                self.dac_write_index = value;
                self.dac_component = 0;
            }
            OFS_PEL_D => {
                let at = usize::from(self.dac_write_index) * 3 + usize::from(self.dac_component);
                if let Some(r) = self.dac.get_mut(at) {
                    *r = value & 0x3f;
                }
                self.next_dac_component(false);
            }
            OFS_GFX_I => self.gfx_index = value,
            OFS_GFX_D => {
                if let Some(r) = self.gfx.get_mut(usize::from(self.gfx_index)) {
                    *r = value;
                }
            }
            OFS_CRT_I => self.crtc_index = value,
            OFS_CRT_D => {
                if let Some(r) = self.crtc.get_mut(usize::from(self.crtc_index)) {
                    *r = value;
                }
            }
            _ => {}
        }
    }

    /// Step to the next DAC component, and to the next entry after blue.
    fn next_dac_component(&mut self, reading: bool) {
        self.dac_component += 1;
        if self.dac_component == 3 {
            self.dac_component = 0;
            if reading {
                self.dac_read_index = self.dac_read_index.wrapping_add(1);
            } else {
                self.dac_write_index = self.dac_write_index.wrapping_add(1);
            }
        }
    }

    fn crtc(&self, reg: usize) -> u8 {
        self.crtc.get(reg).copied().unwrap_or(0)
    }

    /// Columns, rows and row stride (in cells) the CRTC displays, clamped to what the text
    /// window and [`MAX_COLS`]/[`MAX_ROWS`] can hold.
    fn geometry(&self) -> (usize, usize, usize) {
        let cols = usize::from(self.crtc(CRTC_H_DISP)) + 1;
        let overflow = self.crtc(CRTC_OVERFLOW);
        let v_disp = usize::from(self.crtc(CRTC_V_DISP_END))
            | usize::from((overflow >> 1) & 1) << 8
            | usize::from((overflow >> 6) & 1) << 9;
        let cell_height = usize::from(self.crtc(CRTC_MAX_SCAN) & 0x1f) + 1;
        let rows = (v_disp + 1) / cell_height;
        // The offset register counts words of two cells (byte mode) per row.
        let stride = usize::from(self.crtc(CRTC_OFFSET)) * 2;
        let cols = cols.clamp(1, MAX_COLS);
        let rows = rows.clamp(1, MAX_ROWS);
        let stride = if stride < cols { cols } else { stride };
        let rows = rows.min(VGA_TEXT_SIZE / 2 / stride);
        (cols, rows.max(1), stride)
    }

    fn start(&self) -> usize {
        usize::from(self.crtc(CRTC_START_HI)) << 8 | usize::from(self.crtc(CRTC_START_LO))
    }

    fn cursor(&self) -> usize {
        usize::from(self.crtc(CRTC_CURSOR_HI)) << 8 | usize::from(self.crtc(CRTC_CURSOR_LO))
    }
}

/// One read of the text screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VgaScreen {
    pub cols: u16,
    pub rows: u16,
    /// `rows * cols` cells, row by row: the character (code page 437) in the low byte, the
    /// attribute (foreground in bits 0-3, background in bits 4-6, blink in bit 7) in the high.
    pub cells: Vec<u16>,
    /// The cursor's (column, row), or `None` when it is off or outside the screen.
    pub cursor: Option<(u16, u16)>,
}

/// What [`VgaConsole::type_scancodes`] can fail with.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyboardError {
    /// The VM is not built yet: no keyboard to type on.
    NotAttached,
}

/// The host's side of a VGA text console: shared by the I/O port device the guest drives and
/// the caller (vk) that reads the screen and types keys. Create it before the VM, hand it to
/// the builder, which attaches the guest's memory and keyboard when it builds the VM; a VM
/// rebuilt in place (a guest reset) attaches them again.
pub struct VgaConsole {
    regs: Mutex<Regs>,
    memory: Mutex<Option<GuestMemoryMmap>>,
    keyboard: Mutex<Option<Arc<Mutex<I8042Device>>>>,
}

impl VgaConsole {
    pub fn new() -> Arc<VgaConsole> {
        Arc::new(VgaConsole {
            regs: Mutex::new(Regs::new()),
            memory: Mutex::new(None),
            keyboard: Mutex::new(None),
        })
    }

    /// Point the console at a newly built VM, whose registers start in mode 3 again.
    pub fn attach(&self, memory: GuestMemoryMmap, keyboard: Arc<Mutex<I8042Device>>) {
        *lock(&self.regs) = Regs::new();
        *lock(&self.memory) = Some(memory);
        *lock(&self.keyboard) = Some(keyboard);
    }

    /// The I/O port device to put on the bus at [`VGA_PORT_BASE`].
    pub fn ports(self: &Arc<Self>) -> VgaPorts {
        VgaPorts(self.clone())
    }

    /// The screen as the guest shows it now; `None` before a VM is attached or when its memory
    /// cannot be read.
    pub fn screen(&self) -> Option<VgaScreen> {
        let (cols, rows, stride, start, cursor, cursor_on) = {
            let regs = lock(&self.regs);
            let (cols, rows, stride) = regs.geometry();
            let cursor_on = regs.crtc(CRTC_CURSOR_START) & CURSOR_DISABLE == 0;
            (cols, rows, stride, regs.start(), regs.cursor(), cursor_on)
        };
        let mut window = vec![0u8; VGA_TEXT_SIZE];
        {
            let memory = lock(&self.memory);
            memory
                .as_ref()?
                .read_slice(&mut window, GuestAddress(VGA_TEXT_BASE))
                .ok()?;
        }
        let words = VGA_TEXT_SIZE / 2;
        let mut cells = Vec::with_capacity(cols * rows);
        for row in 0..rows {
            for col in 0..cols {
                let word = (start + row * stride + col) % words;
                let lo = window.get(word * 2).copied().unwrap_or(0);
                let hi = window.get(word * 2 + 1).copied().unwrap_or(0);
                cells.push(u16::from_le_bytes([lo, hi]));
            }
        }
        let cursor = cursor
            .checked_sub(start)
            .filter(|_| cursor_on)
            .map(|at| (at % stride, at / stride))
            .filter(|&(col, row)| col < cols && row < rows)
            .and_then(|(col, row)| Some((u16::try_from(col).ok()?, u16::try_from(row).ok()?)));
        Some(VgaScreen {
            cols: u16::try_from(cols).ok()?,
            rows: u16::try_from(rows).ok()?,
            cells,
            cursor,
        })
    }

    /// Type scancodes (set 2, as the keyboard sends them untranslated) on the guest's keyboard.
    /// Returns how many were taken: the controller's buffer is small, so the caller retries the
    /// rest once the guest has read some. A keyboard the guest has disabled takes and drops them.
    pub fn type_scancodes(&self, codes: &[u8]) -> Result<usize, KeyboardError> {
        let keyboard = lock(&self.keyboard)
            .clone()
            .ok_or(KeyboardError::NotAttached)?;
        let taken = lock(&keyboard).type_scancodes(codes);
        Ok(taken)
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panic while holding one of these leaves plain register values behind: still usable.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The VGA register file on the I/O bus, backed by a [`VgaConsole`].
pub struct VgaPorts(Arc<VgaConsole>);

impl BusDevice for VgaPorts {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let mut regs = lock(&self.0.regs);
        for (i, b) in data.iter_mut().enumerate() {
            *b = regs.read(offset + i as u64);
        }
    }

    // A word access (vgacon's `outw` of an index and its value) is two byte accesses.
    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        let mut regs = lock(&self.0.regs);
        for (i, &b) in data.iter().enumerate() {
            regs.write(offset + i as u64, b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn console_with_memory() -> (Arc<VgaConsole>, GuestMemoryMmap) {
        let memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_0000)]).expect("guest memory");
        let console = VgaConsole::new();
        *lock(&console.memory) = Some(memory.clone());
        (console, memory)
    }

    fn put(memory: &GuestMemoryMmap, cell: usize, ch: u8, attr: u8) {
        memory
            .write_slice(&[ch, attr], GuestAddress(VGA_TEXT_BASE + cell as u64 * 2))
            .expect("write a cell");
    }

    fn crtc(ports: &mut VgaPorts, reg: u8, value: u8) {
        // vgacon's write_vga: index and value in one word access.
        ports.write(0, OFS_CRT_I, &[reg, value]);
    }

    #[test]
    fn reads_back_mode3_as_80x25_with_the_cursor() {
        let (console, memory) = console_with_memory();
        let mut ports = console.ports();
        put(&memory, 0, b'h', 0x07);
        put(&memory, 1, b'i', 0x1f);
        put(&memory, 80 * 24 + 79, b'z', 0x07);
        crtc(&mut ports, CRTC_CURSOR_HI as u8, 0);
        crtc(&mut ports, CRTC_CURSOR_LO as u8, 82);

        let screen = console.screen().expect("a screen");
        assert_eq!((screen.cols, screen.rows), (80, 25));
        assert_eq!(screen.cells.len(), 80 * 25);
        assert_eq!(screen.cells[0], 0x0700 | u16::from(b'h'));
        assert_eq!(screen.cells[1], 0x1f00 | u16::from(b'i'));
        assert_eq!(screen.cells[80 * 25 - 1], 0x0700 | u16::from(b'z'));
        assert_eq!(screen.cursor, Some((2, 1)));
    }

    #[test]
    fn follows_the_start_address_and_wraps_in_the_window() {
        let (console, memory) = console_with_memory();
        let mut ports = console.ports();
        // A visible page starting one row before the end of the window wraps to its start.
        let start = VGA_TEXT_SIZE / 2 - 80;
        crtc(&mut ports, CRTC_START_HI as u8, (start >> 8) as u8);
        crtc(&mut ports, CRTC_START_LO as u8, start as u8);
        put(&memory, start, b'a', 0x07);
        put(&memory, 0, b'b', 0x07);

        let screen = console.screen().expect("a screen");
        assert_eq!(screen.cells[0] & 0xff, u16::from(b'a'));
        assert_eq!(screen.cells[80] & 0xff, u16::from(b'b'));
    }

    #[test]
    fn hides_a_disabled_cursor() {
        let (console, _memory) = console_with_memory();
        let mut ports = console.ports();
        crtc(&mut ports, CRTC_CURSOR_START as u8, CURSOR_DISABLE | 0x0d);
        assert_eq!(console.screen().expect("a screen").cursor, None);
    }

    #[test]
    fn crtc_reads_back_what_was_written() {
        let (console, _memory) = console_with_memory();
        let mut ports = console.ports();
        ports.write(0, OFS_CRT_I, &[CRTC_CURSOR_START as u8]);
        let mut v = [0u8];
        ports.read(0, OFS_CRT_D, &mut v);
        assert_eq!(v[0], MODE3_CRTC[CRTC_CURSOR_START]);
        ports.write(0, OFS_CRT_D, &[0x2e]);
        ports.read(0, OFS_CRT_D, &mut v);
        assert_eq!(v[0], 0x2e);
        ports.read(0, OFS_MISC_R, &mut v);
        assert_eq!(v[0] & 1, 1, "colour I/O addresses");
    }

    #[test]
    fn attribute_flip_flop_resets_on_input_status_read() {
        let (console, _memory) = console_with_memory();
        let mut ports = console.ports();
        let mut v = [0u8];
        ports.read(0, OFS_IS1, &mut v);
        ports.write(0, OFS_ATT_W, &[0x01]); // index
        ports.write(0, OFS_ATT_W, &[0x3f]); // data
        ports.write(0, OFS_ATT_W, &[0x01]); // index again
        ports.read(0, OFS_ATT_R, &mut v);
        assert_eq!(v[0], 0x3f);
        ports.read(0, OFS_IS1, &mut v); // back to index
        ports.write(0, OFS_ATT_W, &[0x02]);
        ports.read(0, OFS_ATT_R, &mut v);
        assert_eq!(v[0], MODE3_ATT[2]);
    }

    #[test]
    fn a_narrower_offset_never_reads_rows_onto_each_other() {
        let (console, _memory) = console_with_memory();
        let mut ports = console.ports();
        crtc(&mut ports, CRTC_OFFSET as u8, 0x10); // 32 cells per row, narrower than 80
        let screen = console.screen().expect("a screen");
        assert_eq!(screen.cols, 80);
        assert_eq!(screen.cells.len(), 80 * usize::from(screen.rows));
    }

    #[test]
    fn no_screen_before_a_vm_is_attached() {
        assert_eq!(VgaConsole::new().screen(), None);
        assert_eq!(
            VgaConsole::new().type_scancodes(&[0x1c]),
            Err(KeyboardError::NotAttached)
        );
    }
}
