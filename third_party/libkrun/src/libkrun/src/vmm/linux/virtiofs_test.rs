//! Opt-in scheduling fault for the virtio-fs full-ring regression. Hardware breakpoints
//! observe the enqueue function and its return; no guest instructions are changed.

use kvm_bindings::{KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_HW_BP, kvm_guest_debug};
use kvm_ioctls::{Error, VcpuFd};
use vm_memory::GuestMemoryMmap;

pub(super) struct EnqueueProbe {
    entry: u64,
    returning: Option<u64>,
    memory: GuestMemoryMmap,
}

impl EnqueueProbe {
    pub(super) fn configure(fd: &VcpuFd, memory: &GuestMemoryMmap) -> Result<Option<Self>, Error> {
        let Some(value) = std::env::var_os("VK_TEST_VIRTIOFS_ENQUEUE_PC") else {
            return Ok(None);
        };
        let entry = value
            .to_str()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .filter(|pc| *pc >= 0xffff_8000_0000_0000)
            .ok_or_else(|| Error::new(libc::EINVAL))?;
        let probe = Self {
            entry,
            returning: None,
            memory: memory.clone(),
        };
        probe.arm(fd)?;
        Ok(Some(probe))
    }

    fn arm(&self, fd: &VcpuFd) -> Result<(), Error> {
        let mut debug = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP,
            ..Default::default()
        };
        debug.arch.debugreg[0] = self.entry;
        debug.arch.debugreg[7] = 0x401;
        if let Some(pc) = self.returning {
            debug.arch.debugreg[1] = pc;
            debug.arch.debugreg[7] |= 4;
        }
        fd.set_guest_debug(&debug)
    }

    pub(super) fn handle(&mut self, fd: &VcpuFd, pc: u64, cpu: u8) -> Result<(), Error> {
        let mut regs = fd.get_regs()?;
        if pc == self.entry {
            // These tests use a non-preemptible kernel. A nested enqueue on the same
            // vCPU would lose the return breakpoint; reject it instead of missing refusals.
            if self.returning.is_some() {
                return Err(Error::new(libc::EBUSY));
            }
            let sregs = fd.get_sregs()?;
            let mut bytes = [0; 8];
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = super::vstate::guest_linear_byte(
                    &self.memory,
                    sregs.cr3,
                    sregs.cr4,
                    sregs.efer,
                    regs.rsp + i as u64,
                )
                .ok_or_else(|| Error::new(libc::EFAULT))?;
            }
            self.returning = Some(u64::from_le_bytes(bytes));
        } else if self.returning == Some(pc) {
            self.returning = None;
            // int return value in EAX. At this point enqueue has released fsvq->lock;
            // the old caller has not yet put the refused request on queued_reqs.
            if regs.rax as u32 == (-libc::ENOSPC) as u32 {
                eprintln!("virtiofs-full-ring: ENOSPC cpu={cpu}; pause enqueue return 200ms");
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        } else {
            return Err(Error::new(libc::EINVAL));
        }
        self.arm(fd)?;
        // Resume through the execution breakpoint once, without altering the instruction.
        regs.rflags |= 1 << 16;
        fd.set_regs(&regs)
    }
}
