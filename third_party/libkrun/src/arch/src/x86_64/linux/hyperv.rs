// Hyper-V enlightenments for a Windows guest (local patch, see VENDOR.md).
//
// KVM implements the Hyper-V paravirtual interface (hypercalls, the reference TSC page, the
// SynIC and its synthetic timers, TLB-flush and IPI hypercalls, VP index and runtime MSRs) and
// reports what it supports through `KVM_GET_SUPPORTED_HV_CPUID`. A guest sees it once those
// leaves sit at 0x40000000: KVM's own leaves (kvmclock and friends, which Windows ignores) move
// to 0x40000100, where a Linux guest still finds them. The SynIC needs its per-vCPU capability
// enabled; the guest crash MSRs are hidden, because KVM turns a write to them into a system event
// the VMM has no use for (pvpanic reports a bug check instead). So are the synthetic debugger and
// the extended hypercalls, whose exits KVM leaves to a VMM that implements neither.

use std::os::fd::AsRawFd;

use kvm_bindings::{CpuId, KVM_CAP_HYPERV_SYNIC2, KVM_MAX_CPUID_ENTRIES, kvm_cpuid_entry2};
use kvm_ioctls::VcpuFd;

/// `KVM_GET_SUPPORTED_HV_CPUID`: `_IOWR(KVMIO, 0xc1, struct kvm_cpuid2)`.
const KVM_GET_SUPPORTED_HV_CPUID: libc::c_ulong = 0xc008_aec1;

/// The hypervisor CPUID range Hyper-V and KVM both start at.
pub const HYPERVISOR_BASE: u32 = 0x4000_0000;
/// Where KVM's own leaves move when Hyper-V's take the base.
pub const KVM_RELOCATED_BASE: u32 = 0x4000_0100;

/// Hyper-V feature identification leaf: privileges in EAX and EBX, features in EDX.
pub const HV_FEATURES: u32 = 0x4000_0003;
/// EAX: the SynIC MSRs.
const HV_MSR_SYNIC_AVAILABLE: u32 = 1 << 2;
/// EAX: the synthetic timer MSRs (they need the SynIC).
const HV_MSR_SYNTIMER_AVAILABLE: u32 = 1 << 3;
/// EBX: the extended hypercalls, which KVM leaves to userspace.
pub const HV_ENABLE_EXTENDED_HYPERCALLS: u32 = 1 << 20;
/// EDX: the guest crash MSRs.
pub const HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE: u32 = 1 << 10;
/// EDX: the synthetic debugger MSRs, whose exits KVM leaves to userspace.
pub const HV_FEATURE_DEBUG_MSRS_AVAILABLE: u32 = 1 << 11;
/// EDX: synthetic timers in direct mode (they need the SynIC too).
const HV_STIMER_DIRECT_MODE_AVAILABLE: u32 = 1 << 19;
/// The synthetic debugger's leaves.
pub const HV_SYNDBG_LEAVES: std::ops::RangeInclusive<u32> = 0x4000_0080..=0x4000_0082;
/// The highest Hyper-V leaf below them (nested features).
const HV_MAX_LEAF_BELOW_SYNDBG: u32 = 0x4000_000a;

/// The status a hypercall the VMM does not implement returns.
pub const HV_STATUS_INVALID_HYPERCALL_CODE: u64 = 2;

#[derive(Debug)]
pub enum Error {
    /// `KVM_GET_SUPPORTED_HV_CPUID` failed: the host KVM has no Hyper-V emulation.
    SupportedHvCpuid(std::io::Error),
    /// Building the merged CPUID set failed.
    CpuId(vmm_sys_util::fam::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SupportedHvCpuid(e) => write!(f, "KVM_GET_SUPPORTED_HV_CPUID: {e}"),
            Error::CpuId(e) => write!(f, "building the Hyper-V CPUID set: {e:?}"),
        }
    }
}

/// The Hyper-V leaves KVM recommends for `vcpu`.
fn supported_hv_cpuid(vcpu: &VcpuFd) -> Result<Vec<kvm_cpuid_entry2>, Error> {
    let mut cpuid = CpuId::new(KVM_MAX_CPUID_ENTRIES).map_err(Error::CpuId)?;
    // The vCPU form, deprecated since 5.11 for the one on /dev/kvm, is the one older kernels
    // have too, and needs no other fd.
    // SAFETY: the ioctl writes at most `nent` entries into the wrapper's buffer, `nent` being
    // the capacity it was created with, and updates `nent` to the count written.
    let ret = unsafe {
        libc::ioctl(
            vcpu.as_raw_fd(),
            KVM_GET_SUPPORTED_HV_CPUID as _,
            cpuid.as_mut_fam_struct_ptr(),
        )
    };
    if ret < 0 {
        return Err(Error::SupportedHvCpuid(std::io::Error::last_os_error()));
    }
    Ok(cpuid.as_slice().to_vec())
}

/// `base` with KVM's hypervisor leaves moved up to [`KVM_RELOCATED_BASE`] and `hv` placed at
/// [`HYPERVISOR_BASE`]. The SynIC-dependent features stay only when `synic`; the crash MSRs,
/// the synthetic debugger and the extended hypercalls never do.
fn merge(base: &[kvm_cpuid_entry2], hv: &[kvm_cpuid_entry2], synic: bool) -> Vec<kvm_cpuid_entry2> {
    let mut merged: Vec<kvm_cpuid_entry2> = base
        .iter()
        .map(|entry| {
            let mut entry = *entry;
            if (HYPERVISOR_BASE..KVM_RELOCATED_BASE).contains(&entry.function) {
                entry.function += KVM_RELOCATED_BASE - HYPERVISOR_BASE;
                // The signature leaf names the highest leaf of its range.
                if entry.function == KVM_RELOCATED_BASE && entry.eax >= HYPERVISOR_BASE {
                    entry.eax += KVM_RELOCATED_BASE - HYPERVISOR_BASE;
                }
            }
            entry
        })
        .collect();
    for entry in hv
        .iter()
        .filter(|e| !HV_SYNDBG_LEAVES.contains(&e.function))
    {
        let mut entry = *entry;
        if entry.function == HYPERVISOR_BASE {
            entry.eax = entry.eax.min(HV_MAX_LEAF_BELOW_SYNDBG);
        }
        if entry.function == HV_FEATURES {
            if !synic {
                entry.eax &= !(HV_MSR_SYNIC_AVAILABLE | HV_MSR_SYNTIMER_AVAILABLE);
                entry.edx &= !HV_STIMER_DIRECT_MODE_AVAILABLE;
            }
            entry.ebx &= !HV_ENABLE_EXTENDED_HYPERCALLS;
            entry.edx &= !(HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE | HV_FEATURE_DEBUG_MSRS_AVAILABLE);
        }
        merged.push(entry);
    }
    merged
}

/// The Hyper-V MSRs a vCPU snapshot keeps, in the order a restore must write them: the guest
/// OS ID before the hypercall page (KVM drops the page's enable bit while no OS ID is set), the
/// reference TSC page, the vCPU's own pages, then the SynIC (its control before its pages and
/// interrupt sources) and the synthetic timers (configurations before counts). KVM lists only a
/// few of them in `KVM_GET_MSR_INDEX_LIST`; one this host's KVM does not implement is skipped
/// when the snapshot is taken. Read-only ones (`SVERSION`, `TIME_REF_COUNT`, frequencies) are
/// left out.
pub const SNAPSHOT_MSRS: &[u32] = &[
    0x4000_0000, // GUEST_OS_ID
    0x4000_0001, // HYPERCALL
    0x4000_0021, // REFERENCE_TSC
    0x4000_0002, // VP_INDEX
    0x4000_0010, // VP_RUNTIME
    0x4000_0073, // VP_ASSIST_PAGE
    0x4000_0106, // REENLIGHTENMENT_CONTROL
    0x4000_0107, // TSC_EMULATION_CONTROL
    0x4000_0108, // TSC_EMULATION_STATUS
    0x4000_0118, // TSC_INVARIANT_CONTROL
    0x4000_0080, // SCONTROL
    0x4000_0082, // SIEFP
    0x4000_0083, // SIMP
    0x4000_0090, // SINT0
    0x4000_0091,
    0x4000_0092,
    0x4000_0093,
    0x4000_0094,
    0x4000_0095,
    0x4000_0096,
    0x4000_0097,
    0x4000_0098,
    0x4000_0099,
    0x4000_009a,
    0x4000_009b,
    0x4000_009c,
    0x4000_009d,
    0x4000_009e,
    0x4000_009f, // SINT15
    0x4000_00b0, // STIMER0_CONFIG
    0x4000_00b2, // STIMER1_CONFIG
    0x4000_00b4, // STIMER2_CONFIG
    0x4000_00b6, // STIMER3_CONFIG
    0x4000_00b1, // STIMER0_COUNT
    0x4000_00b3, // STIMER1_COUNT
    0x4000_00b5, // STIMER2_COUNT
    0x4000_00b7, // STIMER3_COUNT
];

/// Present KVM's Hyper-V enlightenments in `cpuid`, the set about to be given to `vcpu`.
/// Returns whether the SynIC (and so the synthetic timers) is on: a host whose KVM refuses
/// it still gets the other enlightenments.
pub fn apply(vcpu: &VcpuFd, cpuid: &mut CpuId) -> Result<bool, Error> {
    let hv = supported_hv_cpuid(vcpu)?;
    let wants_synic = hv
        .iter()
        .any(|e| e.function == HV_FEATURES && e.eax & HV_MSR_SYNIC_AVAILABLE != 0);
    let synic = wants_synic && {
        let cap = kvm_bindings::kvm_enable_cap {
            cap: KVM_CAP_HYPERV_SYNIC2,
            ..Default::default()
        };
        vcpu.enable_cap(&cap).is_ok()
    };
    *cpuid = CpuId::from_entries(&merge(cpuid.as_slice(), &hv, synic)).map_err(Error::CpuId)?;
    Ok(synic)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(function: u32, eax: u32, edx: u32) -> kvm_cpuid_entry2 {
        kvm_cpuid_entry2 {
            function,
            eax,
            edx,
            ..Default::default()
        }
    }

    #[test]
    fn kvm_leaves_move_up_and_hyper_v_takes_the_base() {
        let base = [
            leaf(0x1, 0, 0),
            leaf(HYPERVISOR_BASE, 0x4000_0001, 0),
            leaf(0x4000_0001, 0x1234, 0),
        ];
        let hv = [
            leaf(HYPERVISOR_BASE, 0x4000_000a, 0),
            leaf(
                HV_FEATURES,
                HV_MSR_SYNIC_AVAILABLE | HV_MSR_SYNTIMER_AVAILABLE | 1,
                HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE | HV_STIMER_DIRECT_MODE_AVAILABLE,
            ),
        ];
        let merged = merge(&base, &hv, true);
        let find = |f: u32| merged.iter().find(|e| e.function == f).unwrap();
        assert_eq!(find(0x1).eax, 0);
        assert_eq!(
            find(KVM_RELOCATED_BASE).eax,
            0x4000_0101,
            "KVM's max leaf moved too"
        );
        assert_eq!(find(0x4000_0101).eax, 0x1234);
        assert_eq!(
            find(HYPERVISOR_BASE).eax,
            0x4000_000a,
            "Hyper-V's signature leaf"
        );
        let features = find(HV_FEATURES);
        assert_eq!(
            features.eax,
            HV_MSR_SYNIC_AVAILABLE | HV_MSR_SYNTIMER_AVAILABLE | 1
        );
        assert_eq!(
            features.edx, HV_STIMER_DIRECT_MODE_AVAILABLE,
            "crash MSRs hidden"
        );
        assert_eq!(
            merged
                .iter()
                .filter(|e| e.function == HYPERVISOR_BASE)
                .count(),
            1
        );
    }

    #[test]
    fn without_the_synic_its_timers_are_hidden() {
        let hv = [leaf(
            HV_FEATURES,
            HV_MSR_SYNIC_AVAILABLE | HV_MSR_SYNTIMER_AVAILABLE | 1,
            HV_STIMER_DIRECT_MODE_AVAILABLE,
        )];
        let merged = merge(&[], &hv, false);
        assert_eq!(merged[0].eax, 1);
        assert_eq!(merged[0].edx, 0);
    }

    #[test]
    fn the_synthetic_debugger_and_extended_hypercalls_are_hidden() {
        let mut features = leaf(HV_FEATURES, 0, HV_FEATURE_DEBUG_MSRS_AVAILABLE | 1);
        features.ebx = HV_ENABLE_EXTENDED_HYPERCALLS | 1;
        let hv = [
            leaf(HYPERVISOR_BASE, 0x4000_0082, 0),
            features,
            leaf(0x4000_000a, 0, 0),
            leaf(0x4000_0080, 0, 0),
            leaf(0x4000_0081, 0, 0),
            leaf(0x4000_0082, 0, 0),
        ];
        let merged = merge(&[], &hv, true);
        let functions: Vec<u32> = merged.iter().map(|e| e.function).collect();
        assert_eq!(functions, [HYPERVISOR_BASE, HV_FEATURES, 0x4000_000a]);
        assert_eq!(merged[0].eax, 0x4000_000a, "max leaf below the debugger's");
        assert_eq!(merged[1].ebx, 1);
        assert_eq!(merged[1].edx, 1);
    }
}
