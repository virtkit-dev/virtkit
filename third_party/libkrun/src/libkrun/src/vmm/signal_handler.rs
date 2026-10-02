// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use libc::{_exit, SIGWINCH, c_int, c_void, siginfo_t};
use utils::signal::register_signal_handler;

static CONSOLE_SIGWINCH_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn sigwinch_handler(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) {
    // Safe because we're just reading some fields from a supposedly valid argument.
    let si_signo = unsafe { (*info).si_signo };

    // Sanity check. The condition should never be true.
    if num != si_signo || num != SIGWINCH {
        // Safe because we're terminating the process anyway.
        unsafe { _exit(i32::from(super::FC_EXIT_CODE_UNEXPECTED_ERROR)) };
    }

    let val: u64 = 1;
    let console_fd = CONSOLE_SIGWINCH_FD.load(Ordering::Relaxed);
    let _ = unsafe { libc::write(console_fd, &val as *const _ as *const c_void, 8) };
}

pub fn register_sigwinch_handler(console_fd: RawFd) -> utils::errno::Result<()> {
    CONSOLE_SIGWINCH_FD.store(console_fd, Ordering::Relaxed);

    register_signal_handler(SIGWINCH, sigwinch_handler)?;

    Ok(())
}
