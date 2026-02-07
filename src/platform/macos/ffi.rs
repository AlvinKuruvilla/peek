//! FFI bindings for XNU's `proc_pidfdinfo` with `PROC_PIDFDVNODEPATHINFO`.
//!
//! The [`libproc`] crate exposes `pidfdinfo` for socket FDs (`SocketFDInfo`)
//! but not for vnode FDs with path info. This module defines the minimal set
//! of `#[repr(C)]` structs needed to call
//! `proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO)` and extract the file
//! path. Struct layouts are taken from XNU's `<sys/proc_info.h>`.

use libc::{c_char, c_int, c_void, gid_t, off_t, uid_t};

/// Flavor constant for `proc_pidfdinfo` to request vnode path information.
const PROC_PIDFDVNODEPATHINFO: c_int = 2;

unsafe extern "C" {
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

/// Mirrors XNU's `struct vinfo_stat`.
#[repr(C)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: uid_t,
    vst_gid: gid_t,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: off_t,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

/// Mirrors XNU's `struct vnode_info`.
#[repr(C)]
struct VnodeInfo {
    vi_stat: VinfoStat,
    vi_type: c_int,
    vi_pad: c_int,
    vi_fsid: libc::fsid_t,
}

/// Mirrors XNU's `struct vnode_info_path`.
#[repr(C)]
struct VnodeInfoPath {
    vip_vi: VnodeInfo,
    /// Null-terminated filesystem path, up to 1024 bytes.
    vip_path: [c_char; 1024],
}

/// Mirrors XNU's `struct proc_fileinfo`.
#[repr(C)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: off_t,
    fi_type: i32,
    fi_guardflags: u32,
}

/// Mirrors XNU's `struct vnode_fdinfowithpath`.
///
/// Returned by `proc_pidfdinfo` when called with flavor
/// [`PROC_PIDFDVNODEPATHINFO`].
#[repr(C)]
struct VnodeFDInfoWithPath {
    pfi: ProcFileInfo,
    pvip: VnodeInfoPath,
}

/// Returns the filesystem path for a vnode (regular file) FD.
///
/// Uses a direct FFI call to `proc_pidfdinfo` with
/// `PROC_PIDFDVNODEPATHINFO` because the `libproc` crate does not expose
/// the [`VnodeFDInfoWithPath`] struct as a safe Rust type.
///
/// Returns `"-"` if the path cannot be resolved.
pub(super) fn vnode_detail(pid: i32, fd: i32) -> String {
    let mut info: VnodeFDInfoWithPath = unsafe { std::mem::zeroed() };
    let buffer_size = std::mem::size_of::<VnodeFDInfoWithPath>() as c_int;

    let ret = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDVNODEPATHINFO,
            &mut info as *mut _ as *mut c_void,
            buffer_size,
        )
    };

    if ret <= 0 {
        return "-".to_string();
    }

    // Extract the null-terminated path from the fixed-size `c_char` buffer.
    let path_bytes: Vec<u8> = info
        .pvip
        .vip_path
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();

    String::from_utf8(path_bytes).unwrap_or_else(|_| "-".to_string())
}
