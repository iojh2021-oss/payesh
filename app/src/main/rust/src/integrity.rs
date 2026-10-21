//! User-space tamper indicators. These are heuristics visible to an ordinary (non-root) app.
//! They can reveal a rooted / unlocked / hooked environment, but they can NOT see inside the kernel:
//! a kernel-level rootkit can hide from every user-space check, including these.
//! Output lines: "SEVERITY|CODE|detail"  (H = high, M = medium)
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;

#[cfg(target_os = "android")]
fn prop(name: &str) -> String {
    extern "C" {
        fn __system_property_get(name: *const c_char, value: *mut c_char) -> i32;
    }
    let c = match CString::new(name) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    let mut buf = [0 as c_char; 92];
    let n = unsafe { __system_property_get(c.as_ptr(), buf.as_mut_ptr()) };
    if n <= 0 {
        return String::new();
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
}

#[cfg(not(target_os = "android"))]
fn prop(_name: &str) -> String {
    let _ = (CString::new(""), unsafe { CStr::from_ptr(b"\0".as_ptr() as *const c_char) });
    String::new()
}

const SU_PATHS: &[&str] = &[
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su", "/vendor/bin/su",
    "/su/bin/su", "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su", "/system/app/Superuser.apk",
];
const MAGISK_PATHS: &[&str] = &["/sbin/.magisk", "/data/adb/magisk", "/data/adb/ksu", "/system/bin/magisk", "/debug_ramdisk/.magisk"];
const HOOK_NAMES: &[&str] = &["frida", "xposed", "lsposed", "zygisk", "substrate", "riru"];

pub fn probe() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if let Some(p) = SU_PATHS.iter().find(|p| Path::new(p).exists()) {
        out.push(format!("H|SU_BINARY|{}", p));
    }
    if let Some(p) = MAGISK_PATHS.iter().find(|p| Path::new(p).exists()) {
        out.push(format!("M|MAGISK|{}", p));
    }

    if prop("ro.secure") == "0" {
        out.push("H|INSECURE_BUILD|ro.secure=0".into());
    }
    if prop("ro.debuggable") == "1" {
        out.push("M|DEBUGGABLE_BUILD|ro.debuggable=1".into());
    }
    if prop("ro.build.tags").contains("test-keys") {
        out.push("M|TEST_KEYS|ro.build.tags".into());
    }
    let vb = prop("ro.boot.verifiedbootstate");
    if !vb.is_empty() && vb != "green" {
        out.push(format!("H|VERIFIED_BOOT|{}", vb));
    }
    if prop("ro.boot.flash.locked") == "0" || prop("ro.boot.vbmeta.device_state") == "unlocked" {
        out.push("M|BOOTLOADER_UNLOCKED|".into());
    }

    if let Ok(s) = std::fs::read_to_string("/sys/fs/selinux/enforce") {
        if s.trim() == "0" {
            out.push("H|SELINUX_PERMISSIVE|".into());
        }
    }

    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let low = maps.to_lowercase();
        if let Some(h) = HOOK_NAMES.iter().find(|h| low.contains(*h)) {
            out.push(format!("M|HOOK_LIBRARY|{}", h));
        }
    }
    if let Ok(mi) = std::fs::read_to_string("/proc/self/mountinfo") {
        if mi.to_lowercase().contains("magisk") {
            out.push("M|MAGISK_MOUNT|".into());
        }
    }
    out
}
