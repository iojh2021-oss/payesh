//! Real-time file watcher on raw inotify (the same kernel facility FileObserver uses, without the
//! Java callback overhead). A single blocking `next()` call is driven by one Kotlin thread.
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

const IN_Q_OVERFLOW: u32 = 0x4000;
const IN_IGNORED: u32 = 0x8000;

pub struct Watch {
    ino: i32,
    ev: i32,
    map: Mutex<HashMap<i32, String>>,
}

impl Watch {
    pub fn new() -> Option<Watch> {
        unsafe {
            let ino = libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK);
            if ino < 0 {
                return None;
            }
            let ev = libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK);
            if ev < 0 {
                libc::close(ino);
                return None;
            }
            Some(Watch { ino, ev, map: Mutex::new(HashMap::new()) })
        }
    }

    /// Returns the watch descriptor, or a negative number on failure.
    pub fn add(&self, path: &str) -> i32 {
        let c = match CString::new(path) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        let mask = libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_CREATE;
        let wd = unsafe { libc::inotify_add_watch(self.ino, c.as_ptr(), mask) };
        if wd >= 0 {
            if let Ok(mut m) = self.map.lock() {
                m.insert(wd, path.to_string());
            }
        }
        wd
    }

    pub fn wake(&self) {
        let one: u64 = 1;
        unsafe {
            libc::write(self.ev, &one as *const u64 as *const libc::c_void, 8);
        }
    }

    /// `None` = woken up (stop). `Some(vec)` = zero or more events as "mask|/full/path".
    pub fn next(&self, timeout_ms: i32) -> Option<Vec<String>> {
        let mut fds = [
            libc::pollfd { fd: self.ino, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: self.ev, events: libc::POLLIN, revents: 0 },
        ];
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if r < 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                Some(Vec::new())
            } else {
                None
            };
        }
        if fds[1].revents != 0 {
            return None;
        }
        if fds[0].revents & libc::POLLIN == 0 {
            return Some(Vec::new());
        }
        let mut buf = [0u8; 16384];
        let n = unsafe { libc::read(self.ino, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            return Some(Vec::new());
        }
        let n = n as usize;
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 16 <= n {
            let wd = i32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            let mask = u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
            let len = u32::from_ne_bytes([buf[off + 12], buf[off + 13], buf[off + 14], buf[off + 15]]) as usize;
            let end = off + 16 + len;
            if end > n {
                break;
            }
            let raw = &buf[off + 16..end];
            let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let name = String::from_utf8_lossy(&raw[..nul]).into_owned();
            off = end;
            if mask & IN_Q_OVERFLOW != 0 {
                out.push(format!("{}|", IN_Q_OVERFLOW));
                continue;
            }
            if mask & IN_IGNORED != 0 {
                if let Ok(mut m) = self.map.lock() {
                    m.remove(&wd);
                }
                continue;
            }
            if name.is_empty() {
                continue;
            }
            let dir = self.map.lock().ok().and_then(|m| m.get(&wd).cloned());
            if let Some(d) = dir {
                out.push(format!("{}|{}/{}", mask, d, name));
            }
        }
        Some(out)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.ino);
            libc::close(self.ev);
        }
    }
}
