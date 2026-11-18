//! Native system monitor: CPU / RAM / thermal / process / hardware readings taken straight from
//! /proc and /sys by user-space code (no root). Android restricts some of these files per version
//! and per vendor (for example /proc/stat is blocked for apps on newer releases), so every reader
//! degrades to "missing" instead of failing, and the snapshot says which source it really used.
//!
//! Output format is plain "key=value" lines so the Kotlin side only has to split strings.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn rd(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn clean(s: &str) -> String {
    s.chars().map(|c| if matches!(c, '|' | ';' | '=' | '\n' | '\r') { '_' } else { c }).collect()
}

// ------------------------------------------------------------------ parsers (unit-tested)

/// "MemTotal:       3921632 kB" -> 3921632
pub fn kv_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == key {
                return v.split_whitespace().next().and_then(|x| x.parse().ok());
            }
        }
    }
    None
}

pub fn cpuinfo_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == key {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct CpuTimes {
    pub total: u64,
    pub idle: u64,
}

#[derive(Clone, Debug, Default)]
pub struct StatSample {
    pub all: CpuTimes,
    pub cores: Vec<(usize, CpuTimes)>,
}

pub fn parse_stat(text: &str) -> Option<StatSample> {
    let mut all: Option<CpuTimes> = None;
    let mut cores: Vec<(usize, CpuTimes)> = Vec::new();
    for line in text.lines() {
        if !line.starts_with("cpu") {
            continue;
        }
        let mut it = line.split_whitespace();
        let name = match it.next() {
            Some(n) => n,
            None => continue,
        };
        let nums: Vec<u64> = it.take(8).filter_map(|x| x.parse::<u64>().ok()).collect();
        if nums.len() < 4 {
            continue;
        }
        let total: u64 = nums.iter().sum();
        let idle = nums[3] + nums.get(4).copied().unwrap_or(0);
        let t = CpuTimes { total, idle };
        if name == "cpu" {
            all = Some(t);
        } else if let Ok(i) = name[3..].parse::<usize>() {
            cores.push((i, t));
        }
    }
    cores.sort_by_key(|c| c.0);
    all.map(|a| StatSample { all: a, cores })
}

pub fn busy_pct(prev: CpuTimes, cur: CpuTimes) -> f64 {
    let dt = cur.total.saturating_sub(prev.total);
    if dt == 0 {
        return 0.0;
    }
    let di = cur.idle.saturating_sub(prev.idle);
    (dt.saturating_sub(di) as f64) * 100.0 / dt as f64
}

/// (comm, state, utime+stime ticks, threads) from /proc/<pid>/stat. The name may contain spaces
/// and parentheses, so it is delimited by the first '(' and the LAST ')'.
pub fn parse_proc_stat(s: &str) -> Option<(String, char, u64, u32)> {
    let l = s.find('(')?;
    let r = s.rfind(')')?;
    if r <= l {
        return None;
    }
    let name = s[l + 1..r].to_string();
    let rest: Vec<&str> = s[r + 1..].split_whitespace().collect();
    let state = rest.first()?.chars().next()?;
    let ut: u64 = rest.get(11)?.parse().ok()?;
    let st: u64 = rest.get(12)?.parse().ok()?;
    let th: u32 = rest.get(17).and_then(|x| x.parse().ok()).unwrap_or(1);
    Some((name, state, ut + st, th))
}

/// "4x1804000,4x2400000" – cores grouped by their maximum frequency (little/big clusters).
pub fn clusters(max_khz: &[u64]) -> String {
    let mut m: BTreeMap<u64, usize> = BTreeMap::new();
    for &f in max_khz.iter().filter(|&&f| f > 0) {
        *m.entry(f).or_insert(0) += 1;
    }
    m.iter().map(|(f, n)| format!("{}x{}", n, f)).collect::<Vec<_>>().join(",")
}

/// ARM Cortex part numbers (implementer 0x41 only).
pub fn arm_core_name(part: &str) -> Option<&'static str> {
    Some(match part.to_ascii_lowercase().as_str() {
        "0xd03" => "Cortex-A53", "0xd04" => "Cortex-A35", "0xd05" => "Cortex-A55",
        "0xd07" => "Cortex-A57", "0xd08" => "Cortex-A72", "0xd09" => "Cortex-A73",
        "0xd0a" => "Cortex-A75", "0xd0b" => "Cortex-A76", "0xd0c" => "Neoverse-N1",
        "0xd0d" => "Cortex-A77", "0xd41" => "Cortex-A78", "0xd44" => "Cortex-X1",
        "0xd46" => "Cortex-A510", "0xd47" => "Cortex-A710", "0xd48" => "Cortex-X2",
        "0xd4a" => "Neoverse-E1", "0xd4b" => "Cortex-A78C", "0xd4d" => "Cortex-A715",
        "0xd4e" => "Cortex-X3", "0xd80" => "Cortex-A520", "0xd81" => "Cortex-A720",
        "0xd82" => "Cortex-X4", "0xd84" => "Neoverse-V3", "0xd85" => "Cortex-X925",
        "0xd87" => "Cortex-A725",
        _ => return None,
    })
}

// ------------------------------------------------------------------ live sampling

static PREV_STAT: Mutex<Option<StatSample>> = Mutex::new(None);
static PREV_SELF: Mutex<Option<(u64, Instant)>> = Mutex::new(None);

fn clk_tck() -> f64 {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as f64 } else { 100.0 }
}

fn read_stat() -> Option<StatSample> {
    fs::read_to_string("/proc/stat").ok().and_then(|t| parse_stat(&t))
}

fn cpu_indices() -> Vec<usize> {
    let mut v: Vec<usize> = Vec::new();
    if let Ok(rd) = fs::read_dir("/sys/devices/system/cpu") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if let Some(d) = n.strip_prefix("cpu") {
                if let Ok(i) = d.parse::<usize>() {
                    v.push(i);
                }
            }
        }
    }
    v.sort_unstable();
    v
}

fn num_file(path: &str) -> u64 {
    rd(path).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0)
}

/// Whole-device snapshot, "key=value" per line.
pub fn snapshot() -> String {
    let mut o = String::new();

    // ---- memory
    if let Some(m) = rd("/proc/meminfo") {
        for (key, label) in [
            ("MemTotal", "mem_total_kb"), ("MemAvailable", "mem_avail_kb"), ("MemFree", "mem_free_kb"),
            ("Buffers", "buffers_kb"), ("Cached", "cached_kb"), ("SwapTotal", "swap_total_kb"),
            ("SwapFree", "swap_free_kb"), ("Active", "active_kb"), ("Inactive", "inactive_kb"),
            ("Shmem", "shmem_kb"), ("Dirty", "dirty_kb"),
        ] {
            if let Some(v) = kv_kb(&m, key) {
                let _ = writeln!(o, "{}={}", label, v);
            }
        }
    }

    // ---- per-core frequency data (also the fallback load estimate)
    let idx = cpu_indices();
    let mut cur_f: Vec<(usize, u64)> = Vec::new();
    let mut max_f: Vec<u64> = Vec::new();
    let mut online: Vec<(usize, bool)> = Vec::new();
    let mut min_f: u64 = 0;
    let mut gov = String::new();
    for &i in &idx {
        let base = format!("/sys/devices/system/cpu/cpu{}", i);
        let on = if i == 0 { true } else { rd(&format!("{}/online", base)).map(|s| s == "1").unwrap_or(true) };
        online.push((i, on));
        let cur = num_file(&format!("{}/cpufreq/scaling_cur_freq", base));
        let mut mx = num_file(&format!("{}/cpufreq/cpuinfo_max_freq", base));
        if mx == 0 {
            mx = num_file(&format!("{}/cpufreq/scaling_max_freq", base));
        }
        cur_f.push((i, cur));
        max_f.push(mx);
        if min_f == 0 {
            min_f = num_file(&format!("{}/cpufreq/cpuinfo_min_freq", base));
        }
        if gov.is_empty() {
            gov = rd(&format!("{}/cpufreq/scaling_governor", base)).unwrap_or_default();
        }
    }
    let _ = writeln!(o, "cores={}", idx.len());
    if !idx.is_empty() {
        let j = |f: &dyn Fn(usize) -> String| (0..idx.len()).map(|n| f(n)).collect::<Vec<_>>().join(",");
        let _ = writeln!(o, "core_online={}", j(&|n: usize| format!("{}:{}", idx[n], if online[n].1 { 1 } else { 0 })));
        let _ = writeln!(o, "core_freq={}", j(&|n: usize| format!("{}:{}", idx[n], cur_f[n].1)));
        let _ = writeln!(o, "core_max={}", j(&|n: usize| format!("{}:{}", idx[n], max_f[n])));
        let _ = writeln!(o, "clusters={}", clusters(&max_f));
    }
    if min_f > 0 {
        let _ = writeln!(o, "freq_min={}", min_f);
    }
    if !gov.is_empty() {
        let _ = writeln!(o, "governor={}", clean(&gov));
    }

    // ---- CPU load: real /proc/stat deltas when readable, else a frequency-based estimate
    let cur = read_stat();
    let mut src = "none";
    let mut total_pct = 0.0f64;
    let mut core_pct: Vec<(usize, f64)> = Vec::new();
    if let Some(c) = cur {
        let prev = {
            let g = PREV_STAT.lock().unwrap_or_else(|e| e.into_inner());
            g.clone()
        };
        let (p, c2) = match prev {
            Some(p) => (p, c),
            None => {
                // first call: take a short second sample so the UI gets numbers immediately
                std::thread::sleep(Duration::from_millis(150));
                (c, read_stat().unwrap_or_default())
            }
        };
        total_pct = busy_pct(p.all, c2.all);
        for (i, t) in &c2.cores {
            if let Some((_, pt)) = p.cores.iter().find(|(pi, _)| pi == i) {
                core_pct.push((*i, busy_pct(*pt, *t)));
            }
        }
        src = "stat";
        let mut g = PREV_STAT.lock().unwrap_or_else(|e| e.into_inner());
        *g = Some(c2);
    } else if !idx.is_empty() && max_f.iter().any(|&m| m > 0) {
        let mut sum = 0.0;
        let mut n = 0.0;
        for (k, &(i, f)) in cur_f.iter().enumerate() {
            let m = max_f[k];
            if m > 0 {
                let pct = if online[k].1 { (f as f64 * 100.0 / m as f64).min(100.0) } else { 0.0 };
                core_pct.push((i, pct));
                sum += pct;
                n += 1.0;
            }
        }
        if n > 0.0 {
            total_pct = sum / n;
            src = "freq";
        }
    }
    let _ = writeln!(o, "cpu_src={}", src);
    let _ = writeln!(o, "cpu_total={:.1}", total_pct);
    if !core_pct.is_empty() {
        let _ = writeln!(
            o, "core_pct={}",
            core_pct.iter().map(|(i, p)| format!("{}:{:.1}", i, p)).collect::<Vec<_>>().join(",")
        );
    }

    // ---- uptime / load average
    if let Some(u) = rd("/proc/uptime") {
        let mut it = u.split_whitespace();
        if let Some(up) = it.next().and_then(|x| x.parse::<f64>().ok()) {
            let _ = writeln!(o, "uptime_s={}", up as u64);
        }
    }
    if let Some(l) = rd("/proc/loadavg") {
        let v: Vec<&str> = l.split_whitespace().take(3).collect();
        if v.len() == 3 {
            let _ = writeln!(o, "loadavg={}", v.join(","));
        }
    }

    // ---- thermal zones
    let mut temps: Vec<String> = Vec::new();
    for i in 0..48 {
        let base = format!("/sys/class/thermal/thermal_zone{}", i);
        let ty = match rd(&format!("{}/type", base)) {
            Some(t) => t,
            None => continue,
        };
        let raw = match rd(&format!("{}/temp", base)).and_then(|s| s.parse::<i64>().ok()) {
            Some(r) => r,
            None => continue,
        };
        let c = if raw.abs() >= 1000 { raw as f64 / 1000.0 } else { raw as f64 };
        if c > 0.0 && c < 150.0 {
            temps.push(format!("{}:{:.1}", clean(&ty), c));
        }
    }
    if !temps.is_empty() {
        let _ = writeln!(o, "temps={}", temps.join(";"));
    }

    // ---- this process
    if let Some(st) = rd("/proc/self/status") {
        if let Some(v) = kv_kb(&st, "VmRSS") {
            let _ = writeln!(o, "self_rss_kb={}", v);
        }
    }
    if let Some(s) = rd("/proc/self/stat") {
        if let Some((_, _, ticks, th)) = parse_proc_stat(&s) {
            let _ = writeln!(o, "self_threads={}", th);
            let now = Instant::now();
            let mut g = PREV_SELF.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((pt, pi)) = *g {
                let dt = now.duration_since(pi).as_secs_f64();
                if dt > 0.2 {
                    let pct = (ticks.saturating_sub(pt) as f64 / clk_tck()) / dt * 100.0;
                    let _ = writeln!(o, "self_cpu={:.1}", pct);
                    *g = Some((ticks, now));
                }
            } else {
                *g = Some((ticks, now));
            }
        }
    }
    o
}

/// Static hardware facts (read once by the UI).
pub fn info() -> String {
    let mut o = String::new();
    if let Some(k) = rd("/proc/version") {
        let _ = writeln!(o, "kernel={}", clean(&k.chars().take(180).collect::<String>()));
    }
    let _ = writeln!(o, "arch={}", std::env::consts::ARCH);
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps > 0 {
        let _ = writeln!(o, "page_size={}", ps);
    }
    if let Some(ci) = fs::read_to_string("/proc/cpuinfo").ok() {
        for (key, label) in [("Hardware", "hardware"), ("model name", "cpu_model"), ("Processor", "cpu_proc")] {
            if let Some(v) = cpuinfo_value(&ci, key) {
                let _ = writeln!(o, "{}={}", label, clean(&v));
            }
        }
        let implementer = cpuinfo_value(&ci, "CPU implementer").unwrap_or_default();
        let mut parts: BTreeMap<String, usize> = BTreeMap::new();
        for line in ci.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim() == "CPU part" {
                    *parts.entry(v.trim().to_string()).or_insert(0) += 1;
                }
            }
        }
        if !parts.is_empty() {
            let txt = parts
                .iter()
                .map(|(p, n)| {
                    let name = if implementer.eq_ignore_ascii_case("0x41") {
                        arm_core_name(p).unwrap_or(p.as_str()).to_string()
                    } else {
                        p.clone()
                    };
                    format!("{}x {}", n, clean(&name))
                })
                .collect::<Vec<_>>()
                .join(" + ");
            let _ = writeln!(o, "core_names={}", txt);
        }
        if let Some(f) = cpuinfo_value(&ci, "Features") {
            let _ = writeln!(o, "features={}", clean(&f));
        }
    }
    o
}

/// Visible processes ("P|pid|name|state|threads|rss_kb|ticks|uid") followed by the threads of this
/// very process ("T|tid|name|state|ticks"). Since Android 7 a normal app only sees its own
/// processes in /proc, so the first part is usually short; the thread list is always complete.
pub fn processes() -> Vec<String> {
    let mut procs: Vec<(u64, String)> = Vec::new();
    if let Ok(rdir) = fs::read_dir("/proc") {
        for e in rdir.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let base = format!("/proc/{}", name);
            let stat = match rd(&format!("{}/stat", base)) {
                Some(s) => s,
                None => continue,
            };
            let (comm, state, ticks, th) = match parse_proc_stat(&stat) {
                Some(x) => x,
                None => continue,
            };
            let status = rd(&format!("{}/status", base)).unwrap_or_default();
            let rss = kv_kb(&status, "VmRSS").unwrap_or(0);
            let uid = status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|s| s.to_string()))
                .unwrap_or_else(|| "0".to_string());
            let cmd = fs::read(format!("{}/cmdline", base))
                .ok()
                .map(|b| String::from_utf8_lossy(b.split(|&c| c == 0).next().unwrap_or(&[])).into_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or(comm);
            procs.push((ticks, format!("P|{}|{}|{}|{}|{}|{}|{}", name, clean(&cmd), state, th, rss, ticks, uid)));
        }
    }
    procs.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out: Vec<String> = procs.into_iter().take(40).map(|p| p.1).collect();

    let mut threads: Vec<(u64, String)> = Vec::new();
    if let Ok(rdir) = fs::read_dir("/proc/self/task") {
        for e in rdir.flatten() {
            let tid = e.file_name().to_string_lossy().to_string();
            if let Some(s) = rd(&format!("/proc/self/task/{}/stat", tid)) {
                if let Some((comm, state, ticks, _)) = parse_proc_stat(&s) {
                    threads.push((ticks, format!("T|{}|{}|{}|{}", tid, clean(&comm), state, ticks)));
                }
            }
        }
    }
    threads.sort_by(|a, b| b.0.cmp(&a.0));
    out.extend(threads.into_iter().take(30).map(|t| t.1));
    out
}

/// [total, free, available] bytes of the filesystem holding `path` (statvfs).
pub fn storage(path: &str) -> Vec<i64> {
    let c = match std::ffi::CString::new(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if r != 0 {
        return vec![];
    }
    let bs = st.f_frsize as u64;
    let bs = if bs == 0 { st.f_bsize as u64 } else { bs };
    vec![
        (st.f_blocks as u64).saturating_mul(bs) as i64,
        (st.f_bfree as u64).saturating_mul(bs) as i64,
        (st.f_bavail as u64).saturating_mul(bs) as i64,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_values() {
        let t = "MemTotal:        3921632 kB\nMemFree:          123456 kB\nMemAvailable:    1800000 kB\n";
        assert_eq!(kv_kb(t, "MemTotal"), Some(3921632));
        assert_eq!(kv_kb(t, "MemAvailable"), Some(1800000));
        assert_eq!(kv_kb(t, "Nope"), None);
    }

    #[test]
    fn stat_and_percent() {
        let a = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0 0 0\nintr 1\n";
        let b = "cpu  200 0 200 900 0 0 0 0 0 0\ncpu0 100 0 100 400 0 0 0 0 0 0\ncpu1 100 0 100 500 0 0 0 0 0 0\n";
        let (sa, sb) = (parse_stat(a).unwrap(), parse_stat(b).unwrap());
        assert_eq!(sa.cores.len(), 2);
        assert!((busy_pct(sa.all, sb.all) - 200.0 * 100.0 / 300.0).abs() < 1e-9);
        assert!((busy_pct(sa.cores[0].1, sb.cores[0].1) - 100.0).abs() < 1e-9);
        assert!((busy_pct(sa.cores[1].1, sb.cores[1].1) - 50.0).abs() < 1e-9);
        assert_eq!(busy_pct(sa.all, sa.all), 0.0);
    }

    #[test]
    fn stat_missing_is_none() {
        assert!(parse_stat("").is_none());
        assert!(parse_stat("intr 1 2 3\n").is_none());
    }

    #[test]
    fn proc_stat_with_odd_name() {
        let s = "1234 (my app (x)) S 1 1 1 0 -1 4194560 100 0 0 0 50 25 0 0 20 0 7 0 99";
        let (n, st, ticks, th) = parse_proc_stat(s).unwrap();
        assert_eq!(n, "my app (x)");
        assert_eq!(st, 'S');
        assert_eq!(ticks, 75);
        assert_eq!(th, 7);
        assert!(parse_proc_stat("garbage").is_none());
    }

    #[test]
    fn cluster_grouping() {
        assert_eq!(clusters(&[1804000, 1804000, 2400000, 0]), "2x1804000,1x2400000");
        assert_eq!(clusters(&[]), "");
    }

    #[test]
    fn arm_names() {
        assert_eq!(arm_core_name("0xd05"), Some("Cortex-A55"));
        assert_eq!(arm_core_name("0xD0B"), Some("Cortex-A76"));
        assert_eq!(arm_core_name("0x999"), None);
    }

    #[test]
    fn cpuinfo_lookup() {
        let t = "processor\t: 0\nHardware\t: Qualcomm Technologies, Inc SM8250\nFeatures\t: fp asimd\n";
        assert_eq!(cpuinfo_value(t, "Hardware").as_deref(), Some("Qualcomm Technologies, Inc SM8250"));
        assert_eq!(cpuinfo_value(t, "Features").as_deref(), Some("fp asimd"));
        assert_eq!(cpuinfo_value(t, "x"), None);
    }

    #[test]
    fn snapshot_has_core_keys_on_linux() {
        let s = snapshot();
        assert!(s.contains("cpu_src="));
        assert!(s.contains("cpu_total="));
        assert!(!s.contains('\r'));
    }

    #[test]
    fn storage_of_root() {
        let v = storage("/");
        if !v.is_empty() {
            assert!(v[0] > 0 && v[1] <= v[0]);
        }
        assert!(storage("/definitely/not/here").is_empty());
    }
}
