//! Analysis core: streaming SHA-256, case-insensitive multi-pattern matcher, byte entropy.
//! Reads untrusted data, so it is 100% safe Rust with no manual indexing on file contents.
use aho_corasick::AhoCorasick;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

pub fn hex(b: &[u8]) -> String {
    const HX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HX[(x >> 4) as usize] as char);
        s.push(HX[(x & 15) as usize] as char);
    }
    s
}

pub fn sha256_file(path: &str) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(hex(&h.finalize()))
}

/// Streaming scanner: feed chunks in order; matches that span chunk borders are still found.
pub struct Scanner {
    ac: Option<AhoCorasick>,
    ids: Vec<i32>,      // automaton pattern index -> index in the caller's array
    found: Vec<bool>,
    matches: Vec<i32>,
    carry: Vec<u8>,
    keep: usize,
    work: Vec<u8>,
    hist: [u64; 256],
    total: u64,
}

impl Scanner {
    pub fn new(pats: &[String]) -> Scanner {
        let mut lp: Vec<Vec<u8>> = Vec::new();
        let mut ids: Vec<i32> = Vec::new();
        for (i, p) in pats.iter().enumerate() {
            let b = p.as_bytes();
            if b.is_empty() || b.len() > 255 {
                continue;
            }
            lp.push(b.to_vec());
            ids.push(i as i32);
        }
        let keep = lp.iter().map(|p| p.len()).max().unwrap_or(1).saturating_sub(1);
        let ac = if lp.is_empty() {
            None
        } else {
            AhoCorasick::builder().ascii_case_insensitive(true).build(&lp).ok()
        };
        let found = vec![false; ids.len()];
        Scanner {
            ac,
            ids,
            found,
            matches: Vec::new(),
            carry: Vec::new(),
            keep,
            work: Vec::new(),
            hist: [0; 256],
            total: 0,
        }
    }

    pub fn feed(&mut self, d: &[u8]) {
        for &b in d {
            self.hist[b as usize] += 1;
        }
        self.total += d.len() as u64;
        if let Some(ac) = &self.ac {
            self.work.clear();
            self.work.extend_from_slice(&self.carry);
            self.work.extend_from_slice(d);
            for m in ac.find_overlapping_iter(&self.work[..]) {
                let pid = m.pattern().as_usize();
                if pid < self.found.len() && !self.found[pid] {
                    self.found[pid] = true;
                    self.matches.push(self.ids[pid]);
                }
            }
            let start = self.work.len().saturating_sub(self.keep);
            self.carry.clear();
            self.carry.extend_from_slice(&self.work[start..]);
        }
    }

    pub fn matches(&self) -> &[i32] {
        &self.matches
    }

    pub fn bytes(&self) -> u64 {
        self.total
    }

    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let mut e = 0.0;
        for &c in self.hist.iter() {
            if c == 0 {
                continue;
            }
            let p = c as f64 / self.total as f64;
            e -= p * p.log2();
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        let p = std::env::temp_dir().join("payeshav_sha_test.bin");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(
            sha256_file(p.to_str().unwrap()).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn scanner_finds_across_chunks_case_insensitive() {
        let mut s = Scanner::new(&["".to_string(), "Evil.Example".to_string(), "zzz".to_string()]);
        s.feed(b"aaaa EVIL.EXA");
        s.feed(b"MPLE bbbb");
        assert_eq!(s.matches(), &[1]);
        assert_eq!(s.bytes(), 22);
    }

    #[test]
    fn entropy_bounds() {
        let mut s = Scanner::new(&[]);
        s.feed(&[7u8; 1000]);
        assert!(s.entropy() < 0.01);
        let mut s2 = Scanner::new(&[]);
        let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        s2.feed(&all);
        assert!(s2.entropy() > 7.99);
    }
}
