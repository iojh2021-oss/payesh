package app.payesh

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlin.math.ln

/** What the inspector learned about one destination (ip:port). The payload itself is never stored. */
class Probe {
    @Volatile var svc: String? = null      // detected protocol: "TLS", "SSH", "DNS", "QUIC v1", "HTTP" ...
    @Volatile var enc = 0                  // 0 unknown, 1 encrypted, 2 cleartext, 3 high-entropy (encrypted/compressed, type unknown)
    @Volatile var tlsOffered = 0           // highest TLS version the client offered
    @Volatile var tlsViaExt = false
    @Volatile var tlsChosen = 0            // version the server chose
    @Volatile var cipher = 0               // cipher suite the server chose
    @Volatile var alpn: String? = null
    @Volatile var ech = false              // Encrypted Client Hello: the site name is hidden
    @Volatile var pq = false               // post-quantum key share offered
    @Volatile var weakOffer = false        // client also offered RC4 / DES / 3DES / NULL ciphers
    @Volatile var apk = false              // plain-HTTP response that looks like an APK download
    @Volatile var entropy = -1f
    @Volatile var sUp = 0
    @Volatile var sDown = 0
}

class ScanFinding(
    val key: String, val uid: Int, val app: String, val pkg: String?, val proto: String,
    val ip: String, val port: Int, val host: String?, val service: String, val crypto: String,
    val enc: Int, val level: Int, val notes: List<String>, val up: Long, val down: Long,
    val bg: Boolean, val sampled: Boolean
)

class ScanReport(
    val time: Long, val total: Int, val encrypted: Int, val plain: Int, val unknown: Int,
    val bgApps: Int, val bgKnown: Boolean, val sampled: Int, val items: List<ScanFinding>,
    val learning: Int = 0
)

/**
 * Network Inspector. While ON, the VPN service hands the first bytes of each connection (<= 1500 bytes, first two
 * packets per direction) to [feed]. They are analysed in memory and thrown away: only the protocol name, the kind of
 * encryption and handshake metadata (TLS version, ALPN, chosen cipher...) are kept. The content of encrypted traffic is
 * never decrypted. Nothing is sent anywhere.
 */
object NetScan {
    @Volatile var on = false
    val report = MutableStateFlow<ScanReport?>(null)

    private const val PREF = "net_scan"
    private var inited = false
    private val lock = Any()
    private val notified = HashSet<String>()
    private val labels = HashMap<Int, Pair<String, String?>>()
    private var fg: Set<String>? = null
    private var fgAt = 0L

    fun init(ctx: Context) {
        if (inited) return
        inited = true
        on = ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE).getBoolean("on", false)
    }

    fun setOn(ctx: Context, v: Boolean) {
        init(ctx)
        on = v
        ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit().putBoolean("on", v).apply()
        if (!v) {
            for (u in Tracker.uids.values) for (c in u.conns.values) c.probe = null
            synchronized(lock) { notified.clear(); saveBase(ctx, true) }
            report.value = null
        }
    }

    // ------------------------------------------------------------------ tables

    private val RESOLVERS = mapOf(
        "1.1.1.1" to "Cloudflare", "1.0.0.1" to "Cloudflare", "8.8.8.8" to "Google", "8.8.4.4" to "Google",
        "9.9.9.9" to "Quad9", "149.112.112.112" to "Quad9", "208.67.222.222" to "OpenDNS", "208.67.220.220" to "OpenDNS",
        "94.140.14.14" to "AdGuard", "94.140.15.15" to "AdGuard", "185.228.168.9" to "CleanBrowsing", "76.76.2.0" to "Control D",
        "45.90.28.0" to "NextDNS", "45.90.30.0" to "NextDNS", "178.22.122.100" to "Shecan", "185.51.200.2" to "Shecan"
    )
    private val DOH_HOSTS = listOf(
        "dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "dns.nextdns.io", "doh.opendns.com",
        "dns.adguard.com", "dns.adguard-dns.com", "doh.cleanbrowsing.org", "doh.dns.sb"
    )

    /** Well-known service of a port (what it is NORMALLY used for; an app can use any port for anything). */
    private fun portSvc(proto: String, port: Int): String? {
        if (proto == "UDP") when (port) {
            53 -> return "DNS"; 67, 68 -> return "DHCP"; 123 -> return "NTP (زمان)"; 443 -> return "QUIC / HTTP3"
            500, 4500 -> return "IPsec"; 853 -> return "DNS روی QUIC"; 1194 -> return "OpenVPN"; 1900 -> return "SSDP / UPnP"
            5353 -> return "mDNS"; 51820 -> return "WireGuard"
        }
        when (port) {
            20, 21 -> return "FTP"; 22 -> return "SSH"; 23 -> return "Telnet"; 25 -> return "SMTP"; 53 -> return "DNS (TCP)"
            80 -> return "HTTP"; 110 -> return "POP3"; 143 -> return "IMAP"; 443 -> return "HTTPS"; 445 -> return "SMB"
            465 -> return "SMTPS"; 587 -> return "SMTP (ارسال ایمیل)"; 853 -> return "DNS روی TLS"; 993 -> return "IMAPS"
            995 -> return "POP3S"; 1080 -> return "SOCKS proxy"; 1883 -> return "MQTT"; 3128 -> return "HTTP proxy"
            3389 -> return "RDP"; 4444 -> return "پورت پیش‌فرض بک‌دور/Metasploit"; 5222 -> return "XMPP"
            5228, 5229, 5230 -> return "Google Play / FCM"; 5555 -> return "ADB"; 5900 -> return "VNC"; 6667 -> return "IRC"
            6697 -> return "IRC-TLS"; 8080, 8000, 8008, 8888 -> return "HTTP (پورت جایگزین)"; 8443 -> return "HTTPS (پورت جایگزین)"
            8883 -> return "MQTT-TLS"; 9001, 9030 -> return "Tor"; 9050, 9150 -> return "Tor SOCKS"; 31337 -> return "پورت کلاسیک بک‌دور"
        }
        if (port in 6881..6889) return "BitTorrent"
        if (port in 3478..3481 || port in 19302..19309) return "STUN/TURN (تماس و ویدیو)"
        return null
    }

    private fun isLocal(ip: String): Boolean {
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") || ip.startsWith("169.254.")) return true
        if (ip.startsWith("172.")) { val s = ip.split('.').getOrNull(1)?.toIntOrNull() ?: 0; if (s in 16..31) return true }
        val f = ip.substringBefore('.').toIntOrNull() ?: return ip.contains(':') // IPv6 literal
        return f >= 224
    }

    // ------------------------------------------------------------------ byte helpers

    private fun u8(b: ByteArray, o: Int) = b[o].toInt() and 0xff
    private fun u16(b: ByteArray, o: Int) = (u8(b, o) shl 8) or u8(b, o + 1)
    private fun u32(b: ByteArray, o: Int): Long = (u16(b, o).toLong() shl 16) or u16(b, o + 2).toLong()
    private fun starts(b: ByteArray, s: String): Boolean {
        if (b.size < s.length) return false
        for (i in s.indices) if (b[i].toInt() != s[i].code) return false
        return true
    }
    private fun head(b: ByteArray, n: Int) = String(b, 0, minOf(b.size, n), Charsets.ISO_8859_1)
    private fun grease(v: Int) = (v and 0x0f0f) == 0x0a0a && (v shr 8) == (v and 0xff)
    private fun isWeak(c: Int) = c in 0x0001..0x000a || c == 0xc002 || c == 0xc003 || c == 0xc007 || c == 0xc008 ||
        c == 0xc00c || c == 0xc00d || c == 0xc011 || c == 0xc012 || c == 0xc016

    private fun entropy(b: ByteArray): Float {
        val h = IntArray(256)
        for (x in b) h[x.toInt() and 0xff]++
        var e = 0.0
        for (c in h) if (c > 0) { val q = c.toDouble() / b.size; e -= q * ln(q) / ln(2.0) }
        return e.toFloat()
    }
    /** Random / compressed / encrypted data sits just under the maximum for its sample size; text and JSON are far lower. */
    private fun highEntropy(n: Int, e: Float) = n >= 256 && e >= 8.0 - 255.0 / (2 * n * ln(2.0)) - 0.35

    private fun tlsName(v: Int) = when (v) {
        0x0304 -> "TLS 1.3"; 0x0303 -> "TLS 1.2"; 0x0302 -> "TLS 1.1"; 0x0301 -> "TLS 1.0"; 0x0300 -> "SSL 3.0"; else -> "TLS"
    }

    private fun cipherName(c: Int) = when (c) {
        0x1301 -> "AES-128-GCM"; 0x1302 -> "AES-256-GCM"; 0x1303 -> "ChaCha20-Poly1305"
        0xc02b -> "ECDHE-ECDSA-AES128-GCM"; 0xc02c -> "ECDHE-ECDSA-AES256-GCM"
        0xc02f -> "ECDHE-RSA-AES128-GCM"; 0xc030 -> "ECDHE-RSA-AES256-GCM"
        0xcca8 -> "ECDHE-RSA-ChaCha20"; 0xcca9 -> "ECDHE-ECDSA-ChaCha20"
        0x009c -> "RSA-AES128-GCM (بدون PFS)"; 0x009d -> "RSA-AES256-GCM (بدون PFS)"
        0xc013 -> "ECDHE-RSA-AES128-CBC"; 0xc014 -> "ECDHE-RSA-AES256-CBC"
        0x002f -> "RSA-AES128-CBC (بدون PFS)"; 0x0035 -> "RSA-AES256-CBC (بدون PFS)"
        else -> if (isWeak(c)) "رمز منسوخ (0x" + Integer.toHexString(c) + ")" else "0x" + Integer.toHexString(c)
    }
    private fun noPfs(c: Int) = c == 0x009c || c == 0x009d || c == 0x002f || c == 0x0035 || c == 0x003c || c == 0x003d

    // ------------------------------------------------------------------ analysis (called from the VPN threads)

    fun feed(c: Conn, up: Boolean, d: ByteArray, off: Int, n: Int, port: Int) {
        if (!on || n <= 0) return
        val p = c.probe ?: Probe().also { c.probe = it }
        if (up) { if (p.sUp >= 2) return; p.sUp++ } else { if (p.sDown >= 2) return; p.sDown++ }
        val len = minOf(n, 1500)
        val b = if (off == 0 && len == d.size) d else d.copyOfRange(off, off + len)
        try { analyze(c, p, up, b, port) } catch (_: Exception) {}
    }

    private fun analyze(c: Conn, p: Probe, up: Boolean, b: ByteArray, port: Int) {
        if (c.proto == "TCP") analyzeTcp(c, p, up, b, port) else if (c.proto == "UDP") analyzeUdp(c, p, up, b, port)
        if (p.svc == null) {
            val e = entropy(b)
            if (p.entropy < 0 || b.size >= 256) p.entropy = e
            if (highEntropy(b.size, e)) p.enc = 3
        }
    }

    private fun set(p: Probe, svc: String, enc: Int) { if (p.svc == null || p.svc == "TLS (ادامه)") { p.svc = svc; p.enc = enc } }

    private fun analyzeTcp(c: Conn, p: Probe, up: Boolean, b: ByteArray, port: Int) {
        if (b.size >= 6 && u8(b, 0) == 0x16 && u8(b, 1) == 3) {
            val t = u8(b, 5)
            if (up && t == 1) { parseClient(c, p, b); return }
            if (!up && t == 2) { parseServer(p, b); return }
        }
        if (b.size >= 5 && u8(b, 0) in 0x14..0x17 && u8(b, 1) == 3 && u8(b, 2) <= 4) { set(p, "TLS (ادامه)", 1); return }
        if (starts(b, "SSH-")) { set(p, "SSH", 1); return }
        val h = head(b, 200)
        val low = h.lowercase()
        if (up) {
            when {
                low.startsWith("connect ") -> { set(p, "HTTP CONNECT proxy", 2); return }
                listOf("get ", "post ", "put ", "head ", "delete ", "options ", "patch ").any { low.startsWith(it) } -> {
                    set(p, "HTTP", 2); if (c.url == null) Sniff.http(b)?.let { c.url = it }; return
                }
                low.startsWith("ehlo ") || low.startsWith("helo ") -> { set(p, "SMTP", 2); return }
                low.startsWith("user ") && port == 21 -> { set(p, "FTP", 2); return }
                low.startsWith("nick ") || low.startsWith("cap ls") -> { set(p, "IRC", 2); return }
                u8(b, 0) == 0x13 && h.contains("BitTorrent protocol") -> { set(p, "BitTorrent", 2); return }
                u8(b, 0) == 0x10 && (h.take(14).contains("MQTT") || h.take(14).contains("MQIsdp")) -> { set(p, "MQTT", 2); return }
                b.size >= 3 && u8(b, 0) == 5 && u8(b, 1) in 1..5 && b.size == 2 + u8(b, 1) -> { set(p, "SOCKS5 proxy", 2); return }
                b.size >= 7 && u8(b, 0) == 3 && u8(b, 1) == 0 && u8(b, 5) == 0xE0 -> { set(p, "RDP", 0); return }
                u8(b, 0) == 0xff && b.size >= 3 && u8(b, 1) in 0xfb..0xfe -> { set(p, "Telnet", 2); return }
            }
        } else {
            when {
                low.startsWith("http/1.") -> {
                    set(p, "HTTP", 2)
                    if (low.contains("vnd.android.package-archive") || (low.contains("content-disposition") && low.contains(".apk"))) p.apk = true
                    return
                }
                low.startsWith("220 ") && (low.contains("smtp") || port == 25 || port == 587) -> { set(p, "SMTP", 2); return }
                low.startsWith("220 ") && port == 21 -> { set(p, "FTP", 2); return }
                low.startsWith("* ok") -> { set(p, "IMAP", 2); return }
                low.startsWith("+ok") -> { set(p, "POP3", 2); return }
                low.startsWith("rfb 00") -> { set(p, "VNC", 0); return }
                b.size >= 8 && (u32(b, 4) == 0xff534d42L || u32(b, 4) == 0xfe534d42L) -> { set(p, "SMB", 0); return }
            }
        }
    }

    private fun analyzeUdp(c: Conn, p: Probe, up: Boolean, b: ByteArray, port: Int) {
        if (port == 53 || port == 5353 || port == 5355) {
            if (b.size >= 12) { set(p, if (port == 53) "DNS" else if (port == 5353) "mDNS" else "LLMNR", 2); return }
        }
        if (b.size >= 7 && (u8(b, 0) and 0xc0) == 0xc0) { // QUIC long header
            val v = u32(b, 1)
            val name = when {
                v == 1L -> "QUIC v1 (HTTP/3)"
                v == 0x6b3343cfL -> "QUIC v2"
                (v and 0xffffff00L) == 0xff000000L -> "QUIC draft-" + (v and 0xff)
                v == 0L -> "QUIC (Version Negotiation)"
                else -> null
            }
            if (name != null) { set(p, name, 1); return }
        }
        if (b.size >= 20 && u32(b, 4) == 0x2112a442L) { set(p, "STUN/TURN (تماس/WebRTC)", 2); return }
        if (b.size >= 13 && u8(b, 0) in 20..23 && u8(b, 1) == 0xfe && (u8(b, 2) == 0xfd || u8(b, 2) == 0xff)) { set(p, "DTLS (WebRTC / VPN)", 1); return }
        if (b.size >= 32 && u8(b, 0) in 1..4 && u8(b, 1) == 0 && u8(b, 2) == 0 && u8(b, 3) == 0 && (b.size == 148 || b.size == 92 || b.size == 32 || u8(b, 0) == 4)) {
            set(p, "WireGuard", 1); return
        }
        if (b.size >= 14 && u8(b, 0) == 0x38) { set(p, "OpenVPN", 1); return }
        if (port == 123 && b.size == 48) { set(p, "NTP", 2); return }
        if (port == 1900 && (starts(b, "M-SEARCH") || starts(b, "NOTIFY"))) { set(p, "SSDP / UPnP", 2); return }
        if (port == 443 && b.size >= 20 && (u8(b, 0) and 0x40) != 0 && (u8(b, 0) and 0x80) == 0) { set(p, "QUIC (بستهٔ رمزشده)", 1); return }
    }

    private fun parseClient(c: Conn, p: Probe, d: ByteArray) {
        p.svc = "TLS"; p.enc = 1
        var ver = u16(d, 9); var viaExt = false
        var q = 43
        q += 1 + u8(d, q)
        val csLen = u16(d, q)
        var weak = false
        var i = q + 2
        val csEnd = minOf(q + 2 + csLen, d.size)
        while (i + 2 <= csEnd) { if (isWeak(u16(d, i))) weak = true; i += 2 }
        q += 2 + csLen
        q += 1 + u8(d, q)
        val extEnd = minOf(q + 2 + u16(d, q), d.size)
        q += 2
        val alpns = ArrayList<String>()
        while (q + 4 <= extEnd) {
            val t = u16(d, q); val l = u16(d, q + 2); q += 4
            when (t) {
                0 -> if (q + 5 <= d.size && c.domain == null) {
                    val nl = u16(d, q + 3)
                    if (nl in 1..253 && q + 5 + nl <= d.size) c.domain = String(d, q + 5, nl, Charsets.US_ASCII)
                }
                0x2b -> if (q < d.size) {
                    val n = u8(d, q); var j = q + 1; var best = 0
                    while (j + 2 <= q + 1 + n && j + 2 <= d.size) { val v = u16(d, j); if (!grease(v) && v > best) best = v; j += 2 }
                    if (best > 0) { ver = best; viaExt = true }
                }
                0x10 -> if (q + 2 <= d.size) {
                    var j = q + 2; val e = minOf(q + 2 + u16(d, q), d.size)
                    while (j < e) { val n = u8(d, j); if (j + 1 + n > d.size) break; alpns.add(String(d, j + 1, n, Charsets.US_ASCII)); j += 1 + n }
                }
                0xfe0d -> p.ech = true
                0x33 -> if (q + 2 <= d.size) {
                    var j = q + 2; val e = minOf(q + 2 + u16(d, q), d.size)
                    while (j + 4 <= e) { val g = u16(d, j); if (g == 0x11ec || g == 0x6399) p.pq = true; j += 4 + u16(d, j + 2) }
                }
            }
            q += l
        }
        p.tlsOffered = ver; p.tlsViaExt = viaExt; p.weakOffer = weak
        if (alpns.isNotEmpty() && p.alpn == null) p.alpn = alpns.joinToString(",")
    }

    private fun parseServer(p: Probe, d: ByteArray) {
        if (p.svc == null || p.svc == "TLS (ادامه)") { p.svc = "TLS"; p.enc = 1 }
        var ver = u16(d, 9)
        var q = 43
        q += 1 + u8(d, q)
        p.cipher = u16(d, q)
        q += 3
        if (q + 2 <= d.size) {
            val extEnd = minOf(q + 2 + u16(d, q), d.size)
            q += 2
            while (q + 4 <= extEnd) {
                val t = u16(d, q); val l = u16(d, q + 2); q += 4
                if (t == 0x2b && q + 2 <= d.size) ver = u16(d, q)
                else if (t == 0x10 && q + 5 <= d.size) p.alpn = String(d, q + 3, minOf(u8(d, q + 2), d.size - q - 3), Charsets.US_ASCII)
                q += l
            }
        }
        p.tlsChosen = ver
    }

    // ------------------------------------------------------------------ learned behaviour (per app)
    // Which domains an app normally talks to, and how much it normally uploads while in the background.
    // Stored only on this phone (SharedPreferences "net_baseline"). The first 48 hours per app are learning only.

    private const val BPREF = "net_baseline"
    private const val LEARN_MS = 48L * 3600_000
    private val domCache = HashMap<String, MutableSet<String>>()               // pkg -> known registrable domains
    private val firstSeen = HashMap<String, Long>()                            // pkg -> first time the inspector saw it
    private val bgDays = HashMap<String, java.util.TreeMap<String, Long>>()    // pkg -> day -> background upload bytes
    private val newSeen = HashMap<String, Long>()                              // "pkg|domain" -> when it first appeared (after learning)
    private val lastUp = HashMap<String, Long>()
    private var dirty = false
    private var savedAt = 0L
    private var baseLoaded = false

    private fun e2ld(host: String): String? {
        val h = host.lowercase().trimEnd('.')
        if (!h.contains('.') || h.all { it.isDigit() || it == '.' }) return null
        val l = h.split('.')
        if (l.size < 2) return null
        val sld = setOf("co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go")
        return if (l.size >= 3 && l.last().length == 2 && l[l.size - 2] in sld) l.takeLast(3).joinToString(".") else l.takeLast(2).joinToString(".")
    }

    private fun loadBase(ctx: Context) {
        if (baseLoaded) return
        baseLoaded = true
        val all = ctx.applicationContext.getSharedPreferences(BPREF, Context.MODE_PRIVATE).all
        for ((k, v) in all) {
            try {
                when {
                    k.startsWith("d:") && v is Set<*> -> domCache[k.substring(2)] = LinkedHashSet(v.filterIsInstance<String>())
                    k.startsWith("t:") && v is Long -> firstSeen[k.substring(2)] = v
                    k.startsWith("b:") && v is String -> {
                        val m = java.util.TreeMap<String, Long>()
                        for (part in v.split(';')) {
                            val i = part.indexOf('=')
                            if (i > 0) m[part.substring(0, i)] = part.substring(i + 1).toLongOrNull() ?: 0L
                        }
                        bgDays[k.substring(2)] = m
                    }
                }
            } catch (_: Exception) {}
        }
    }

    private fun saveBase(ctx: Context, force: Boolean) {
        val now = System.currentTimeMillis()
        if (!dirty || (!force && now - savedAt < 120_000)) return
        val e = ctx.applicationContext.getSharedPreferences(BPREF, Context.MODE_PRIVATE).edit()
        for ((p, set) in domCache) e.putStringSet("d:$p", set.toList().takeLast(400).toSet())
        for ((p, t) in firstSeen) e.putLong("t:$p", t)
        for ((p, m) in bgDays) e.putString("b:$p", m.entries.toList().takeLast(15).joinToString(";") { it.key + "=" + it.value })
        e.apply()
        dirty = false
        savedAt = now
    }

    fun resetBaseline(ctx: Context) {
        synchronized(lock) {
            domCache.clear(); firstSeen.clear(); bgDays.clear(); newSeen.clear(); lastUp.clear(); dirty = false
            ctx.applicationContext.getSharedPreferences(BPREF, Context.MODE_PRIVATE).edit().clear().apply()
        }
    }

    /** (0 normal / 1 unusual / 2 very unusual, typical daily background upload). Needs 3 earlier days of history. */
    private fun anomaly(pkg: String, today: String, todayBytes: Long): Pair<Int, Long> {
        val m = bgDays[pkg] ?: return 0 to 0L
        val prev = m.filterKeys { it < today }.values.toList()
        if (prev.size < 3) return 0 to 0L
        val med = prev.sorted()[prev.size / 2]
        val thr = maxOf(5L * 1024 * 1024, 4 * maxOf(med, 512L * 1024))
        val lv = when {
            todayBytes > 3 * thr && todayBytes > 20L * 1024 * 1024 -> 2
            todayBytes > thr -> 1
            else -> 0
        }
        return lv to med
    }

    // ------------------------------------------------------------------ report

    private fun appOf(ctx: Context, uid: Int): Pair<String, String?> = labels.getOrPut(uid) {
        when {
            uid < 0 -> "نامشخص" to null
            uid == 1000 -> "Android System" to "android"
            else -> try {
                val pm = ctx.packageManager
                val pkg = pm.getPackagesForUid(uid)?.firstOrNull()
                if (pkg == null) "uid $uid" to null
                else (pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString()) to pkg
            } catch (_: Exception) { "uid $uid" to null }
        }
    }

    private fun isDoh(c: Conn, port: Int): Boolean {
        if (port != 443) return false
        if (RESOLVERS.containsKey(c.ip)) return true
        val h = (c.domain ?: Tracker.dns[c.ip])?.lowercase() ?: return false
        return DOH_HOSTS.any { h == it || h.endsWith(".$it") }
    }

    fun scan(ctx: Context, notify: Boolean) {
        if (!on) return
        val now = System.currentTimeMillis()
        val db = try { AvDbStore.load(ctx) } catch (_: Exception) { null }
        synchronized(lock) {
            if (now - fgAt > 15_000) { fg = try { Fg.foreground(ctx) } catch (_: Exception) { null }; fgAt = now }
            val fgSet = fg
            val old = Tracker.sessionStart.let { it > 0 && now - it > 120_000 }
            loadBase(ctx)
            val today = java.time.LocalDate.now().toString()
            val selfUid = ctx.applicationInfo.uid
            val bgToday = HashMap<Int, Long>()
            val topConn = HashMap<Int, String>()
            val anomalies = HashMap<Int, Pair<Int, Long>>()
            val learnPk = HashSet<String>()
            if (lastUp.size > 5000) lastUp.clear()
            for ((uid, us) in Tracker.uids) {
                val pkg = appOf(ctx, uid).second
                val bg0 = fgSet != null && (pkg == null || pkg !in fgSet) && uid != selfUid
                var best = -1L
                for (c in us.conns.values) {
                    if (c.proto == "ICMP") continue
                    val k = "$uid|${c.proto}|${c.ip}|${c.port}"
                    val u = c.up.get()
                    val prev = lastUp.put(k, u)
                    // the first observation of a connection counts nothing: we do not know when those bytes were sent
                    val delta = if (prev == null) 0L else if (u >= prev) u - prev else u
                    if (bg0 && delta > 0 && pkg != null) {
                        val m = bgDays.getOrPut(pkg) { java.util.TreeMap<String, Long>() }
                        m[today] = (m[today] ?: 0L) + delta
                        dirty = true
                    }
                    if (u > best) { best = u; topConn[uid] = k }
                }
                if (pkg != null) {
                    val t = bgDays[pkg]?.get(today) ?: 0L
                    bgToday[uid] = t
                    val an = anomaly(pkg, today, t)
                    if (an.first > 0) anomalies[uid] = an
                }
            }
            val items = ArrayList<ScanFinding>()
            var enc = 0; var plain = 0; var unk = 0; var sampled = 0
            val bgSet = HashSet<Int>()
            for ((uid, us) in Tracker.uids) {
                val (label, pkg) = appOf(ctx, uid)
                val bg = fgSet != null && (pkg == null || pkg !in fgSet) && uid != ctx.applicationInfo.uid
                for (c in us.conns.values) {
                    if (c.proto == "ICMP") continue
                    val up = c.up.get(); val down = c.down.get()
                    if (up + down == 0L) continue
                    val p = c.probe
                    val port = c.port
                    val byPort = portSvc(c.proto, port)
                    val notes = ArrayList<String>()
                    var level = 0
                    fun note(l: Int, t: String) { notes.add(t); if (l > level) level = l }
                    val host = c.domain ?: Tracker.dns[c.ip]
                    val local = isLocal(c.ip)
                    val ckey = "$uid|${c.proto}|${c.ip}|${c.port}"
                    var newDom: String? = null
                    if (pkg != null && host != null && !local) {
                        val d = e2ld(host)
                        if (d != null) {
                            val first = firstSeen.getOrPut(pkg) { dirty = true; now }
                            if (now - first < LEARN_MS) learnPk.add(pkg)
                            val known = domCache.getOrPut(pkg) { LinkedHashSet<String>() }
                            if (d !in known) {
                                if (now - first >= LEARN_MS && bg) newSeen.putIfAbsent("$pkg|$d", now)
                                known.add(d)
                                if (known.size > 400) { val itr = known.iterator(); itr.next(); itr.remove() }
                                dirty = true
                            }
                            val ts = newSeen["$pkg|$d"]
                            if (ts != null && now - ts < 6L * 3600_000) newDom = d
                        }
                    }

                    // ---- what is it, and how is it protected
                    var service: String; var crypto: String; var e: Int
                    val tls = p?.svc == "TLS"
                    if (tls) {
                        val parts = ArrayList<String>()
                        parts.add(if (p!!.tlsChosen != 0) tlsName(p.tlsChosen) else tlsName(p.tlsOffered) + " (حداکثر پیشنهادی)")
                        p.alpn?.let { a -> parts.add(if (a.contains("h3")) "ALPN: $a" else "ALPN: $a") }
                        if (p.cipher != 0) parts.add(cipherName(p.cipher))
                        if (p.ech) parts.add("ECH (نام سایت مخفی)")
                        if (p.pq) parts.add("کلید پساکوانتومی")
                        crypto = parts.joinToString(" • ")
                        service = when {
                            port == 853 -> "DNS روی TLS (DoT)"
                            isDoh(c, port) -> "DNS روی HTTPS (DoH)"
                            else -> byPort?.takeIf { port != 443 } ?: "HTTPS"
                        }
                        e = 1
                    } else if (p?.svc != null) {
                        service = p.svc!!
                        e = p.enc
                        crypto = when (p.enc) {
                            1 -> "رمزنگاری‌شده (${p.svc})"
                            2 -> "بدون رمزنگاری"
                            else -> "پروتکل ${p.svc} (رمزنگاری در خود پروتکل)"
                        }
                        if (service == "DNS") {
                            val r = RESOLVERS[c.ip]
                            service = if (r != null) "DNS ($r ${c.ip})" else "DNS"
                            crypto = "بدون رمزنگاری (UDP/$port)"
                        }
                    } else if (p != null && p.enc == 3) {
                        service = byPort ?: "پروتکل ناشناخته"
                        e = 3
                        crypto = "داده با آنتروپی بالا (${"%.1f".format(p.entropy)}/8): رمز یا فشرده، پروتکل شناسایی نشد"
                    } else {
                        service = byPort ?: "نامشخص"
                        e = 0
                        crypto = if (p == null || (p.sUp == 0 && p.sDown == 0)) "نمونه‌برداری نشده (اتصال قبل از روشن‌شدن بازرس برقرار شده؛ فقط طبق پورت)"
                        else "محتوای کافی برای تشخیص دریافت نشد"
                    }
                    // 1.1.1.1 and 8.8.8.8 are the DNS servers the Payesh VPN itself hands to every app, so they are not a bypass
                    if (RESOLVERS.containsKey(c.ip) && port == 53 && c.ip != "1.1.1.1" && c.ip != "8.8.8.8") note(0, "برنامه مستقیم از DNS عمومی ${RESOLVERS[c.ip]} استفاده می‌کند و DNS سیستم را دور می‌زند.")
                    if (c.ip.startsWith("10.10.34.") && host != null) note(1, "نام عمومی $host به آدرس ${c.ip} حل شده؛ این بازه معمولاً صفحهٔ مسدودسازی شبکه است (دست‌کاری DNS بدون رمزنگاری). فعال‌کردن Private DNS (مثلاً dns.google) جلویش را می‌گیرد.")
                    if (service.startsWith("DNS روی")) note(0, "پرس‌وجوهای DNS این برنامه رمزنگاری‌شده است و در لاگ DNS سیستم دیده نمی‌شود.")
                    if (p?.apk == true) { crypto = "بدون رمزنگاری"; service = "HTTP (دانلود APK)"; e = 2 }

                    if (p != null && (p.sUp > 0 || p.sDown > 0)) sampled++
                    when (e) { 1 -> enc++; 2 -> plain++; 3 -> unk++; else -> unk++ }
                    if (bg) bgSet.add(uid)

                    // ---- risk indicators
                    val fam = if (host != null && db != null) db.domainHit(host) else null
                    if (fam != null) note(3, "دامنهٔ ${host} در پایگاه تهدید است ($fam).")
                    if (p?.apk == true) note(3, "فایل APK روی HTTP بدون رمزنگاری دریافت می‌شود؛ مسیر می‌تواند آن را دست‌کاری کند.")
                    val cleartextSvc = e == 2 && !local && service.substringBefore(' ') in
                        setOf("HTTP", "FTP", "Telnet", "SMTP", "IMAP", "POP3", "IRC", "MQTT", "SOCKS5", "HTTP")
                    if (cleartextSvc && p?.apk != true) note(if (bg) 2 else 1, "ارتباط بدون رمزنگاری با ${host ?: c.ip}: هر کسی در مسیر (وای‌فای، اپراتور) می‌تواند محتوا را ببیند یا تغییر دهد.")
                    if (tls && p != null) {
                        val v = if (p.tlsChosen != 0) p.tlsChosen else p.tlsOffered
                        if (v in 0x0300..0x0302) note(2, "نسخهٔ منسوخ و ناامن ${tlsName(v)}.")
                        if (p.cipher != 0 && isWeak(p.cipher)) note(2, "رمز ضعیف انتخاب شد: ${cipherName(p.cipher)}.")
                        else if (p.cipher != 0 && noPfs(p.cipher)) note(1, "رمز انتخابی Forward Secrecy ندارد.")
                        if (p.weakOffer) note(1, "برنامه رمزهای منسوخ (RC4/3DES/DES/NULL) را هم پیشنهاد می‌دهد.")
                        if (host == null && !local && old && !RESOLVERS.containsKey(c.ip)) note(1, "اتصال TLS مستقیم به IP بدون نام دامنه.")
                    }
                    if (e == 3 && !local && byPort == null) {
                        if (bg) note(2, "کانال رمز/فشردهٔ سفارشی روی پورت غیراستاندارد از برنامه‌ای در پس‌زمینه. بازی/تماس/P2P هم همین‌طور است، ولی بدافزارها هم از این الگو استفاده می‌کنند.")
                        else note(1, "کانال رمز/فشردهٔ سفارشی روی پورت غیراستاندارد.")
                    }
                    if (!local) when (port) {
                        4444, 31337 -> note(2, "پورت $port معمولاً برای بک‌دور/ابزار نفوذ استفاده می‌شود.")
                        5555 -> note(2, "پورت ADB: دسترسی دیباگ از راه دور.")
                        9001, 9030, 9050, 9150 -> note(1, "پورت معمول شبکهٔ Tor (ناشناس‌سازی).")
                        23 -> note(2, "Telnet: فرمان و رمز بدون رمزنگاری.")
                        3389, 5900 -> note(1, "پروتکل کنترل از راه دور (${byPort}).")
                        6667 -> note(1, "IRC؛ بات‌نت‌های قدیمی از آن برای فرمان استفاده می‌کردند.")
                        22 -> if (bg) note(1, "SSH از یک برنامهٔ پس‌زمینه.")
                    }
                    if (service == "HTTP CONNECT proxy" || service == "SOCKS5 proxy") note(1, "برنامه از پروکسی/تونل استفاده می‌کند.")
                    if (p?.svc == "WireGuard" || p?.svc == "OpenVPN") note(1, "تونل VPN داخل برنامه (${p?.svc}).")
                    if (bg && up > 20L * 1024 * 1024) note(2, "ارسال حجیم در پس‌زمینه: ${fmt(up)} از اول نشست.")
                    else if (bg && up > 2L * 1024 * 1024) note(1, "ارسال قابل‌توجه در پس‌زمینه: ${fmt(up)}.")

                    if (newDom != null) {
                        if (up >= 1024L * 1024) note(2, "هشدار رفتاری: ارسال ${fmt(up)} به دامنهٔ تازه $newDom از برنامه‌ای در پس‌زمینه.")
                        else note(1, "دامنهٔ تازه برای این برنامه: $newDom (تا امروز در رفتار عادی‌اش دیده نشده بود).")
                    }
                    if (pkg != null && topConn[uid] == ckey) {
                        anomalies[uid]?.let { (lv, med) ->
                            val t = fmt(bgToday[uid] ?: 0L)
                            if (lv == 2) note(2, "هشدار رفتاری: ارسال پس‌زمینهٔ امروز ($t) چند برابر حد معمول این برنامه است (معمولاً حدود ${fmt(med)}).")
                            else note(1, "ارسال پس‌زمینهٔ امروز ($t) بیشتر از حد معمول این برنامه است (معمولاً حدود ${fmt(med)}).")
                        }
                    }

                    items.add(ScanFinding("$uid|${c.proto}|${c.ip}|$port", uid, label, pkg, c.proto, c.ip, port, host, service, crypto, e, level, notes, up, down, bg, p != null && (p.sUp > 0 || p.sDown > 0)))
                }
            }
            items.sortWith(compareByDescending<ScanFinding> { it.level }.thenByDescending { it.bg }.thenByDescending { it.up + it.down })
            val shown = if (items.size > 200) items.subList(0, 200).toList() else items
            report.value = ScanReport(now, items.size, enc, plain, unk, bgSet.size, fgSet != null, sampled, shown, learnPk.size)

            if (notify) {
                var sent = 0
                for (f in items) {
                    if ((f.level < 3 && f.notes.none { it.startsWith("هشدار رفتاری") }) || sent >= 3) continue
                    if (!notified.add(f.key + "|" + f.notes.firstOrNull()?.take(24) + "|" + today)) continue
                    sent++
                    AvNotify.post(
                        ctx, ("netscan:" + f.key).hashCode(), if (f.level >= 3) "بازرس شبکه: ارتباط خطرناک" else "بازرس شبکه: رفتار غیرعادی",
                        "${f.app} ← ${f.host ?: f.ip}:${f.port}\n" + f.notes.take(2).joinToString("\n") { "• $it" }, true
                    )
                }
            }
            saveBase(ctx, false)
        }
    }

    /** Plain-text report (for copying / sharing). */
    fun text(): String {
        val r = report.value ?: return "گزارشی نیست."
        val sb = StringBuilder()
        sb.append("گزارش بازرس شبکهٔ پایش\n")
        sb.append("کل مقصدها: ${r.total} | رمزنگاری‌شده: ${r.encrypted} | بدون رمزنگاری: ${r.plain} | نامشخص/رمز ناشناخته: ${r.unknown} | نمونه‌برداری‌شده: ${r.sampled}\n\n")
        for (f in r.items) {
            sb.append("[${listOf("عادی", "توجه", "مشکوک", "خطرناک")[f.level.coerceIn(0, 3)]}] ${f.app}${if (f.bg) " (پس‌زمینه)" else ""}\n")
            sb.append("  ${f.proto} ${f.ip}:${f.port}${f.host?.let { " ($it)" } ?: ""}\n")
            sb.append("  ${f.service} • ${f.crypto}\n")
            for (n in f.notes) sb.append("  - $n\n")
        }
        return sb.toString()
    }
}
