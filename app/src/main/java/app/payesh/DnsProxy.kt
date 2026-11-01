package app.payesh

import android.content.Context
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Encrypted DNS inside the Payesh VPN. Apps still ask 1.1.1.1 / 8.8.8.8 (the addresses the VPN hands out), but while this
 * is ON every DNS query (UDP/53) is caught by the VPN and sent to the provider you choose over DNS-over-TLS
 * (TCP 853, certificate and host name verified). The network can then neither read nor rewrite the answers.
 * The chosen provider still sees the names you look up: pick the one you trust, or your own server.
 */
object DnsProxy {
    class Provider(val id: String, val name: String, val ips: List<String>, val host: String)

    val builtin = listOf(
        Provider("quad9", "Quad9", listOf("9.9.9.9", "149.112.112.112"), "dns.quad9.net"),
        Provider("cloudflare", "Cloudflare", listOf("1.1.1.1", "1.0.0.1"), "cloudflare-dns.com"),
        Provider("google", "Google", listOf("8.8.8.8", "8.8.4.4"), "dns.google"),
        Provider("adguard", "AdGuard", listOf("94.140.14.14", "94.140.15.15"), "dns.adguard-dns.com")
    )

    @Volatile var enabled = false
    @Volatile var fallbackPlain = true     // if the encrypted channel does not work, use plain DNS instead of breaking the internet
    @Volatile var providerId = "quad9"
    @Volatile var customIp = ""
    @Volatile var customHost = ""
    @Volatile var protector: ((Socket) -> Boolean)? = null   // VpnService.protect: our own sockets must bypass the tunnel
    @Volatile var blockedUntil = 0L        // circuit breaker: after repeated failures stop trying for a minute

    val ok = AtomicInteger()
    val failed = AtomicInteger()
    val plain = AtomicInteger()
    private val fails = AtomicInteger()
    private val pool = ConcurrentLinkedQueue<Dot>()
    private val gate = Semaphore(6)
    private const val PREF = "dns_proxy"
    private var inited = false

    val provider: Provider
        get() = if (providerId == "custom") Provider("custom", "سرور من", listOf(customIp.trim()), customHost.trim())
        else builtin.firstOrNull { it.id == providerId } ?: builtin[0]

    fun init(ctx: Context) {
        if (inited) return
        inited = true
        val sp = ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE)
        enabled = sp.getBoolean("on", false)
        fallbackPlain = sp.getBoolean("fb", true)
        providerId = sp.getString("id", "quad9") ?: "quad9"
        customIp = sp.getString("cip", "") ?: ""
        customHost = sp.getString("chost", "") ?: ""
    }

    fun save(ctx: Context) {
        ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean("on", enabled).putBoolean("fb", fallbackPlain).putString("id", providerId)
            .putString("cip", customIp).putString("chost", customHost).apply()
        fails.set(0)
        blockedUntil = 0L
        closePool()
    }

    fun closePool() {
        while (true) { val d = pool.poll() ?: break; d.close() }
    }

    /** One DNS message in, one DNS message out (both raw wire format, no length prefix). null = failed. */
    fun query(q: ByteArray, force: Boolean): ByteArray? {
        if (q.size < 12 || q.size > 4096) return null
        val p = provider
        if (p.ips.isEmpty() || p.ips[0].isBlank() || p.host.isBlank()) return null
        if (!force && System.currentTimeMillis() < blockedUntil) return null
        if (!gate.tryAcquire(2, TimeUnit.SECONDS)) return null
        try {
            for (attempt in 0 until 2) {
                var d: Dot? = pool.poll()
                if (d != null && (d.ip !in p.ips || d.host != p.host || System.currentTimeMillis() - d.last > 25_000)) { d.close(); d = null }
                if (d == null) {
                    d = Dot(p.ips[attempt % p.ips.size], p.host)
                    if (!d.open()) { d.close(); continue }
                }
                val r = try { d.ask(q) } catch (_: Exception) { null }
                if (r != null) {
                    if (pool.size < 4) pool.offer(d) else d.close()
                    ok.incrementAndGet()
                    fails.set(0)
                    return r
                }
                d.close() // a pooled connection may simply have gone stale: the next attempt opens a fresh one
            }
            failed.incrementAndGet()
            if (fails.incrementAndGet() >= 3) blockedUntil = System.currentTimeMillis() + 60_000
            return null
        } finally {
            gate.release()
        }
    }

    /** Reply too big for one UDP packet inside the tunnel: header + question with the TC bit, so the client retries. */
    fun truncate(r: ByteArray): ByteArray {
        if (r.size < 12) return r
        val qd = ((r[4].toInt() and 0xff) shl 8) or (r[5].toInt() and 0xff)
        var i = 12
        for (k in 0 until qd) {
            while (i < r.size) {
                val l = r[i].toInt() and 0xff
                if (l == 0) { i++; break }
                if ((l and 0xc0) == 0xc0) { i += 2; break }
                i += l + 1
            }
            i += 4
        }
        val t = r.copyOf(minOf(i, r.size))
        t[2] = (t[2].toInt() or 0x02).toByte()
        for (k in 6..11) t[k] = 0
        return t
    }

    private fun buildQuery(name: String): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(byteArrayOf(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
        for (l in name.split('.')) { o.write(l.length); o.write(l.toByteArray()) }
        o.write(0)
        o.write(byteArrayOf(0, 1, 0, 1))
        return o.toByteArray()
    }

    /** Settings-screen test: resolves example.com through the chosen provider. */
    fun test(): String {
        val p = provider
        if (p.ips.isEmpty() || p.ips[0].isBlank() || p.host.isBlank()) return "آدرس IP و نام سرور را وارد کن."
        val t0 = System.currentTimeMillis()
        val r = query(buildQuery("example.com"), true)
        val ms = System.currentTimeMillis() - t0
        return when {
            r == null -> "ناموفق: اتصال امن به ${p.name} (پورت 853) برقرار نشد. ممکن است شبکه این پورت را ببندد."
            (r[3].toInt() and 0x0f) != 0 -> "سرور پاسخ داد ولی خطا برگرداند (rcode=${r[3].toInt() and 0x0f})."
            else -> { blockedUntil = 0L; "کار می‌کند ✓ پاسخ امن از ${p.name} در $ms میلی‌ثانیه." }
        }
    }

    private class Dot(val ip: String, val host: String) {
        var last = System.currentTimeMillis()
        private var raw: Socket? = null
        private var sock: SSLSocket? = null
        private var inp: DataInputStream? = null
        private var out: OutputStream? = null

        fun open(): Boolean {
            return try {
                val r = Socket()
                raw = r
                DnsProxy.protector?.invoke(r)
                r.tcpNoDelay = true
                r.connect(InetSocketAddress(ip, 853), 2000)
                r.soTimeout = 3000
                val f = Pq.factory
                val s = f.createSocket(r, host, 853, true) as SSLSocket
                sock = s
                val prm = s.sslParameters
                prm.endpointIdentificationAlgorithm = "HTTPS" // verify the server certificate against the host name
                s.sslParameters = prm
                s.soTimeout = 3000
                s.startHandshake()
                inp = DataInputStream(BufferedInputStream(s.inputStream))
                out = s.outputStream
                true
            } catch (_: Exception) {
                false
            }
        }

        fun ask(q: ByteArray): ByteArray? {
            val o = out ?: return null
            val i = inp ?: return null
            val msg = ByteArray(q.size + 2)
            msg[0] = (q.size shr 8).toByte()
            msg[1] = q.size.toByte()
            System.arraycopy(q, 0, msg, 2, q.size)
            o.write(msg)
            o.flush()
            val n = i.readUnsignedShort()
            if (n < 12) return null
            val r = ByteArray(n)
            i.readFully(r)
            if (r[0] != q[0] || r[1] != q[1]) return null // not the answer to this query
            last = System.currentTimeMillis()
            return r
        }

        fun close() {
            try { sock?.close() } catch (_: Exception) {}
            try { raw?.close() } catch (_: Exception) {}
        }
    }
}
