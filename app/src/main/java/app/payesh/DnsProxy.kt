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
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLSocket

/**
 * Encrypted DNS inside the Payesh VPN. Apps still ask 1.1.1.1 / 8.8.8.8 (the addresses the VPN hands out), but while this
 * is ON every DNS query (UDP/53) is caught by the VPN and sent to the provider you choose over an encrypted channel:
 *  - DoT: DNS-over-TLS on TCP 853 (some networks block this port), or
 *  - DoH: DNS-over-HTTPS on TCP 443 (looks like ordinary web traffic, much harder to block).
 * "Auto" tries the channel that worked last and falls back to the other one. The certificate and host name of the
 * server are always verified, so the network can neither read nor rewrite the answers.
 * The chosen provider still sees the names you look up: pick the one you trust, or your own server.
 */
object DnsProxy {
    class Provider(val id: String, val name: String, val ips: List<String>, val host: String, val path: String = "/dns-query")

    val builtin = listOf(
        Provider("quad9", "Quad9", listOf("9.9.9.9", "149.112.112.112"), "dns.quad9.net"),
        Provider("cloudflare", "Cloudflare", listOf("1.1.1.1", "1.0.0.1"), "cloudflare-dns.com"),
        Provider("google", "Google", listOf("8.8.8.8", "8.8.4.4"), "dns.google"),
        Provider("adguard", "AdGuard", listOf("94.140.14.14", "94.140.15.15"), "dns.adguard-dns.com")
    )

    const val T_AUTO = 0
    const val T_DOT = 1
    const val T_DOH = 2

    @Volatile var enabled = false
    @Volatile var fallbackPlain = true     // if no encrypted channel works, use plain DNS instead of breaking the internet
    @Volatile var providerId = "quad9"
    @Volatile var transport = T_AUTO
    @Volatile var customIp = ""
    @Volatile var customHost = ""
    @Volatile var lastOk = ""              // "DoT" or "DoH": the channel that answered last
    @Volatile var lastError = ""           // why the last attempt failed (stage + exception)
    @Volatile var lastOkAt = 0L            // when an encrypted answer last arrived (the inspector only claims "encrypted" if this is recent)
    @Volatile var protector: ((Socket) -> Boolean)? = null   // VpnService.protect: our own sockets must bypass the tunnel

    val ok = AtomicInteger()
    val failed = AtomicInteger()
    val plain = AtomicInteger()

    // circuit breaker per channel: after repeated failures stop trying that channel for a few minutes
    private val dotBlocked = AtomicLong(0)
    private val dohBlocked = AtomicLong(0)
    private val dotFails = AtomicInteger()
    private val dohFails = AtomicInteger()
    private val lastLog = AtomicLong(0)
    private val dotPool = ConcurrentLinkedQueue<Chan>()
    private val dohPool = ConcurrentLinkedQueue<Chan>()
    private val gate = Semaphore(6)
    private const val PREF = "dns_proxy"
    private var inited = false

    val blockedUntil: Long
        get() = when (transport) {
            T_DOT -> dotBlocked.get()
            T_DOH -> dohBlocked.get()
            else -> minOf(dotBlocked.get(), dohBlocked.get())
        }

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
        transport = sp.getInt("tr", T_AUTO)
        customIp = sp.getString("cip", "") ?: ""
        customHost = sp.getString("chost", "") ?: ""
    }

    fun save(ctx: Context) {
        ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean("on", enabled).putBoolean("fb", fallbackPlain).putString("id", providerId).putInt("tr", transport)
            .putString("cip", customIp).putString("chost", customHost).apply()
        dotFails.set(0); dohFails.set(0)
        dotBlocked.set(0); dohBlocked.set(0)
        closePool()
    }

    fun closePool() {
        while (true) { val d = dotPool.poll() ?: break; d.close() }
        while (true) { val d = dohPool.poll() ?: break; d.close() }
    }

    private fun blockedOf(t: Int) = if (t == T_DOT) dotBlocked.get() else dohBlocked.get()

    /** One DNS message in, one DNS message out (raw wire format). null = no encrypted channel worked. */
    fun query(q: ByteArray, force: Boolean): ByteArray? {
        if (q.size < 12 || q.size > 4096) return null
        val p = provider
        if (p.ips.isEmpty() || p.ips[0].isBlank() || p.host.isBlank()) return null
        val order = when (transport) {
            T_DOT -> listOf(T_DOT)
            T_DOH -> listOf(T_DOH)
            else -> if (lastOk == "DoH") listOf(T_DOH, T_DOT) else listOf(T_DOT, T_DOH)
        }
        if (!gate.tryAcquire(2, TimeUnit.SECONDS)) return null
        try {
            for (t in order) {
                if (!force && System.currentTimeMillis() < blockedOf(t)) continue
                val r = queryOn(t, p, q)
                if (r != null) return r
            }
            failed.incrementAndGet()
            return null
        } finally {
            gate.release()
        }
    }

    private fun queryOn(t: Int, p: Provider, q: ByteArray): ByteArray? {
        val pool = if (t == T_DOT) dotPool else dohPool
        for (attempt in 0 until 2) {
            var c: Chan? = pool.poll()
            if (c != null && (c.ip !in p.ips || c.host != p.host || System.currentTimeMillis() - c.last > 25_000)) { c.close(); c = null }
            if (c == null) {
                val ip = p.ips[attempt % p.ips.size]
                c = if (t == T_DOT) Dot(ip, p.host) else Doh(ip, p.host, p.path)
                if (!c.open()) { c.close(); continue }
            }
            val r = try { c.ask(q) } catch (e: Exception) { lastError = "پرسش: " + e.javaClass.simpleName; null }
            if (r != null) {
                if (!c.dead && pool.size < 4) pool.offer(c) else c.close()
                ok.incrementAndGet()
                (if (t == T_DOT) dotFails else dohFails).set(0)
                val label = if (t == T_DOT) "DoT" else "DoH"
                if (lastOk != label) Plog.w("dns: encrypted answers via $label (${p.name})")
                lastOk = label
                lastOkAt = System.currentTimeMillis()
                return r
            }
            c.close() // a pooled connection may simply have gone stale: the next attempt opens a fresh one
        }
        val now0 = System.currentTimeMillis()
        if (now0 - lastLog.get() > 60_000) { // one line per minute, so the log shows WHY without flooding it
            lastLog.set(now0)
            Plog.w("dns: ${if (t == T_DOT) "DoT" else "DoH"} failed (${p.name}): ${lastError.ifEmpty { "no detail" }}")
        }
        val n = (if (t == T_DOT) dotFails else dohFails).incrementAndGet()
        if (n >= 2) (if (t == T_DOT) dotBlocked else dohBlocked).set(System.currentTimeMillis() + 180_000)
        return null
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

    /** Settings-screen test: resolves example.com through the chosen provider over BOTH channels and says what happened. */
    fun test(): String {
        val p = provider
        if (p.ips.isEmpty() || p.ips[0].isBlank() || p.host.isBlank()) return "آدرس IP و نام سرور را وارد کن."
        val q = buildQuery("example.com")
        val sb = StringBuilder()
        var any = false
        for ((t, name) in listOf(T_DOT to "DoT (پورت 853)", T_DOH to "DoH (پورت 443)")) {
            lastError = ""
            val t0 = System.currentTimeMillis()
            val r = queryOn(t, p, q)
            val ms = System.currentTimeMillis() - t0
            sb.append(name).append(": ")
            if (r == null) sb.append("ناموفق").append(if (lastError.isNotEmpty()) " — $lastError" else "")
            else if ((r[3].toInt() and 0x0f) != 0) sb.append("پاسخ با خطا (rcode=${r[3].toInt() and 0x0f})")
            else { any = true; sb.append("کار می‌کند ✓ ($ms میلی‌ثانیه)") }
            sb.append("\n")
        }
        if (any) { dotBlocked.set(0); dohBlocked.set(0) }
        sb.append(
            if (any) "مسیر سالم پیدا شد. حالت «خودکار» خودش همان را انتخاب می‌کند."
            else "هیچ مسیری کار نکرد؛ احتمالاً شبکه یا ISP این سرویس را می‌بندد. سرویس دیگری را امتحان کن."
        )
        return sb.toString()
    }

    // ------------------------------------------------------------------ channels

    private abstract class Chan(val ip: String, val host: String) {
        var last = System.currentTimeMillis()
        @Volatile var dead = false
        protected var raw: Socket? = null
        protected var sock: SSLSocket? = null
        protected var inp: DataInputStream? = null
        protected var out: OutputStream? = null
        protected abstract val port: Int
        protected abstract val tag: String

        fun open(): Boolean {
            var stage = "اتصال TCP"
            return try {
                val r = Socket()
                raw = r
                DnsProxy.protector?.invoke(r)
                r.tcpNoDelay = true
                r.connect(InetSocketAddress(ip, port), 2000)
                r.soTimeout = 2500
                stage = "دست‌دهی TLS"
                val s = Pq.factory.createSocket(r, host, port, true) as SSLSocket
                sock = s
                val prm = s.sslParameters
                prm.endpointIdentificationAlgorithm = "HTTPS" // verify the server certificate against the host name
                s.sslParameters = prm
                s.soTimeout = 2500
                s.startHandshake()
                inp = DataInputStream(BufferedInputStream(s.inputStream))
                out = s.outputStream
                true
            } catch (e: Exception) {
                DnsProxy.lastError = tag + " " + stage + ": " + e.javaClass.simpleName + (e.message?.let { " (" + it.take(70) + ")" } ?: "")
                false
            }
        }

        abstract fun ask(q: ByteArray): ByteArray?

        fun close() {
            try { sock?.close() } catch (_: Exception) {}
            try { raw?.close() } catch (_: Exception) {}
        }
    }

    private class Dot(ip: String, host: String) : Chan(ip, host) {
        override val port = 853
        override val tag = "DoT"

        override fun ask(q: ByteArray): ByteArray? {
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
    }

    /** DNS-over-HTTPS (RFC 8484), HTTP/1.1 POST with keep-alive over our own verified TLS socket. */
    private class Doh(ip: String, host: String, val path: String) : Chan(ip, host) {
        override val port = 443
        override val tag = "DoH"

        override fun ask(q: ByteArray): ByteArray? {
            val o = out ?: return null
            val i = inp ?: return null
            val head = "POST $path HTTP/1.1\r\nHost: $host\r\nContent-Type: application/dns-message\r\n" +
                "Accept: application/dns-message\r\nContent-Length: ${q.size}\r\nConnection: keep-alive\r\n\r\n"
            o.write(head.toByteArray(Charsets.ISO_8859_1))
            o.write(q)
            o.flush()
            val status = readLine(i) ?: return null
            if (!status.startsWith("HTTP/1.") || !status.contains(" 200")) {
                DnsProxy.lastError = "DoH پاسخ HTTP: " + status.take(40)
                dead = true
                return null
            }
            var len = -1
            var chunked = false
            var connClose = false
            while (true) {
                val l = readLine(i) ?: return null
                if (l.isEmpty()) break
                val k = l.substringBefore(':').trim().lowercase()
                val v = l.substringAfter(':', "").trim().lowercase()
                if (k == "content-length") len = v.toIntOrNull() ?: -1
                else if (k == "transfer-encoding") chunked = v.contains("chunked")
                else if (k == "connection") connClose = v.contains("close")
            }
            val body = if (chunked) readChunked(i) else if (len in 12..65535) ByteArray(len).also { i.readFully(it) } else null
            if (connClose) dead = true
            if (body == null || body.size < 12) return null
            if (body[0] != q[0] || body[1] != q[1]) return null
            last = System.currentTimeMillis()
            return body
        }

        private fun readLine(i: DataInputStream): String? {
            val sb = StringBuilder()
            while (sb.length < 8192) {
                val b = i.read()
                if (b < 0) return null
                if (b == '\n'.code) return sb.toString().trimEnd('\r')
                sb.append(b.toChar())
            }
            return null
        }

        private fun readChunked(i: DataInputStream): ByteArray? {
            val acc = ByteArrayOutputStream()
            while (true) {
                val l = readLine(i) ?: return null
                val n = l.substringBefore(';').trim().toIntOrNull(16) ?: return null
                if (n == 0) {
                    while (true) { val t = readLine(i) ?: break; if (t.isEmpty()) break }
                    break
                }
                if (n > 65535 || acc.size() + n > 65535) return null
                val b = ByteArray(n)
                i.readFully(b)
                acc.write(b)
                readLine(i) // the CRLF after each chunk
            }
            return acc.toByteArray()
        }
    }
}
