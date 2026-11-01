package app.payesh

import org.conscrypt.Conscrypt
import java.io.DataInputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory

/**
 * TLS for every connection Payesh makes itself (database updates, VirusTotal, dashboard, encrypted DNS).
 * It uses the Conscrypt (BoringSSL) library bundled with the app instead of the one in the phone, because the
 * bundled one offers the hybrid post-quantum key exchange X25519MLKEM768 by default (Conscrypt 2.7.0).
 * When the server supports it too, the session key cannot be recovered later from recorded traffic by a quantum computer.
 * Server authentication (certificates) is still classical: public CAs do not issue post-quantum certificates yet.
 * If the bundled library cannot be loaded, the system TLS is used so nothing breaks.
 */
object Pq {
    @Volatile var bundled = false
    @Volatile var error: String? = null

    val factory: SSLSocketFactory by lazy { build() }

    private fun build(): SSLSocketFactory {
        return try {
            val provider = Conscrypt.newProvider()
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?) // the phone's normal trusted certificate authorities
            val ctx = SSLContext.getInstance("TLS", provider)
            ctx.init(null, tmf.trustManagers, null)
            bundled = true
            ctx.socketFactory
        } catch (t: Throwable) {
            error = t.javaClass.simpleName + ": " + (t.message ?: "")
            HttpsURLConnection.getDefaultSSLSocketFactory()
        }
    }

    /** Drop-in replacement for `URL(u).openConnection()`: https connections use [factory]. */
    fun open(url: String): HttpURLConnection {
        val c = URL(url).openConnection() as HttpURLConnection
        if (c is HttpsURLConnection) c.sslSocketFactory = factory
        return c
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)

    /** (supported_groups, key_share groups) of a TLS ClientHello. */
    private fun groups(d: ByteArray): Pair<List<Int>, List<Int>> {
        val sg = ArrayList<Int>()
        val ks = ArrayList<Int>()
        try {
            var q = 43
            q += 1 + (d[q].toInt() and 0xff)
            q += 2 + u16(d, q)
            q += 1 + (d[q].toInt() and 0xff)
            val end = minOf(q + 2 + u16(d, q), d.size)
            q += 2
            while (q + 4 <= end) {
                val t = u16(d, q); val l = u16(d, q + 2); q += 4
                if (t == 0x000a) {
                    var j = q + 2; val e = minOf(q + 2 + u16(d, q), d.size)
                    while (j + 2 <= e) { sg.add(u16(d, j)); j += 2 }
                } else if (t == 0x0033) {
                    var j = q + 2; val e = minOf(q + 2 + u16(d, q), d.size)
                    while (j + 4 <= e) { ks.add(u16(d, j)); j += 4 + u16(d, j + 2) }
                }
                q += l
            }
        } catch (_: Exception) {}
        return sg to ks
    }

    private fun groupName(g: Int) = when (g) {
        0x11ec -> "X25519MLKEM768"
        0x11eb -> "SecP256r1MLKEM768"
        0x11ed -> "SecP384r1MLKEM1024"
        0x6399 -> "X25519Kyber768 (پیش‌نویس قدیمی)"
        0x001d -> "X25519"
        0x0017 -> "P-256"
        0x0018 -> "P-384"
        else -> "0x" + Integer.toHexString(g)
    }
    private fun isPq(g: Int) = g == 0x11ec || g == 0x11eb || g == 0x11ed || g == 0x6399

    /**
     * Offline check: connects to a throw-away server on this phone (127.0.0.1) and reads the TLS ClientHello that
     * the app's TLS library really sends. This proves what we OFFER; whether a given server accepts it is up to the server.
     */
    fun selfTest(): String {
        val f = factory
        val hello = AtomicReference<ByteArray?>(null)
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val t = Thread {
            try {
                server.soTimeout = 4000
                server.accept().use { s ->
                    s.soTimeout = 3000
                    val i = DataInputStream(s.getInputStream())
                    val h = ByteArray(5)
                    i.readFully(h)
                    val body = ByteArray(minOf(u16(h, 3), 16000))
                    i.readFully(body)
                    hello.set(h + body)
                }
            } catch (_: Exception) {}
        }
        t.start()
        try {
            val raw = Socket()
            raw.connect(InetSocketAddress("127.0.0.1", server.localPort), 2000)
            raw.soTimeout = 2000
            val s = f.createSocket(raw, "localhost", server.localPort, true) as SSLSocket
            try { s.startHandshake() } catch (_: Exception) {} // the fake server never answers; the ClientHello is already out
            try { s.close() } catch (_: Exception) {}
        } catch (_: Exception) {}
        t.join(5000)
        try { server.close() } catch (_: Exception) {}
        val b = hello.get() ?: return "ناموفق: ClientHello خوانده نشد."
        val (sg, ks) = groups(b)
        val offers = sg.any { isPq(it) }
        val sent = ks.any { isPq(it) }
        val lib = if (bundled) "Conscrypt همراه برنامه (BoringSSL) ✓" else "TLS پیش‌فرض سیستم؛ کتابخانهٔ همراه بارگذاری نشد (${error ?: "?"})"
        return "کتابخانهٔ TLS: $lib\n" +
            "گروه‌های پیشنهادی: " + sg.joinToString("، ") { groupName(it) } + "\n" +
            "تبادل کلید پسا‌کوانتومی پیشنهاد می‌شود: " + (if (offers) "بله ✓" else "خیر ✗") + "\n" +
            "کلید PQ واقعاً فرستاده می‌شود: " + (if (sent) "بله ✓" else "خیر ✗")
    }
}
