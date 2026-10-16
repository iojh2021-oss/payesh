package app.payesh

/** Extracts domain names / URLs from DNS answers, TLS ClientHello (SNI) and plain HTTP. */
object Sniff {

    private fun readName(d: ByteArray, start: Int): Pair<String, Int> {
        val sb = StringBuilder()
        var p = start
        var next = -1
        var jumps = 0
        while (p < d.size) {
            val l = d[p].toInt() and 0xff
            if (l == 0) { p++; break }
            if ((l and 0xc0) == 0xc0) {
                if (next < 0) next = p + 2
                p = ((l and 0x3f) shl 8) or (d[p + 1].toInt() and 0xff)
                if (++jumps > 10) break
                continue
            }
            p++
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(d, p, l, Charsets.US_ASCII))
            p += l
        }
        return sb.toString() to (if (next >= 0) next else p)
    }

    /** Learns ip -> domain from a DNS response. */
    fun dns(d: ByteArray) {
        try {
            if (d.size < 12 || (d[2].toInt() and 0x80) == 0) return
            val qd = Pkt.u16(d, 4)
            val an = Pkt.u16(d, 6)
            var p = 12
            var qname = ""
            repeat(qd) {
                val (n, np) = readName(d, p)
                if (qname.isEmpty()) qname = n
                p = np + 4
            }
            if (qname.isEmpty()) return
            repeat(an) {
                if (p >= d.size) return
                val (_, np) = readName(d, p)
                p = np
                if (p + 10 > d.size) return
                val type = Pkt.u16(d, p)
                val rdlen = Pkt.u16(d, p + 8)
                p += 10
                if (type == 1 && rdlen == 4 && p + 4 <= d.size) Tracker.dns[Pkt.ip(d, p)] = qname
                p += rdlen
            }
        } catch (_: Exception) {
        }
    }

    /** Server name from a TLS ClientHello (may be truncated). */
    fun sni(d: ByteArray): String? {
        try {
            if (d.size < 48 || d[0].toInt() != 0x16 || d[5].toInt() != 1) return null
            var p = 43
            p += 1 + (d[p].toInt() and 0xff)
            p += 2 + Pkt.u16(d, p)
            p += 1 + (d[p].toInt() and 0xff)
            val extEnd = p + 2 + Pkt.u16(d, p)
            p += 2
            while (p + 4 <= extEnd && p + 4 <= d.size) {
                val type = Pkt.u16(d, p)
                val len = Pkt.u16(d, p + 2)
                p += 4
                if (type == 0) {
                    val nl = Pkt.u16(d, p + 3)
                    return String(d, p + 5, nl, Charsets.US_ASCII)
                }
                p += len
            }
        } catch (_: Exception) {
        }
        return null
    }

    /** "host/path" from the first line of a plain HTTP request. */
    fun http(d: ByteArray): String? {
        return try {
            val s = String(d, 0, minOf(d.size, 1024), Charsets.ISO_8859_1)
            val lines = s.lineSequence()
            val first = lines.firstOrNull() ?: return null
            val parts = first.split(" ")
            if (parts.size < 2 || parts[0] !in setOf("GET", "POST", "PUT", "HEAD")) return null
            val host = lines.firstOrNull { it.startsWith("Host:", true) }?.substring(5)?.trim() ?: ""
            host + parts[1]
        } catch (_: Exception) {
            null
        }
    }
}
