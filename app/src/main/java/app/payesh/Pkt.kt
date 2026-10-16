package app.payesh

/** Minimal IPv4/TCP/UDP packet helpers. */
object Pkt {
    const val MASK = 0xFFFFFFFFL
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10

    fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)
    fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xff) shl 24) or ((b[o + 1].toLong() and 0xff) shl 16) or
            ((b[o + 2].toLong() and 0xff) shl 8) or (b[o + 3].toLong() and 0xff)

    fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v shr 8).toByte(); b[o + 1] = v.toByte()
    }

    fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v shr 24).toByte(); b[o + 1] = (v shr 16).toByte()
        b[o + 2] = (v shr 8).toByte(); b[o + 3] = v.toByte()
    }

    fun ip(b: ByteArray, o: Int = 0) =
        "${b[o].toInt() and 0xff}.${b[o + 1].toInt() and 0xff}.${b[o + 2].toInt() and 0xff}.${b[o + 3].toInt() and 0xff}"

    private fun sum(b: ByteArray, off: Int, len: Int, init: Long): Long {
        var s = init
        var i = off
        val end = off + len
        while (i + 1 < end) { s += u16(b, i); i += 2 }
        if (i < end) s += (b[i].toInt() and 0xff) shl 8
        return s
    }

    private fun fold(x: Long): Int {
        var s = x
        while ((s shr 16) != 0L) s = (s and 0xffff) + (s shr 16)
        return s.inv().toInt() and 0xffff
    }

    private fun pseudo(src: ByteArray, dst: ByteArray, proto: Int, len: Int): Long =
        (u16(src, 0) + u16(src, 2) + u16(dst, 0) + u16(dst, 2) + proto + len).toLong()

    private fun ipHeader(p: ByteArray, total: Int, proto: Int, src: ByteArray, dst: ByteArray) {
        p[0] = 0x45; p[1] = 0
        put16(p, 2, total); put16(p, 4, 0); put16(p, 6, 0x4000)
        p[8] = 64; p[9] = proto.toByte(); put16(p, 10, 0)
        System.arraycopy(src, 0, p, 12, 4)
        System.arraycopy(dst, 0, p, 16, 4)
        put16(p, 10, fold(sum(p, 0, 20, 0)))
    }

    fun tcp(
        src: ByteArray, dst: ByteArray, sp: Int, dp: Int, seq: Long, ack: Long,
        flags: Int, win: Int, data: ByteArray?, off: Int, len: Int
    ): ByteArray {
        val opt = if ((flags and SYN) != 0) 4 else 0
        val tl = 20 + opt + len
        val total = 20 + tl
        val p = ByteArray(total)
        ipHeader(p, total, 6, src, dst)
        val t = 20
        put16(p, t, sp); put16(p, t + 2, dp)
        put32(p, t + 4, seq and MASK); put32(p, t + 8, ack and MASK)
        p[t + 12] = (((20 + opt) / 4) shl 4).toByte()
        p[t + 13] = flags.toByte()
        put16(p, t + 14, win)
        if (opt > 0) { p[t + 20] = 2; p[t + 21] = 4; put16(p, t + 22, 1360) }
        if (len > 0 && data != null) System.arraycopy(data, off, p, t + 20 + opt, len)
        put16(p, t + 16, fold(sum(p, t, tl, pseudo(src, dst, 6, tl))))
        return p
    }

    /** IPv6 TCP segment without payload (used to refuse IPv6 connections). */
    fun tcp6Rst(src: ByteArray, dst: ByteArray, sp: Int, dp: Int, seq: Long, ack: Long, flags: Int): ByteArray {
        val p = ByteArray(60)
        p[0] = 0x60
        put16(p, 4, 20); p[6] = 6; p[7] = 64
        System.arraycopy(src, 0, p, 8, 16)
        System.arraycopy(dst, 0, p, 24, 16)
        val t = 40
        put16(p, t, sp); put16(p, t + 2, dp)
        put32(p, t + 4, seq and MASK); put32(p, t + 8, ack and MASK)
        p[t + 12] = (5 shl 4).toByte(); p[t + 13] = flags.toByte(); put16(p, t + 14, 0)
        var s = 0L
        var i = 0
        while (i < 16) { s += u16(src, i) + u16(dst, i); i += 2 }
        s += 20 + 6
        put16(p, t + 16, fold(sum(p, t, 20, s)))
        return p
    }

    fun udp(src: ByteArray, dst: ByteArray, sp: Int, dp: Int, data: ByteArray, len: Int): ByteArray {
        val ul = 8 + len
        val total = 20 + ul
        val p = ByteArray(total)
        ipHeader(p, total, 17, src, dst)
        val t = 20
        put16(p, t, sp); put16(p, t + 2, dp); put16(p, t + 4, ul); put16(p, t + 6, 0)
        System.arraycopy(data, 0, p, t + 8, len)
        var c = fold(sum(p, t, ul, pseudo(src, dst, 17, ul)))
        if (c == 0) c = 0xffff
        put16(p, t + 6, c)
        return p
    }
}
