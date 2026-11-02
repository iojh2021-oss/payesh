package app.payesh

import android.util.Base64

/**
 * ML-DSA-65 (FIPS 204) signature check for the threat database. The AV database is signed twice (hybrid):
 * ECDSA P-256 (classical) and ML-DSA-65 (post-quantum). Both must be valid, so a break of either algorithm alone is not enough
 * to push a forged database to the phones.
 * Bouncy Castle is reached by reflection, so a missing or changed library can never crash the app: it just reports why.
 */
object MlDsa {
    /** Public key in the APK (PEM, SubjectPublicKeyInfo). Its presence turns enforcement ON. */
    const val ASSET = "av-pub-mldsa65.pem"
    private const val RAW_PUB_LEN = 1952 // ML-DSA-65 public key size

    @Volatile var lastError = ""

    fun available(): Boolean = try {
        Class.forName("org.bouncycastle.pqc.crypto.mldsa.MLDSASigner")
        true
    } catch (_: Throwable) { false }

    /** Raw public key bytes out of the PEM (minimal DER walk: SEQUENCE { SEQUENCE { OID }, BIT STRING { 00, key } }). */
    fun rawKey(pem: String): ByteArray? = try {
        val der = Base64.decode(pem.lines().filter { !it.startsWith("-----") }.joinToString("").trim(), Base64.DEFAULT)
        var p = 0
        fun len(): Int {
            val l = der[p++].toInt() and 0xff
            if (l < 0x80) return l
            var v = 0
            repeat(l and 0x7f) { v = (v shl 8) or (der[p++].toInt() and 0xff) }
            return v
        }
        require(der[p++].toInt() == 0x30); len()
        require(der[p++].toInt() == 0x30); val al = len(); p += al
        require(der[p++].toInt() == 0x03); val bl = len()
        p++ // number of unused bits
        var key = der.copyOfRange(p, p + bl - 1)
        if (key.size == RAW_PUB_LEN + 4 && key[0].toInt() == 0x04) key = key.copyOfRange(4, key.size) // tolerate an inner OCTET STRING
        if (key.size == RAW_PUB_LEN) key else null
    } catch (_: Exception) { null }

    fun verify(rawPub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = try {
        val paramsCls = Class.forName("org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters")
        val p65 = paramsCls.getField("ml_dsa_65").get(null)
        val pubCls = Class.forName("org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters")
        val pub = pubCls.getConstructor(paramsCls, ByteArray::class.java).newInstance(p65, rawPub)
        val signerCls = Class.forName("org.bouncycastle.pqc.crypto.mldsa.MLDSASigner")
        val signer = signerCls.getConstructor().newInstance()
        val cp = Class.forName("org.bouncycastle.crypto.CipherParameters")
        signerCls.getMethod("init", Boolean::class.javaPrimitiveType!!, cp).invoke(signer, false, pub)
        signerCls.getMethod("update", ByteArray::class.java, Int::class.javaPrimitiveType!!, Int::class.javaPrimitiveType!!)
            .invoke(signer, msg, 0, msg.size)
        val ok = signerCls.getMethod("verifySignature", ByteArray::class.java).invoke(signer, sig) as Boolean
        if (!ok) lastError = "امضا با کلید عمومی مطابقت ندارد"
        ok
    } catch (e: Throwable) {
        lastError = (e.cause ?: e).javaClass.simpleName + (e.cause?.message ?: e.message)?.let { ": " + it.take(60) }.orEmpty()
        false
    }
}
