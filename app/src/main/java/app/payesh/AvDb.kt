package app.payesh

import android.content.Context
import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/** Declarative behavior rule: matches when all[] present, any[] (if given) has a hit and none[] absent. */
class AvRule(val id: String, val name: String, val score: Int, val all: Set<String>, val any: Set<String>, val none: Set<String>) {
    fun matches(f: Set<String>) = f.containsAll(all) && (any.isEmpty() || any.any { it in f }) && none.none { it in f }
}

/** Threat database published by the GitHub pipeline (hashes, packages, certificates, domains, indicators, rules). */
class AvDb(
    val version: Int, val updated: String,
    val hashes: Map<String, String>, val pkgs: Map<String, String>, val certs: Map<String, String>,
    val rules: List<AvRule>,
    val domains: Map<String, String> = emptyMap(),
    val entries: Map<String, String> = emptyMap()
) {
    /** Matches the host or any parent domain against the malicious-domain list. */
    fun domainHit(host: String): String? {
        var h = host.lowercase().trimEnd('.')
        while (h.contains('.')) {
            domains[h]?.let { return it }
            h = h.substringAfter('.')
        }
        return null
    }

    companion object { val EMPTY = AvDb(0, "", emptyMap(), emptyMap(), emptyMap(), emptyList()) }
}

data class DbInfo(
    val version: Int = 0, val updated: String = "", val hashes: Int = 0, val pkgs: Int = 0,
    val certs: Int = 0, val rules: Int = 0, val lastCheck: Long = 0,
    val domains: Int = 0, val signed: Boolean = false, val signing: Boolean = false, val sources: String = ""
)

private class Resp(val code: Int, val body: ByteArray?, val etag: String?)

object AvDbStore {
    /** Directory of the data branch published by the "Update AV database" workflow. */
    const val DEFAULT_BASE = "https://raw.githubusercontent.com/iojh2021-oss/payesh/av-db/"

    val info = MutableStateFlow(DbInfo())
    val busy = MutableStateFlow(false)
    val message = MutableStateFlow<String?>(null)
    @Volatile private var cache: AvDb? = null
    private val hex64 = Regex("^[0-9a-f]{64}$")
    private val hex40or64 = Regex("^([0-9a-f]{40}|[0-9a-f]{64})$")
    private val hostRe = Regex("^[a-z0-9]([a-z0-9.-]{1,251})[a-z0-9]$")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private fun p(ctx: Context) = ctx.applicationContext.getSharedPreferences("payesh_avdb", Context.MODE_PRIVATE)
    private fun file(ctx: Context) = File(ctx.applicationContext.filesDir, "av-db.json")

    /** Base URL (directory). A stored file URL from older versions is converted to its directory. */
    fun url(ctx: Context): String {
        val u = (p(ctx).getString("url", DEFAULT_BASE) ?: DEFAULT_BASE).trim()
        val dir = if (u.endsWith(".json")) u.substringBeforeLast('/') + "/" else u
        return if (dir.endsWith("/")) dir else "$dir/"
    }
    fun setUrl(ctx: Context, u: String) = p(ctx).edit().putString("url", u.trim()).remove("etag").apply()
    fun auto(ctx: Context) = p(ctx).getBoolean("auto", true)
    fun setAuto(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("auto", v).apply()
    fun lastCheck(ctx: Context) = p(ctx).getLong("last_check", 0L)

    fun parse(text: String): AvDb {
        val o = JSONObject(text)
        require(o.optInt("schema", 1) in 1..2) { "schema" }
        fun strMap(name: String, valid: (String) -> Boolean): Map<String, String> {
            val m = HashMap<String, String>()
            val h = o.optJSONObject(name) ?: return m
            val iter = h.keys()
            while (iter.hasNext()) {
                val k = iter.next()
                val kk = k.lowercase()
                if (valid(kk)) m[kk] = h.optString(k, "Malware").take(60)
            }
            return m
        }
        val rules = ArrayList<AvRule>()
        val ra = o.optJSONArray("rules")
        if (ra != null) for (i in 0 until ra.length()) {
            val r = ra.optJSONObject(i) ?: continue
            val id = r.optString("id")
            if (id.isBlank()) continue
            fun strs(n: String): Set<String> {
                val a = r.optJSONArray(n) ?: return emptySet()
                return (0 until a.length()).map { a.optString(it) }.filter { it.isNotBlank() }.toSet()
            }
            // a rule alone can reach "suspicious" at most; only hash/package/certificate hits are conclusive
            rules.add(AvRule(id, r.optString("name", id).take(80), r.optInt("score", 0).coerceIn(1, 60), strs("all"), strs("any"), strs("none")))
        }
        return AvDb(
            o.optInt("version", 0), o.optString("updated", ""),
            strMap("hashes") { hex64.matches(it) },
            strMap("packages") { it.length in 3..200 && it.contains('.') },
            strMap("certs") { hex40or64.matches(it) },
            rules,
            strMap("domains") { it.length in 4..253 && it.contains('.') && hostRe.matches(it) },
            strMap("entry_names") { it.length in 3..120 && !it.contains('/') }
        )
    }

    private fun publish(ctx: Context, db: AvDb) {
        info.value = DbInfo(
            db.version, db.updated, db.hashes.size, db.pkgs.size, db.certs.size, db.rules.size, lastCheck(ctx),
            db.domains.size, p(ctx).getBoolean("signed", false), pubKey(ctx) != null, p(ctx).getString("sources", "") ?: ""
        )
    }

    private fun baseline(app: Context): AvDb = try {
        parse(app.assets.open("av-db.json").bufferedReader().use { it.readText() })
    } catch (_: Exception) { AvDb.EMPTY }

    /** Downloaded database if present, otherwise the baseline bundled in the APK. */
    fun load(ctx: Context): AvDb {
        cache?.let { return it }
        val app = ctx.applicationContext
        val db = try {
            val f = file(app)
            if (f.exists()) parse(f.readText()) else baseline(app)
        } catch (_: Exception) { baseline(app) }
        cache = db
        publish(app, db)
        return db
    }

    // ------------------------------------------------------------------ verification helpers

    /** Public key bundled in the APK (assets/av-pub.pem). Without it only checksums are verified. */
    private fun pubKey(ctx: Context): PublicKey? = try {
        val pem = ctx.applicationContext.assets.open("av-pub.pem").bufferedReader().use { it.readText() }
        val der = Base64.decode(pem.lines().filter { !it.startsWith("-----") }.joinToString("").trim(), Base64.DEFAULT)
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
    } catch (_: Exception) { null }

    private fun verify(pub: PublicKey, data: ByteArray, sigB64: String): Boolean = try {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initVerify(pub)
        s.update(data)
        s.verify(Base64.decode(sigB64.trim(), Base64.DEFAULT))
    } catch (_: Exception) { false }

    private fun sha256(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun get(u: String, etag: String?, max: Int): Resp {
        val con = URL(u).openConnection() as HttpURLConnection
        con.connectTimeout = 15_000
        con.readTimeout = 30_000
        if (etag != null) con.setRequestProperty("If-None-Match", etag)
        try {
            val code = con.responseCode
            if (code != 200) return Resp(code, null, null)
            val out = ByteArrayOutputStream()
            con.inputStream.use { ins ->
                val b = ByteArray(64 * 1024)
                var total = 0
                while (true) {
                    val n = ins.read(b)
                    if (n < 0) break
                    total += n
                    if (total > max) throw IOException("فایل بیش از حد بزرگ است")
                    out.write(b, 0, n)
                }
            }
            return Resp(200, out.toByteArray(), con.getHeaderField("ETag"))
        } finally {
            con.disconnect()
        }
    }

    /**
     * Pipeline: manifest.json -> (signature check) -> version check -> av-db.json -> SHA-256 check against
     * manifest and checksums.txt -> record-count check -> atomic install. Any failure keeps the old database.
     * Blocking; call from a background thread.
     */
    fun updateNow(ctx: Context, force: Boolean): String {
        val app = ctx.applicationContext
        val base = url(app)
        if (!base.startsWith("https://")) return "آدرس بروزرسانی باید با https شروع شود"
        return try {
            val etag = if (force) null else p(app).getString("etag", null)
            val mr = get(base + "manifest.json", etag, 1_000_000)
            p(app).edit().putLong("last_check", System.currentTimeMillis()).apply()
            if (mr.code == 304) { publish(app, load(app)); return "پایگاه از قبل به‌روز است (نسخهٔ ${load(app).version})" }
            if (mr.code == 404) return "پایگاه هنوز منتشر نشده (workflow «Update AV database» را یک‌بار اجرا کن)"
            val mb = mr.body ?: return "سرور پاسخ ${mr.code} داد"
            val man = JSONObject(String(mb, Charsets.UTF_8))
            require(man.optInt("schema", 0) in 1..2) { "schema مانیفست" }

            // 1) authenticity: digital signature over the exact manifest bytes
            val pub = pubKey(app)
            var signed = false
            if (pub != null) {
                val sr = get(base + "manifest.sig", null, 4096)
                val sig = sr.body?.let { String(it, Charsets.UTF_8) }
                if (sr.code != 200 || sig == null || !verify(pub, mb, sig)) return "امضای دیجیتال پایگاه نامعتبر است؛ بروزرسانی رد شد"
                signed = true
            }

            // 2) version (rollback protection)
            val ver = man.getInt("version")
            val cur = load(app)
            if (ver < cur.version) return "نسخهٔ سرور ($ver) قدیمی‌تر از نسخهٔ فعلی (${cur.version}) است؛ نادیده گرفته شد"
            if (ver == cur.version && !force && file(app).exists()) {
                p(app).edit().putString("etag", mr.etag).apply()
                return "پایگاه از قبل به‌روز است (نسخهٔ $ver)"
            }

            // 3) integrity: file hash must match manifest and checksums.txt
            var wantSha = ""
            var wantSize = -1L
            val files = man.getJSONArray("files")
            for (i in 0 until files.length()) {
                val f = files.getJSONObject(i)
                if (f.optString("name") == "av-db.json") { wantSha = f.optString("sha256").lowercase(); wantSize = f.optLong("size", -1) }
            }
            if (!hex64.matches(wantSha)) return "مانیفست هش فایل پایگاه را ندارد"
            val dr = get(base + "av-db.json", null, 40_000_000)
            val body = dr.body ?: return "دانلود فایل پایگاه ناموفق بود (${dr.code})"
            if (wantSize >= 0 && body.size.toLong() != wantSize) return "اندازهٔ فایل پایگاه با مانیفست نمی‌خواند"
            val got = sha256(body)
            if (got != wantSha) return "هش فایل پایگاه با مانیفست نمی‌خواند؛ رد شد"
            val cr = get(base + "checksums.txt", null, 64_000)
            if (cr.code == 200) {
                val line = String(cr.body ?: ByteArray(0), Charsets.UTF_8).lines().firstOrNull { it.trim().endsWith("av-db.json") }
                if (line == null || !line.trim().lowercase().startsWith(got)) return "checksums.txt با فایل پایگاه نمی‌خواند؛ رد شد"
            }

            // 4) content validation
            val db = parse(String(body, Charsets.UTF_8))
            val counts = man.optJSONObject("counts")
            if (counts != null) {
                fun off(want: Int, have: Int) = want > 0 && Math.abs(want - have) * 100 > want   // more than 1% missing/extra
                if (off(counts.optInt("hashes"), db.hashes.size) || off(counts.optInt("packages"), db.pkgs.size) ||
                    off(counts.optInt("certs"), db.certs.size) || off(counts.optInt("domains"), db.domains.size) ||
                    off(counts.optInt("rules"), db.rules.size)
                ) return "تعداد رکوردهای پایگاه با مانیفست نمی‌خواند؛ رد شد"
            }

            // 5) atomic install
            val tmp = File(app.filesDir, "av-db.json.tmp")
            tmp.writeBytes(body)
            if (!tmp.renameTo(file(app))) { file(app).writeBytes(body); tmp.delete() }
            val src = StringBuilder()
            man.optJSONArray("sources")?.let { a ->
                for (i in 0 until a.length()) {
                    val s = a.optJSONObject(i) ?: continue
                    if (src.isNotEmpty()) src.append(" • ")
                    src.append(s.optString("name")).append(": ").append(s.optString("status"))
                }
            }
            p(app).edit().putString("etag", mr.etag).putBoolean("signed", signed).putString("sources", src.toString()).apply()
            cache = db
            publish(app, db)
            "بروزرسانی شد: نسخهٔ ${db.version} • ${db.hashes.size} هش • ${db.pkgs.size} پکیج • ${db.certs.size} گواهی • ${db.domains.size} دامنه • " +
                (if (signed) "امضا معتبر" else "بدون امضا")
        } catch (e: Exception) {
            "بروزرسانی ناموفق: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    fun updateAsync(ctx: Context) {
        if (busy.value) return
        val app = ctx.applicationContext
        scope.launch {
            busy.value = true
            message.value = null
            message.value = updateNow(app, true)
            busy.value = false
        }
    }

    /** Called periodically: updates when auto-update is on and the last check is older than 6 hours. */
    fun updateIfDue(ctx: Context) {
        val app = ctx.applicationContext
        if (!auto(app) || System.currentTimeMillis() - lastCheck(app) < 6 * 3_600_000L) return
        Plog.w("av-db: " + updateNow(app, false))
    }
}
