package app.payesh

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/** Declarative behavior rule: matches when all[] present, any[] (if given) has a hit and none[] absent. */
class AvRule(val id: String, val name: String, val score: Int, val all: Set<String>, val any: Set<String>, val none: Set<String>) {
    fun matches(f: Set<String>) = f.containsAll(all) && (any.isEmpty() || any.any { it in f }) && none.none { it in f }
}

/** Threat database that can be updated over the air (no new APK build needed). */
class AvDb(
    val version: Int, val updated: String,
    val hashes: Map<String, String>, val pkgs: Map<String, String>, val certs: Map<String, String>,
    val rules: List<AvRule>
) {
    companion object { val EMPTY = AvDb(0, "", emptyMap(), emptyMap(), emptyMap(), emptyList()) }
}

data class DbInfo(
    val version: Int = 0, val updated: String = "", val hashes: Int = 0, val pkgs: Int = 0,
    val certs: Int = 0, val rules: Int = 0, val lastCheck: Long = 0
)

object AvDbStore {
    /** Data branch published by the "Update AV database" GitHub workflow. */
    const val DEFAULT_URL = "https://raw.githubusercontent.com/iojh2021-oss/payesh/av-db/av-db.json"

    val info = MutableStateFlow(DbInfo())
    val busy = MutableStateFlow(false)
    val message = MutableStateFlow<String?>(null)
    @Volatile private var cache: AvDb? = null
    private val hex64 = Regex("^[0-9a-f]{64}$")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private fun p(ctx: Context) = ctx.applicationContext.getSharedPreferences("payesh_avdb", Context.MODE_PRIVATE)
    private fun file(ctx: Context) = File(ctx.applicationContext.filesDir, "av-db.json")

    fun url(ctx: Context): String = p(ctx).getString("url", DEFAULT_URL) ?: DEFAULT_URL
    fun setUrl(ctx: Context, u: String) = p(ctx).edit().putString("url", u.trim()).remove("etag").apply()
    fun auto(ctx: Context) = p(ctx).getBoolean("auto", true)
    fun setAuto(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("auto", v).apply()
    fun lastCheck(ctx: Context) = p(ctx).getLong("last_check", 0L)

    fun parse(text: String): AvDb {
        val o = JSONObject(text)
        require(o.optInt("schema", 1) == 1) { "schema" }
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
            strMap("certs") { hex64.matches(it) },
            rules
        )
    }

    private fun publish(ctx: Context, db: AvDb) {
        info.value = DbInfo(db.version, db.updated, db.hashes.size, db.pkgs.size, db.certs.size, db.rules.size, lastCheck(ctx))
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

    /** Blocking; call from a background thread. Returns a message for the user. */
    fun updateNow(ctx: Context, force: Boolean): String {
        val app = ctx.applicationContext
        val u = url(app)
        if (!u.startsWith("https://")) return "آدرس بروزرسانی باید با https شروع شود"
        return try {
            val con = URL(u).openConnection() as HttpURLConnection
            con.connectTimeout = 15_000
            con.readTimeout = 30_000
            val etag = p(app).getString("etag", null)
            if (etag != null && !force) con.setRequestProperty("If-None-Match", etag)
            try {
                val code = con.responseCode
                p(app).edit().putLong("last_check", System.currentTimeMillis()).apply()
                if (code == 304) { publish(app, load(app)); return "پایگاه از قبل به‌روز است (نسخهٔ ${load(app).version})" }
                if (code == 404) return "فایل پایگاه هنوز روی سرور ساخته نشده (workflow «Update AV database» را یک‌بار اجرا کن)"
                if (code != 200) return "سرور پاسخ $code داد"
                if (con.contentLengthLong > 40_000_000L) return "فایل پایگاه بیش از حد بزرگ است"
                val text = con.inputStream.bufferedReader().use { it.readText() }
                val db = parse(text)
                val cur = load(app)
                if (db.version < cur.version) return "نسخهٔ سرور (${db.version}) قدیمی‌تر از نسخهٔ فعلی (${cur.version}) است؛ نادیده گرفته شد"
                val tmp = File(app.filesDir, "av-db.json.tmp")
                tmp.writeText(text)
                if (!tmp.renameTo(file(app))) { file(app).writeText(text); tmp.delete() }
                p(app).edit().putString("etag", con.getHeaderField("ETag")).apply()
                cache = db
                publish(app, db)
                "بروزرسانی شد: نسخهٔ ${db.version} • ${db.hashes.size} هش • ${db.pkgs.size} پکیج • ${db.certs.size} گواهی • ${db.rules.size} قانون"
            } finally {
                con.disconnect()
            }
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
        val msg = updateNow(app, false)
        Plog.w("av-db: $msg")
    }
}
