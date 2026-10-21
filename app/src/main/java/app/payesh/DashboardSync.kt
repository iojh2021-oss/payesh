package app.payesh

import android.content.Context
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

/**
 * Optional, opt-in report to the Payesh dashboard API (POST /api/v1/telemetry).
 * OFF by default. Sends only summary data (counts, scan findings, event log) and a random install id —
 * never file contents, traffic contents or URLs.
 */
object DashboardPrefs {
    private fun p(ctx: Context) = ctx.applicationContext.getSharedPreferences("payesh_dashboard", Context.MODE_PRIVATE)
    fun enabled(ctx: Context) = p(ctx).getBoolean("on", false)
    fun url(ctx: Context) = p(ctx).getString("url", "") ?: ""
    fun token(ctx: Context) = p(ctx).getString("token", "") ?: ""
    fun name(ctx: Context) = p(ctx).getString("name", "") ?: ""
    fun set(ctx: Context, on: Boolean, url: String, token: String, name: String) =
        p(ctx).edit().putBoolean("on", on).putString("url", url.trim().trimEnd('/'))
            .putString("token", token.trim()).putString("name", name.trim()).apply()

    /** Random per-install id (not a hardware identifier). */
    fun deviceId(ctx: Context): String {
        val sp = p(ctx)
        sp.getString("id", null)?.let { return it }
        val id = UUID.randomUUID().toString()
        sp.edit().putString("id", id).apply()
        return id
    }
}

object DashboardSync {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val lastResult = MutableStateFlow("")
    @Volatile private var lastSent = 0L

    private fun iso(t: Long): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(t))

    fun build(ctx: Context): JSONObject {
        val now = System.currentTimeMillis()
        val pm = ctx.packageManager
        val pkgs = try { pm.getInstalledPackages(0) } catch (_: Exception) { emptyList() }
        val sys = pkgs.count { (it.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0 }
        var tcp = 0; var udp = 0
        val doms = HashSet<String>()
        for (u in Tracker.uids.values) for (c in u.conns.values) {
            if (c.proto.equals("tcp", true)) tcp++ else udp++
            c.domain?.let { doms.add(it) }
        }
        val findings = AvState.findings.value
        val rt = Runtime.getRuntime()
        val apps = JSONArray()
        findings.filter { it.kind == 0 }.take(200).forEach {
            apps.put(JSONObject().put("name", it.title).put("pkg", it.pkg ?: "").put("kind", "برنامه نصب‌شده")
                .put("version", "").put("status", if (it.level == 0) "بررسی‌شده" else if (it.level == 1) "مشکوک" else "خطرناک"))
        }
        val logs = JSONArray()
        findings.filter { it.level > 0 }.take(50).forEach {
            logs.put(JSONObject().put("type", "warn").put("title", it.title)
                .put("desc", (listOf(it.sub) + it.reasons).filter { s -> s.isNotBlank() }.joinToString(" • "))
                .put("time", ""))
        }
        AvState.netThreats.value.take(30).forEach {
            logs.put(JSONObject().put("type", "warn").put("title", "تهدید شبکه: ${it.label}")
                .put("desc", "${it.domain} (${it.family})").put("time", iso(it.time)))
        }
        val name = DashboardPrefs.name(ctx).ifBlank { "${Build.MANUFACTURER} ${Build.MODEL}" }
        return JSONObject()
            .put("id", DashboardPrefs.deviceId(ctx)).put("name", name)
            .put("model", Build.MODEL).put("android", "Android ${Build.VERSION.RELEASE}")
            .put("app_version", "Payesh " + try { pm.getPackageInfo(ctx.packageName, 0).versionName } catch (_: Exception) { "" })
            .put("last_seen", iso(now)).put("online", true)
            .put("vpn", Tracker.running.value).put("guard", AvState.enabled.value)
            .put("db", "").put("score", AvState.score.value.takeIf { it >= 0 })
            .put("memory", "${(rt.totalMemory() - rt.freeMemory()) / 1_048_576} MB")
            .put("threads", Thread.activeCount()).put("tcp", tcp).put("udp", udp)
            .put("packages", pkgs.size).put("system_apps", sys).put("user_apps", pkgs.size - sys)
            .put("files_scanned", AvState.counts.value.files)
            .put("events", AvGuardState.events.value).put("alerts", findings.count { it.level > 0 })
            .put("hashes", AvPrefs.sigCount(ctx)).put("certs", 0).put("domains", doms.size)
            .put("apps", apps).put("scans", JSONArray()).put("logs", logs)
    }

    /** Called from the guard loop; sends at most every 10 minutes and only if the user enabled it. */
    fun syncIfDue(ctx: Context) {
        if (!DashboardPrefs.enabled(ctx)) return
        if (System.currentTimeMillis() - lastSent < 10 * 60_000L) return
        sendNow(ctx)
    }

    fun sendNow(ctx: Context) {
        val app = ctx.applicationContext
        scope.launch {
            val url = DashboardPrefs.url(app)
            val token = DashboardPrefs.token(app)
            if (!url.startsWith("https://") || token.isEmpty()) {
                lastResult.value = "آدرس باید با https:// شروع شود و توکن خالی نباشد"
                return@launch
            }
            try {
                val c = URL("$url/api/v1/telemetry").openConnection() as HttpURLConnection
                c.requestMethod = "POST"
                c.connectTimeout = 10_000; c.readTimeout = 15_000
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.setRequestProperty("Authorization", "Bearer $token")
                c.outputStream.use { it.write(build(app).toString().toByteArray()) }
                val code = c.responseCode
                c.disconnect()
                if (code in 200..299) { lastSent = System.currentTimeMillis(); lastResult.value = "ارسال شد ✓" }
                else lastResult.value = "خطای سرور: HTTP $code"
            } catch (e: Exception) {
                lastResult.value = "ارسال ناموفق: ${e.javaClass.simpleName}"
            }
        }
    }
}

@Composable
fun DashboardCard(ctx: Context) {
    var on by remember { mutableStateOf(DashboardPrefs.enabled(ctx)) }
    var url by remember { mutableStateOf(DashboardPrefs.url(ctx)) }
    var token by remember { mutableStateOf(DashboardPrefs.token(ctx)) }
    var name by remember { mutableStateOf(DashboardPrefs.name(ctx)) }
    val res by DashboardSync.lastResult.collectAsState()
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp)) {
        Row {
            Column(Modifier.weight(1f)) {
                Text("ارسال گزارش به داشبورد", color = Color.White, fontWeight = FontWeight.Bold)
                Text(
                    "اختیاری و پیش‌فرض خاموش. فقط خلاصهٔ وضعیت، نتیجهٔ اسکن و رویدادها ارسال می‌شود؛ نه محتوای فایل‌ها و نه ترافیک.",
                    color = Muted, fontSize = 11.sp
                )
            }
            Toggle(on) { on = it; DashboardPrefs.set(ctx, it, url, token, name) }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(url, { url = it }, label = { Text("آدرس API (https://…)") }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), modifier = Modifier.fillMaxWidth())
        OutlinedTextField(token, { token = it }, label = { Text("توکن ارسال") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
        OutlinedTextField(name, { name = it }, label = { Text("نام دستگاه (اختیاری)") }, singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
        Spacer(Modifier.height(8.dp))
        AvBtn("ذخیره و ارسال همین حالا", true, Accent, Modifier.fillMaxWidth()) {
            DashboardPrefs.set(ctx, on, url, token, name)
            DashboardSync.sendNow(ctx)
        }
        if (res.isNotEmpty()) Text(res, color = Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
    }
}
