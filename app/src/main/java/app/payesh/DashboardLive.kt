package app.payesh

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** The UI's own traffic list, published by MainVM so the live stream shows exactly what the Live screen shows. */
object LiveBridge {
    @Volatile var apps: List<AppUi> = emptyList()
    @Volatile var at = 0L
}

/**
 * Opt-in live mirror of the app's screens for the dashboard (read-only).
 * Idle: asks the server every few seconds "is a dashboard open for this device?".
 * Only while one is, it sends the same data the app screens show; nothing can be controlled from the dashboard.
 * A visible notification is shown for as long as the stream is active.
 */
object DashboardLive {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var job: Job? = null
    val streaming = MutableStateFlow(false)
    val status = MutableStateFlow("")

    fun ensure(ctx: Context) {
        val app = ctx.applicationContext
        if (!(DashboardPrefs.enabled(app) && DashboardPrefs.live(app))) {
            job?.cancel(); job = null
            if (streaming.value) setStreaming(app, false)
            return
        }
        if (job?.isActive == true) return
        job = scope.launch { loop(app) }
    }

    private fun setStreaming(ctx: Context, on: Boolean) {
        if (streaming.value == on) return
        streaming.value = on
        Plog.w(if (on) "live: dashboard connected, streaming" else "live: stream stopped")
        try {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            if (on) {
                nm.createNotificationChannel(NotificationChannel("guard", "محافظ آنتی‌ویروس", NotificationManager.IMPORTANCE_LOW))
                val pi = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
                val n = Notification.Builder(ctx, "guard").setSmallIcon(R.drawable.ic_notif)
                    .setContentTitle("اشتراک زنده فعال است")
                    .setContentText("داشبورد در حال مشاهدهٔ وضعیت این گوشی است (فقط مشاهده). برای قطع، از تنظیمات برنامه خاموشش کن.")
                    .setContentIntent(pi).setOngoing(true).build()
                nm.notify(3, n)
            } else {
                nm.cancel(3)
            }
        } catch (_: Exception) {
        }
    }

    private suspend fun loop(ctx: Context) {
        var watch = false
        var fails = 0
        val sent = HashMap<String, String>()
        var tAv = 0L
        var tSlow = 0L
        var tFull = SystemClock.elapsedRealtime()
        while (currentCoroutineContext().isActive && DashboardPrefs.enabled(ctx) && DashboardPrefs.live(ctx)) {
            val base = DashboardPrefs.url(ctx)
            val tok = DashboardPrefs.token(ctx)
            if (!base.startsWith("https://") || tok.isEmpty()) {
                status.value = "آدرس https یا توکن کامل نیست"
                delay(10_000); continue
            }
            val id = URLEncoder.encode(DashboardPrefs.deviceId(ctx), "UTF-8")
            try {
                if (watch) {
                    val now = SystemClock.elapsedRealtime()
                    if (now - tFull > 60_000) { sent.clear(); tFull = now }
                    val body = JSONObject()
                    putIfChanged(body, sent, "traffic", trafficJson())
                    if (now - tAv > 4_000 || tAv == 0L) {
                        tAv = now
                        putIfChanged(body, sent, "meta", metaJson(ctx))
                        putIfChanged(body, sent, "av", avJson(ctx))
                        putIfChanged(body, sent, "clean", cleanJson())
                        putIfChanged(body, sent, "log", JSONObject().put("lines", JSONArray(Plog.tail(40))))
                    }
                    if (now - tSlow > 30_000 || tSlow == 0L) {
                        tSlow = now
                        putIfChanged(body, sent, "sys", sysJson(ctx))
                        putIfChanged(body, sent, "hist", histJson(ctx))
                    }
                    val r = http("POST", "$base/api/v1/live/$id", tok, body.toString()) ?: throw IllegalStateException("http")
                    watch = r.optBoolean("watch", false)
                } else {
                    val r = http("GET", "$base/api/v1/live/$id/watch", tok, null) ?: throw IllegalStateException("http")
                    watch = r.optBoolean("watch", false)
                    if (watch) { sent.clear(); tAv = 0L; tSlow = 0L; tFull = SystemClock.elapsedRealtime() }
                }
                fails = 0
                status.value = if (watch) "در حال پخش زنده" else "آماده؛ منتظر باز شدن داشبورد"
                setStreaming(ctx, watch)
                delay(if (watch) 2_000 else 6_000)
            } catch (e: Exception) {
                fails++
                watch = false
                setStreaming(ctx, false)
                status.value = "خطای اتصال به سرور"
                delay(if (fails < 5) 8_000 else 30_000)
            }
        }
        setStreaming(ctx, false)
    }

    private fun putIfChanged(body: JSONObject, sent: HashMap<String, String>, key: String, v: JSONObject) {
        val s = v.toString()
        if (sent[key] != s) { sent[key] = s; body.put(key, v) }
    }

    private fun http(method: String, url: String, token: String, body: String?): JSONObject? {
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 8_000; c.readTimeout = 12_000
            c.setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(body.toByteArray()) }
            }
            if (c.responseCode !in 200..299) return null
            return JSONObject(c.inputStream.bufferedReader().readText())
        } finally {
            c.disconnect()
        }
    }

    // ---------------------------------------------------------------- sections

    private fun metaJson(ctx: Context): JSONObject {
        val rt = Runtime.getRuntime()
        return JSONObject()
            .put("name", DashboardPrefs.name(ctx).ifBlank { "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}" })
            .put("model", android.os.Build.MODEL).put("android", "Android ${android.os.Build.VERSION.RELEASE}")
            .put("vpn", Tracker.running.value).put("guard", AvState.enabled.value)
            .put("mem", (rt.totalMemory() - rt.freeMemory()) / 1_048_576).put("threads", Thread.activeCount())
    }

    private fun trafficJson(): JSONObject {
        val now = System.currentTimeMillis()
        val fresh = now - LiveBridge.at < 10_000
        val list = if (fresh) LiveBridge.apps else emptyList()
        val arr = JSONArray()
        for (a in list.filter { it.up + it.down > 0 || it.active || it.outside > 0 }.take(60)) {
            val cs = JSONArray()
            for (c in a.conns.take(6)) {
                cs.put(
                    JSONObject().put("d", c.dest).put("ip", c.ip).put("p", c.port).put("pr", c.proto)
                        .put("u", c.up).put("dn", c.down).put("r", c.rate)
                        .put("url", c.url?.take(160) ?: JSONObject.NULL).put("a", c.active).put("l", c.last)
                )
            }
            arr.put(
                JSONObject().put("uid", a.uid).put("pkg", a.pkg).put("label", a.label).put("sys", a.system)
                    .put("u", a.up).put("dn", a.down).put("r", a.rate).put("a", a.active)
                    .put("fg", a.foreground ?: JSONObject.NULL).put("dl", a.downloading)
                    .put("l", a.last).put("out", a.outside).put("c", cs)
            )
        }
        return JSONObject().put("t", now).put("run", Tracker.running.value).put("session", Tracker.sessionStart)
            .put("stale", !fresh).put("down", list.sumOf { it.down }).put("up", list.sumOf { it.up })
            .put("activeApps", list.count { it.active }).put("apps", arr)
    }

    private fun avJson(ctx: Context): JSONObject {
        val st = AvState.status.value
        val cn = AvState.counts.value
        val f = JSONArray()
        for (x in AvState.findings.value.sortedWith(compareByDescending<Finding> { it.level }.thenByDescending { it.score }).take(100)) {
            f.put(
                JSONObject().put("id", x.id).put("k", x.kind).put("t", x.title).put("s", x.sub).put("sc", x.score)
                    .put("lv", x.level).put("rs", JSONArray(x.reasons.take(6))).put("pkg", x.pkg ?: JSONObject.NULL)
                    .put("path", x.path ?: JSONObject.NULL)
            )
        }
        val po = JSONArray()
        for (p in AvState.posture.value) po.put(JSONObject().put("t", p.title).put("d", p.detail).put("ok", p.ok).put("sev", p.severity))
        val th = JSONArray()
        for (t in AvState.netThreats.value.take(40)) {
            th.put(JSONObject().put("label", t.label).put("pkg", t.pkg ?: JSONObject.NULL).put("domain", t.domain).put("family", t.family).put("time", t.time))
        }
        val q = JSONArray()
        for (i in AvState.quarantine.value.take(40)) q.put(JSONObject().put("name", i.name).put("size", i.size).put("time", i.time))
        return JSONObject().put("enabled", AvState.enabled.value).put("score", AvState.score.value)
            .put("note", AvState.note.value ?: JSONObject.NULL)
            .put("status", JSONObject().put("state", st.state).put("mode", st.mode).put("phase", st.phase).put("done", st.done)
                .put("total", st.total).put("note", st.note).put("started", st.started).put("finished", st.finished))
            .put("counts", JSONObject().put("apps", cn.apps).put("files", cn.files).put("lastScan", cn.lastScan).put("cloud", cn.cloud))
            .put("guard", JSONObject().put("running", AvGuardState.running.value).put("watched", AvGuardState.watched.value)
                .put("last", AvGuardState.last.value).put("events", AvGuardState.events.value).put("integrity", AvGuardState.integrity.value))
            .put("findings", f).put("posture", po).put("threats", th).put("quarantine", q)
    }

    /** Cleaner: only totals and group sizes, never file names or paths. */
    private fun cleanJson(): JSONObject {
        val s = CleanerState.status.value
        val g = CleanerState.groups.value
        val top = JSONArray()
        for (x in g.sortedByDescending { it.size * it.files.size }.take(10)) {
            top.put(JSONObject().put("size", x.size).put("n", x.files.size).put("type", x.type))
        }
        return JSONObject().put("state", s.state).put("phase", s.phase).put("done", s.done).put("total", s.total)
            .put("note", s.note).put("groups", g.size)
            .put("reclaim", g.sumOf { it.toDelete().sumOf { f -> f.size } }).put("top", top)
    }

    private fun sysJson(ctx: Context): JSONObject {
        val granted = Fg.granted(ctx)
        val o = JSONObject().put("granted", granted).put("hours", 24)
        if (!granted) return o
        val arr = JSONArray()
        for (a in SysStats.load(ctx, 24).sortedByDescending { it.rx.sum() + it.tx.sum() }.take(60)) {
            arr.put(
                JSONObject().put("label", a.label).put("pkg", a.pkg).put("sys", a.system)
                    .put("rx", JSONArray(a.rx.toList())).put("tx", JSONArray(a.tx.toList()))
            )
        }
        val out = JSONArray()
        try {
            for ((a, b) in SysStats.outsideList(ctx).take(20)) out.put(JSONObject().put("label", a.label).put("pkg", a.pkg).put("b", b))
        } catch (_: Exception) {
        }
        return o.put("apps", arr).put("outside", out)
    }

    private fun histJson(ctx: Context): JSONObject {
        val arr = JSONArray()
        for (a in History.loadSince(ctx).sortedByDescending { it.down + it.up }.take(60)) {
            val ds = JSONArray()
            for (d in a.dests.take(8)) {
                ds.put(JSONObject().put("d", d.dest).put("p", d.port).put("pr", d.proto).put("u", d.up).put("dn", d.down).put("bg", d.bgDown))
            }
            arr.put(
                JSONObject().put("label", a.label).put("pkg", a.pkg).put("sys", a.system)
                    .put("fgUp", a.fgUp).put("bgUp", a.bgUp).put("unUp", a.unUp)
                    .put("fgDn", a.fgDown).put("bgDn", a.bgDown).put("unDn", a.unDown).put("dests", ds)
            )
        }
        val days = JSONArray()
        for (d in History.days(ctx)) days.put(JSONObject().put("day", d.day).put("j", History.jalali(d.day)).put("up", d.up).put("dn", d.down).put("apps", d.apps))
        return JSONObject().put("apps", arr).put("days", days)
    }
}
