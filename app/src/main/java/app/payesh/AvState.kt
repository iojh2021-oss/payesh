package app.payesh

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files

data class AvStatus(
    val state: Int = 0, // 0 idle, 1 scanning, 2 finished
    val mode: Int = 0,  // 0 smart, 1 full
    val phase: String = "", val done: Int = 0, val total: Int = 0, val note: String = "",
    val started: Long = 0, val finished: Long = 0
)

data class AvCounts(val apps: Int = 0, val files: Int = 0, val lastScan: Long = 0, val cloud: Int = 0)

data class NetThreat(val uid: Int, val label: String, val pkg: String?, val domain: String, val family: String, val time: Long)

data class QItem(val id: String, val orig: String, val name: String, val size: Long, val time: Long)

object AvPrefs {
    private fun p(ctx: Context) = ctx.applicationContext.getSharedPreferences("payesh_av", Context.MODE_PRIVATE)

    // sha256 of the standard EICAR test file
    private const val EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    fun enabled(ctx: Context) = p(ctx).getBoolean("enabled", false)
    fun setEnabled(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("enabled", v).apply()

    /** Ask before scanning a freshly downloaded APK (default) instead of scanning automatically. */
    fun askBeforeScan(ctx: Context) = p(ctx).getBoolean("ask_scan", true)
    fun setAskBeforeScan(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("ask_scan", v).apply()

    fun vtEnabled(ctx: Context) = p(ctx).getBoolean("vt_on", false)
    fun vtKey(ctx: Context) = p(ctx).getString("vt_key", "") ?: ""
    fun setVt(ctx: Context, on: Boolean, key: String) = p(ctx).edit().putBoolean("vt_on", on).putString("vt_key", key).apply()

    fun lastScan(ctx: Context) = p(ctx).getLong("last_scan", 0L)
    fun setLastScan(ctx: Context, t: Long) = p(ctx).edit().putLong("last_scan", t).apply()

    fun trusted(ctx: Context): Set<String> = HashSet(p(ctx).getStringSet("trusted", emptySet()) ?: emptySet())
    fun trust(ctx: Context, id: String) {
        val s = trusted(ctx).toMutableSet()
        s.add(id)
        p(ctx).edit().putStringSet("trusted", s).apply()
    }

    fun snapshot(ctx: Context): Set<String>? = p(ctx).getStringSet("snap", null)?.let { HashSet(it) }
    fun setSnapshot(ctx: Context, s: Set<String>) = p(ctx).edit().putStringSet("snap", s).apply()

    private fun sigFile(ctx: Context) = File(ctx.applicationContext.filesDir, "signatures.txt")

    private fun parseSig(line: String): Pair<String, String>? {
        val t = line.trim()
        if (t.length < 64) return null
        val h = t.substring(0, 64).lowercase()
        if (!h.all { it in '0'..'9' || it in 'a'..'f' }) return null
        val name = t.substring(64).trim(' ', ',', ';', '\t').ifEmpty { "Malware" }
        return h to name
    }

    fun signatures(ctx: Context): Map<String, String> {
        val m = HashMap<String, String>()
        m[EICAR] = "EICAR-Test-File"
        try {
            val f = sigFile(ctx)
            if (f.exists()) f.forEachLine { l -> parseSig(l)?.let { m[it.first] = it.second } }
        } catch (_: Exception) {
        }
        return m
    }

    fun sigCount(ctx: Context) = signatures(ctx).size

    /** Adds hashes from a text file (one SHA-256 per line, optional name after it). Returns the number added. */
    fun importSignatures(ctx: Context, uri: Uri): Int {
        var added = 0
        try {
            val known = signatures(ctx).keys
            val sb = StringBuilder()
            ctx.contentResolver.openInputStream(uri)?.bufferedReader()?.useLines { lines ->
                for (l in lines) {
                    val s = parseSig(l) ?: continue
                    if (s.first !in known) { sb.append(s.first).append(',').append(s.second).append('\n'); added++ }
                }
            }
            if (sb.isNotEmpty()) sigFile(ctx).appendText(sb.toString())
        } catch (_: Exception) {
        }
        return added
    }

    fun quarantine(ctx: Context): List<QItem> = try {
        val a = JSONArray(p(ctx).getString("quarantine", "[]"))
        (0 until a.length()).map {
            val o = a.getJSONObject(it)
            QItem(o.getString("id"), o.getString("orig"), o.getString("name"), o.optLong("size"), o.optLong("time"))
        }
    } catch (_: Exception) { emptyList() }

    fun saveQuarantine(ctx: Context, list: List<QItem>) {
        val a = JSONArray()
        list.forEach {
            a.put(JSONObject().put("id", it.id).put("orig", it.orig).put("name", it.name).put("size", it.size).put("time", it.time))
        }
        p(ctx).edit().putString("quarantine", a.toString()).apply()
    }
}

object AvNotify {
    /** high = heads-up alert channel, otherwise the quiet info channel. Actions are the buttons under the text. */
    fun post(ctx: Context, id: Int, title: String, text: String, high: Boolean, actions: List<Notification.Action> = emptyList()) {
        try {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel("av_alerts", "هشدار آنتی‌ویروس", NotificationManager.IMPORTANCE_HIGH))
            nm.createNotificationChannel(NotificationChannel("av_info", "اطلاعیه‌های آنتی‌ویروس", NotificationManager.IMPORTANCE_DEFAULT))
            val pi = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            val b = Notification.Builder(ctx, if (high) "av_alerts" else "av_info")
                .setSmallIcon(R.drawable.ic_notif).setContentTitle(title).setContentText(text.lines().first())
                .setStyle(Notification.BigTextStyle().bigText(text)).setContentIntent(pi).setAutoCancel(true)
            actions.forEach { b.addAction(it) }
            nm.notify(id, b.build())
        } catch (_: Exception) {
        }
    }

    fun alert(ctx: Context, id: Int, title: String, text: String) = post(ctx, id, title, text, true)
}

/** Process-wide antivirus state; scans keep running while you browse other pages. */
object AvState {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val status = MutableStateFlow(AvStatus())
    val findings = MutableStateFlow<List<Finding>>(emptyList())
    val posture = MutableStateFlow<List<Posture>>(emptyList())
    val enabled = MutableStateFlow(false)
    val counts = MutableStateFlow(AvCounts())
    val quarantine = MutableStateFlow<List<QItem>>(emptyList())
    val score = MutableStateFlow(-1)
    val note = MutableStateFlow<String?>(null)
    val netThreats = MutableStateFlow<List<NetThreat>>(emptyList())
    private val reported = HashSet<String>()
    @Volatile private var cancel = false
    private var job: Job? = null
    private var inited = false

    fun init(ctx: Context) {
        if (inited) return
        inited = true
        val app = ctx.applicationContext
        enabled.value = AvPrefs.enabled(app)
        quarantine.value = AvPrefs.quarantine(app)
        counts.value = AvCounts(0, 0, AvPrefs.lastScan(app))
        if (enabled.value) startGuard(app)
        scope.launch {
            try { posture.value = Av.posture(app, AvEnv(app)) } catch (_: Exception) {}
            try { AvDbStore.updateIfDue(app) } catch (_: Exception) {}
        }
    }

    fun startGuard(ctx: Context) {
        try { ctx.startForegroundService(Intent(ctx, GuardService::class.java)) } catch (e: Exception) { Plog.w("guard start failed: $e") }
    }

    fun setEnabled(ctx: Context, on: Boolean) {
        val app = ctx.applicationContext
        AvPrefs.setEnabled(app, on)
        enabled.value = on
        if (on) startGuard(app)
        else try { app.startService(Intent(app, GuardService::class.java).setAction(GuardService.ACTION_STOP)) } catch (_: Exception) {}
    }

    fun cancelScan() { cancel = true }

    /** Live web protection: matches what apps contact (SNI / DNS seen by the VPN monitor) against malicious domains. */
    fun checkTraffic(ctx: Context) {
        val app = ctx.applicationContext
        val db = AvDbStore.load(app)
        if (db.domains.isEmpty()) return
        val pm = app.packageManager
        for (u in Tracker.uids.values) for (c in u.conns.values) {
            val url = c.url
            val host = if (c.port == 53 && url != null && url.startsWith("DNS: ")) url.removePrefix("DNS: ") else (c.domain ?: Tracker.dns[c.ip])
            if (host == null) continue
            val fam = db.domainHit(host) ?: continue
            val key = "${u.uid}|$host"
            if (!reported.add(key)) continue
            val pkg = try { pm.getPackagesForUid(u.uid)?.firstOrNull() } catch (_: Exception) { null }
            val label = if (pkg != null) try { pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString() } catch (_: Exception) { pkg } else "نامشخص (uid ${u.uid})"
            netThreats.value = listOf(NetThreat(u.uid, label, pkg, host, fam, System.currentTimeMillis())) + netThreats.value.take(99)
            AvNotify.alert(app, key.hashCode(), "⚠ ارتباط با دامنهٔ مخرب", "$label به $host ($fam) وصل شد")
            Plog.w("netguard: $label -> $host ($fam)")
        }
    }

    fun scan(ctx: Context, mode: Int) {
        if (job?.isActive == true) return
        val app = ctx.applicationContext
        cancel = false
        note.value = null
        job = scope.launch {
            val started = System.currentTimeMillis()
            fun st(phase: String, d: Int = 0, t: Int = 0, n: String = "") {
                status.value = AvStatus(1, mode, phase, d, t, n, started, 0)
            }
            val byId = LinkedHashMap<String, Finding>()
            var files = 0
            var cloud = 0
            try {
                val env = AvEnv(app)
                st("بررسی وضعیت امنیتی دستگاه")
                posture.value = Av.posture(app, env)

                // 1) installed apps: permissions, behavior, certificate, installer, payload, signature hash
                val pm = app.packageManager
                val names = pm.getInstalledApplications(0).map { it.packageName }
                for ((i, pkg) in names.withIndex()) {
                    if (cancel) break
                    if (i % 3 == 0) st("تحلیل برنامه‌ها (رفتار، دسترسی‌ها، امضا)", i, names.size, pkg)
                    if (pkg == env.self) continue
                    val pi = try { pm.getPackageInfo(pkg, Av.FLAGS) } catch (_: Exception) { continue }
                    val label = try { pi.applicationInfo?.loadLabel(pm)?.toString() ?: pkg } catch (_: Exception) { pkg }
                    byId[pkg] = Av.analyze(env, pi, label, true, mode == 1)
                }

                // 2) files: APKs, disguised executables, double extensions, ELF/DEX, EICAR, known hashes
                if (!cancel) {
                    if (Dedup.hasAccess(app)) {
                        st("اسکن فایل‌ها (APK، فایل‌های پنهان‌شده، اجرایی)")
                        val roots = Dedup.roots(app)
                        val skip = HashSet<String>()
                        for (r in roots) { skip.add(File(r, "Android/data").path); skip.add(File(r, "Android/obb").path) }
                        val stack = java.util.ArrayDeque<File>()
                        if (mode == 1) roots.forEach { stack.push(it) }
                        else for (r in roots) for (d in Av.SMART_DIRS) { val f = File(r, d); if (f.isDirectory) stack.push(f) }
                        while (stack.isNotEmpty() && !cancel) {
                            val dir = stack.pop()
                            val list = (try { dir.listFiles() } catch (_: Exception) { null }) ?: continue
                            for (f in list) {
                                try {
                                    if (Files.isSymbolicLink(f.toPath())) continue
                                    if (f.isDirectory) {
                                        if (f.path !in skip && f.name !in Av.SKIP_DIRS) stack.push(f)
                                    } else if (f.isFile) {
                                        files++
                                        if (files % 250 == 0) st("اسکن فایل‌ها", files, 0, dir.path)
                                        Av.analyzeFile(env, f)?.let { byId[it.id] = it }
                                    }
                                } catch (_: Exception) {
                                }
                            }
                        }
                    } else {
                        note.value = ((note.value?.let { "$it • " }) ?: "") + "برای اسکن فایل‌ها دسترسی «همهٔ فایل‌ها» لازم است (تب پاکسازی)"
                    }
                }

                val flagged = byId.values.filter { it.id !in env.trusted && it.level > 0 }.sortedByDescending { it.score }
                findings.value = flagged
                val now = System.currentTimeMillis()
                counts.value = AvCounts(byId.values.count { it.kind == 0 } + 1, files, now, cloud)
                AvPrefs.setLastScan(app, now)
                score.value = Av.score(flagged, posture.value)
                status.value = AvStatus(2, mode, "", 0, 0, "", started, now)
            } catch (e: Exception) {
                Plog.w("av scan failed: $e")
                note.value = "اسکن با خطا متوقف شد"
                status.value = AvStatus()
            }
        }
    }

    private fun refresh() { score.value = if (counts.value.lastScan == 0L) -1 else Av.score(findings.value, posture.value) }

    fun trust(ctx: Context, id: String) {
        AvPrefs.trust(ctx, id)
        findings.value = findings.value.filter { it.id != id }
        refresh()
    }

    private fun move(src: File, dst: File): Boolean {
        dst.parentFile?.mkdirs()
        if (src.renameTo(dst)) return true
        return try { src.copyTo(dst, overwrite = false); src.delete(); true } catch (_: Exception) { false }
    }

    fun quarantineFile(ctx: Context, f: Finding): Boolean {
        val path = f.path ?: return false
        val src = File(path)
        if (!src.isFile) return false
        val id = System.currentTimeMillis().toString()
        val dst = File(File(ctx.filesDir, "quarantine"), "${id}_${src.name}.quar")
        val size = src.length()
        if (!move(src, dst)) return false
        val list = AvPrefs.quarantine(ctx) + QItem(id, path, src.name, size, System.currentTimeMillis())
        AvPrefs.saveQuarantine(ctx, list)
        quarantine.value = list
        findings.value = findings.value.filter { it.id != f.id }
        refresh()
        return true
    }

    fun deleteFile(f: Finding): Boolean {
        val path = f.path ?: return false
        val ok = File(path).delete()
        if (ok) { findings.value = findings.value.filter { it.id != f.id }; refresh() }
        return ok
    }

    fun restore(ctx: Context, q: QItem): Boolean {
        val src = File(File(ctx.filesDir, "quarantine"), "${q.id}_${q.name}.quar")
        var dst = File(q.orig)
        if (dst.exists()) dst = File(dst.parentFile, "restored_${q.name}")
        val ok = move(src, dst)
        if (ok) {
            val list = AvPrefs.quarantine(ctx).filter { it.id != q.id }
            AvPrefs.saveQuarantine(ctx, list)
            quarantine.value = list
        }
        return ok
    }

    fun deleteQuarantined(ctx: Context, q: QItem) {
        File(File(ctx.filesDir, "quarantine"), "${q.id}_${q.name}.quar").delete()
        val list = AvPrefs.quarantine(ctx).filter { it.id != q.id }
        AvPrefs.saveQuarantine(ctx, list)
        quarantine.value = list
    }
}
