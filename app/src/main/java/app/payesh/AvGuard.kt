package app.payesh

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.FileObserver
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/** Live status of the real-time guard, shown in the antivirus tab. */
object AvGuardState {
    val watched = MutableStateFlow(0)
    val last = MutableStateFlow("—")
    val running = MutableStateFlow(false)   // is the guard service alive?
    val events = MutableStateFlow(0)        // file events seen since the service started
    val note = MutableStateFlow("—")        // last notification attempt
    val integrity = MutableStateFlow(0)     // number of system-integrity indicators found
    val budget = MutableStateFlow(0)        // max folders the watcher is allowed to use
    val mediaEvents = MutableStateFlow(0)   // new files reported by the MediaStore observer
}

/**
 * Instant detection of new files: one inotify watch per download-like folder (and its sub-folders).
 * Fires when a file is completely written or renamed into place (e.g. Chrome's .crdownload -> .apk).
 * Uses the native (Rust) inotify watcher when available, otherwise falls back to FileObserver.
 */
class DownloadWatcher(private val onFile: (File) -> Unit) {
    private val observers = HashMap<String, FileObserver>()
    private val nativeDirs = HashMap<String, Int>() // native mode: dir path -> remaining depth
    private val recent = HashMap<String, Long>()
    private val mask = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO or FileObserver.CREATE
    private var nh = 0L
    private var th: Thread? = null
    @Volatile private var running = false

    fun count(): Int = synchronized(this) { if (nh != 0L) nativeDirs.size else observers.size }

    /** How many folders we may watch: half of the system inotify limit (read at runtime), within sane bounds. */
    private val budget: Int by lazy {
        val sys = try { File("/proc/sys/fs/inotify/max_user_watches").readText().trim().toInt() } catch (_: Exception) { 0 }
        if (sys > 0) (sys / 2).coerceIn(300, 6_000) else 1_500
    }

    private fun forbidden(dir: File): Boolean {
        val p = dir.path
        // other apps' private folders are not accessible to us since Android 11 (even with all-files access)
        return p.contains("/Android/data") || p.contains("/Android/obb")
    }

    @Synchronized
    fun start(roots: List<File>) {
        if (nh == 0L && observers.isEmpty() && NativeEngine.ok) startNative()
        // pass 1: priority folders first, so they can never be starved by the budget
        for (r in roots) for (d in Av.SMART_DIRS) addTree(File(r, d), 5)
        // pass 2: every other visible folder (hidden ones included: malware likes them), then the storage root itself
        for (r in roots) {
            r.listFiles()?.filter { it.isDirectory && it.name != "Android" }?.forEach { addTree(it, 3) }
            addTree(r, 0)
        }
        AvGuardState.watched.value = count()
        AvGuardState.budget.value = budget
    }

    fun stop() {
        var h = 0L
        var t: Thread? = null
        synchronized(this) {
            h = nh; t = th
            nh = 0L; th = null; running = false
            observers.values.forEach { it.stopWatching() }
            observers.clear()
            nativeDirs.clear()
        }
        if (h != 0L) {
            try {
                NativeEngine.watchWake(h)
                t?.join(3_000)
                // never free while the reader thread might still be inside the native call
                if (t == null || !t!!.isAlive) NativeEngine.watchFree(h)
            } catch (_: Throwable) {}
        }
        AvGuardState.watched.value = 0
    }

    private fun startNative() {
        val h = try { NativeEngine.watchCreate() } catch (_: Throwable) { 0L }
        if (h == 0L) return
        nh = h
        running = true
        th = Thread({ nativeLoop(h) }, "guard-inotify").also { it.isDaemon = true; it.start() }
        Plog.w("guard: native inotify watcher active")
    }

    private fun nativeLoop(h: Long) {
        try {
            while (running) {
                val ev = NativeEngine.watchNext(h, 1_000) ?: break
                for (s in ev) onNative(s)
            }
        } catch (e: Throwable) {
            Plog.w("native watch loop failed: $e")
        }
    }

    private fun onNative(s: String) {
        if (!running) return
        val i = s.indexOf('|')
        if (i < 0) return
        val m = s.substring(0, i).toIntOrNull() ?: return
        val p = s.substring(i + 1)
        if (p.isEmpty()) return // queue overflow: the guard's periodic poll is the safety net
        val f = File(p)
        if ((m and 0x40000000) != 0) { // IN_ISDIR: a new sub-folder
            val d = synchronized(this) { nativeDirs[f.parent ?: ""] } ?: 0
            if (d > 0) addTree(f, d - 1)
            AvGuardState.watched.value = count()
            return
        }
        if ((m and (0x8 or 0x80)) == 0) return // only CLOSE_WRITE / MOVED_TO
        val now = System.currentTimeMillis()
        synchronized(recent) {
            if ((recent[f.path] ?: 0L) > now - 3_000) return
            recent[f.path] = now
            if (recent.size > 500) recent.clear()
        }
        onFile(f)
    }

    @Synchronized
    private fun addTree(dir: File, depth: Int) {
        if (!dir.isDirectory || dir.name in Av.SKIP_DIRS || forbidden(dir)) return
        val watched = dir.path in observers || dir.path in nativeDirs
        if (!watched) {
            if (count() >= budget) return
            if (nh != 0L) {
                if (NativeEngine.watchAdd(nh, dir.path) < 0) return
                nativeDirs[dir.path] = depth
            } else {
                val o = object : FileObserver(dir, mask) {
                    override fun onEvent(event: Int, path: String?) {
                        if (path == null) return
                        val f = File(dir, path)
                        if (f.isDirectory) {
                            if (depth > 0) addTree(f, depth - 1)
                            AvGuardState.watched.value = observers.size
                            return
                        }
                        if ((event and (FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO)) == 0) return
                        val now = System.currentTimeMillis()
                        synchronized(recent) {
                            if ((recent[f.path] ?: 0L) > now - 3_000) return
                            recent[f.path] = now
                            if (recent.size > 500) recent.clear()
                        }
                        onFile(f)
                    }
                }
                o.startWatching()
                observers[dir.path] = o
            }
        }
        // also for folders that are already watched: a periodic start() then finds sub-folders that were skipped earlier
        if (depth > 0) dir.listFiles()?.filter { it.isDirectory }?.forEach { addTree(it, depth - 1) }
    }
}

object AvGuard {
    const val ACT_SCAN = "app.payesh.G_SCAN"
    const val ACT_DELETE = "app.payesh.G_DELETE"
    const val ACT_QUAR = "app.payesh.G_QUAR"
    const val ACT_IGNORE = "app.payesh.G_IGNORE"

    /** path -> (finding or null when nothing suspicious, time) */
    val results = ConcurrentHashMap<String, Pair<Finding?, Long>>()

    fun nid(path: String) = (path.hashCode() and 0x7fffffff) + 100

    fun action(ctx: Context, title: String, act: String, path: String, nid: Int): Notification.Action {
        val i = Intent(ctx, GuardActionReceiver::class.java).setAction(act).putExtra("path", path).putExtra("nid", nid)
        val pi = PendingIntent.getBroadcast(ctx, (act + path).hashCode(), i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Action.Builder(Icon.createWithResource(ctx, R.drawable.ic_notif), title, pi).build()
    }

    /** Ask the user before scanning a freshly downloaded APK (like AVG's download shield). */
    fun askScan(ctx: Context, f: File, who: String?) {
        val id = nid(f.path)
        AvNotify.post(
            ctx, id, "فایل APK دانلود شد؛ قبل از نصب اسکن شود؟",
            "«${f.name}» (${fmt(f.length())})" + (who?.let { "\n$it" } ?: "") +
                "\nبرای اسکن امن قبل از نصب، «اسکن الان» را بزن.",
            true, listOf(action(ctx, "اسکن الان", ACT_SCAN, f.path, id), action(ctx, "نادیده", ACT_IGNORE, f.path, id))
        )
    }

    /** Scan a file now and report: clean / suspicious / malicious with the reasons. */
    fun scanAndNotify(ctx: Context, f: File, who: String?) {
        if (!f.isFile) return
        val r = try { Av.analyzeFile(AvEnv(ctx), f) } catch (_: Exception) { null }
        results[f.path] = r to System.currentTimeMillis()
        val id = nid(f.path)
        val src = who?.let { "\n$it" } ?: ""
        if (r == null || r.level == 0) {
            AvNotify.post(
                ctx, id, "✓ مورد مشکوکی پیدا نشد",
                "«${f.name}» اسکن شد و طبق پایگاه تهدیدها و تحلیل رفتاری مشکوک نیست. این به معنای تضمین سالم بودن نیست.$src",
                false
            )
        } else {
            val head = if (r.level == 2) "⚠ فایل مخرب است؛ نصب نکن" else "⚠ فایل مشکوک است"
            AvNotify.post(
                ctx, id, head,
                "«${r.title}» (ریسک ${r.score})\n" + r.reasons.take(5).joinToString("\n") { "• $it" } + src,
                true, listOf(action(ctx, "حذف فایل", ACT_DELETE, f.path, id), action(ctx, "قرنطینه", ACT_QUAR, f.path, id))
            )
        }
    }

    /** Best guess which app downloaded something just now, from the VPN network monitor. */
    fun guessDownloader(ctx: Context): String? {
        if (!Tracker.running.value) return null
        val now = System.currentTimeMillis()
        var bestUid = Int.MIN_VALUE
        var best = 0L
        for (u in Tracker.uids.values) for (c in u.conns.values) {
            if (now - c.last < 20_000 && c.down.get() >= 100_000 && c.down.get() > best) { best = c.down.get(); bestUid = u.uid }
        }
        if (bestUid == Int.MIN_VALUE) return null
        val pm = ctx.packageManager
        val pkg = try { pm.getPackagesForUid(bestUid)?.firstOrNull() } catch (_: Exception) { null } ?: return null
        return try { pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString() } catch (_: Exception) { pkg }
    }
}

/** Handles the buttons on guard notifications (scan now / delete / quarantine / ignore). */
class GuardActionReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, i: Intent) {
        val path = i.getStringExtra("path") ?: return
        val nid = i.getIntExtra("nid", 0)
        val act = i.action
        val app = ctx.applicationContext
        val pending = goAsync()
        thread(name = "guard-action") {
            try {
                val nm = app.getSystemService(NotificationManager::class.java)
                val f = File(path)
                when (act) {
                    AvGuard.ACT_SCAN -> { nm.cancel(nid); AvGuard.scanAndNotify(app, f, null) }
                    AvGuard.ACT_IGNORE -> nm.cancel(nid)
                    AvGuard.ACT_DELETE -> {
                        val ok = f.delete()
                        nm.cancel(nid)
                        AvNotify.post(app, nid, if (ok) "فایل حذف شد" else "حذف فایل ناموفق بود", f.name, false)
                    }
                    AvGuard.ACT_QUAR -> {
                        nm.cancel(nid)
                        val fnd = Finding(path, 1, f.name, path, 0, 0, emptyList(), path = path)
                        val ok = AvState.quarantineFile(app, fnd)
                        AvNotify.post(app, nid, if (ok) "فایل به قرنطینه رفت" else "قرنطینهٔ فایل ناموفق بود", f.name + (if (ok) "\nاز تب آنتی‌ویروس می‌توانی بازگردانی یا حذف همیشگی کنی." else ""), false)
                    }
                }
            } catch (e: Exception) {
                Plog.w("guard action failed: $e")
            } finally {
                pending.finish()
            }
        }
    }
}
