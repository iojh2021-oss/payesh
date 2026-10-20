package app.payesh

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Real-time protection:
 *  - every install / update of an app that did not come from Google Play -> notification with the scan result
 *  - every new file in download folders -> instant detection; APKs: "scan before install?" prompt (or auto-scan)
 *  - when the system package-installer screen opens -> reminder / verdict for the latest downloaded APK
 *  - new Accessibility / Device Admin / notification-listener grants -> alert
 */
class GuardService : Service() {
    companion object {
        const val ACTION_STOP = "app.payesh.GUARD_STOP"
        private val TEMP_EXT = setOf("crdownload", "part", "tmp", "download", "partial", "temp", "opdownload", "aria2")
        private val APK_EXT = setOf("apk", "xapk", "apks", "apkm")
        private val INSTALLERS = setOf(
            "com.google.android.packageinstaller", "com.android.packageinstaller",
            "com.samsung.android.packageinstaller", "com.miui.packageinstaller"
        )
        private val STORE_NAMES = mapOf(
            "com.android.vending" to "Google Play", "com.sec.android.app.samsungapps" to "Galaxy Store",
            "com.huawei.appmarket" to "AppGallery", "com.xiaomi.mipicks" to "Xiaomi GetApps",
            "com.amazon.venezia" to "Amazon Appstore", "org.fdroid.fdroid" to "F-Droid",
            "com.farsitel.bazaar" to "کافه‌بازار", "ir.mservices.market" to "مایکت",
            "com.heytap.market" to "OPPO Store", "com.oppo.market" to "OPPO Store", "com.vivo.appstore" to "vivo Store"
        )
    }

    private var sched: ScheduledExecutorService? = null
    private var work: ExecutorService? = null
    private var recv: BroadcastReceiver? = null
    private var watcher: DownloadWatcher? = null
    private val handled: MutableSet<String> = java.util.Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())
    private val recentApks = ConcurrentLinkedDeque<Pair<String, Long>>()
    @Volatile private var lastInstallerAlert = 0L
    @Volatile private var lastPoll = 0L
    @Volatile private var envCache: AvEnv? = null
    @Volatile private var envAt = 0L
    private var tick = 0

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Plog.init(this)
        if (intent?.action == ACTION_STOP) {
            shutdown(); stopForegroundCompat(); stopSelf(); return START_NOT_STICKY
        }
        goForeground()
        if (sched == null) begin()
        return START_STICKY
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun stopForegroundCompat() { try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Exception) {} }

    private fun goForeground() {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel("guard", "محافظ آنتی‌ویروس", NotificationManager.IMPORTANCE_LOW))
            val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            val n = Notification.Builder(this, "guard").setSmallIcon(R.drawable.ic_notif)
                .setContentTitle("آنتی‌ویروس پایش").setContentText("محافظت لحظه‌ای فعال است: نصب‌ها و دانلودها زیر نظر است")
                .setContentIntent(pi).setOngoing(true).build()
            if (Build.VERSION.SDK_INT >= 34) startForeground(2, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(2, n)
        } catch (e: Exception) {
            Plog.w("guard foreground failed: $e")
        }
    }

    private fun env(): AvEnv {
        val now = System.currentTimeMillis()
        synchronized(this) {
            val c = envCache
            if (c != null && now - envAt < 60_000) return c
            val e = AvEnv(this)
            envCache = e
            envAt = now
            return e
        }
    }

    private fun begin() {
        lastPoll = System.currentTimeMillis()
        work = Executors.newFixedThreadPool(2)
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) { onPkg(i) }
        }
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(r, f, Context.RECEIVER_EXPORTED) else registerReceiver(r, f)
        recv = r
        startWatcher()
        sched = Executors.newSingleThreadScheduledExecutor().also {
            it.scheduleWithFixedDelay({
                try { loop() } catch (e: Exception) { Plog.w("guard loop failed: $e") }
            }, 3, 3, TimeUnit.SECONDS)
        }
        Plog.w("guard started")
    }

    private fun shutdown() {
        sched?.shutdownNow(); sched = null
        work?.shutdownNow(); work = null
        watcher?.stop(); watcher = null
        try { recv?.let { unregisterReceiver(it) } } catch (_: Exception) {}
        recv = null
    }

    private fun startWatcher() {
        watcher?.stop()
        watcher = null
        if (!Dedup.hasAccess(this)) { AvGuardState.watched.value = 0; return }
        val w = DownloadWatcher { onNewFile(it) }
        w.start(Dedup.roots(this))
        watcher = w
        Plog.w("guard watching ${w.count()} folders")
    }

    /** Runs every 3 seconds. */
    private fun loop() {
        tick++
        checkInstaller()
        if (tick % 7 == 0) pollFiles()
        if (tick % 40 == 0 && (watcher?.count() ?: 0) == 0 && Dedup.hasAccess(this)) startWatcher()
        if (tick % 100 == 0) { behaviorCheck(); watcher?.start(Dedup.roots(this)) } // also picks up newly created folders
        if (tick == 10 || tick % 7200 == 0) AvDbStore.updateIfDue(this)
    }

    // ------------------------------------------------------------------ app installs

    private fun onPkg(i: Intent) {
        val pkg = i.data?.schemeSpecificPart ?: return
        val replaced = i.action == Intent.ACTION_PACKAGE_REPLACED
        if (!replaced && i.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        work?.execute { checkPackage(pkg, replaced) }
    }

    @Suppress("DEPRECATION")
    private fun installSource(pkg: String): Pair<String?, String?> = try {
        if (Build.VERSION.SDK_INT >= 30) {
            val s = packageManager.getInstallSourceInfo(pkg)
            s.installingPackageName to s.initiatingPackageName
        } else packageManager.getInstallerPackageName(pkg) to null
    } catch (_: Exception) { null to null }

    private fun describe(installer: String?, initiator: String?): String {
        val e = env()
        val base = if (installer == null) "نصب دستی (APK / منبع ناشناس)"
        else if (installer in STORE_NAMES) "فروشگاه ${STORE_NAMES[installer]}"
        else if (installer.contains("packageinstaller")) "نصب دستی (APK)"
        else "نصب‌کننده: ${e.label(installer)}"
        val ini = if (initiator != null && initiator != installer && initiator != packageName) " • توسط ${e.label(initiator)}" else ""
        return base + ini
    }

    private fun checkPackage(pkg: String, replaced: Boolean) {
        try {
            val e = env()
            if (pkg == e.self) return
            val pi = packageManager.getPackageInfo(pkg, Av.FLAGS)
            val label = pi.applicationInfo?.loadLabel(packageManager)?.toString() ?: pkg
            val (installer, initiator) = installSource(pkg)
            val fromPlay = installer == "com.android.vending"
            val f = Av.analyze(e, pi, label, true, true)
            Plog.w("guard: ${if (replaced) "update" else "install"} $pkg installer=$installer score=${f.score}")
            AvGuardState.last.value = "${if (replaced) "بروزرسانی" else "نصب"}: $label"
            val src = describe(installer, initiator)
            val what = if (replaced) "بروزرسانی شد" else "نصب شد"
            if (f.level > 0 && pkg !in e.trusted) {
                AvNotify.post(
                    this, pkg.hashCode(),
                    if (f.level == 2) "⚠ برنامهٔ خطرناک $what" else "برنامهٔ مشکوک $what",
                    "$label (ریسک ${f.score})\n$src\n" + f.reasons.take(4).joinToString("\n") { "• $it" }, true
                )
            } else if (!fromPlay) {
                AvNotify.post(
                    this, pkg.hashCode(),
                    "برنامه از منبع غیر Google Play $what",
                    "$label\n$src\nنتیجهٔ اسکن خودکار: مورد مشکوکی پیدا نشد (ریسک ${f.score})", false
                )
            }
        } catch (e: Exception) {
            Plog.w("guard pkg failed: $e")
        }
    }

    // ------------------------------------------------------------------ downloads

    private fun onNewFile(f: File) {
        val ext = f.name.substringAfterLast('.', "").lowercase()
        if (ext in TEMP_EXT) return
        if (!handled.add(f.path + "|" + f.lastModified())) return
        if (handled.size > 2000) handled.clear()
        work?.execute { handleFile(f, ext) }
    }

    private fun handleFile(f: File, ext: String) {
        try {
            if (!f.isFile || f.length() < 64) return
            val ask = AvPrefs.askBeforeScan(this)
            if (ext in APK_EXT) {
                recentApks.addFirst(f.path to System.currentTimeMillis())
                while (recentApks.size > 20) recentApks.pollLast()
                AvGuardState.last.value = "APK دانلودی: ${f.name}"
                val who = AvGuard.guessDownloader(this)?.let { "احتمالاً توسط «$it» دانلود شد (بر اساس رصد شبکه)" }
                if (ask) AvGuard.askScan(this, f, who) else AvGuard.scanAndNotify(this, f, who)
            } else {
                AvGuardState.last.value = f.name
                val r = Av.analyzeFile(env(), f)
                if (r != null && r.level > 0 && f.path !in env().trusted)
                    AvNotify.post(
                        this, AvGuard.nid(f.path), if (r.level == 2) "⚠ فایل مخرب پیدا شد" else "فایل مشکوک پیدا شد",
                        "«${r.title}»\n" + r.reasons.take(4).joinToString("\n") { "• $it" }, true,
                        listOf(
                            AvGuard.action(this, "حذف فایل", AvGuard.ACT_DELETE, f.path, AvGuard.nid(f.path)),
                            AvGuard.action(this, "قرنطینه", AvGuard.ACT_QUAR, f.path, AvGuard.nid(f.path))
                        )
                    )
            }
        } catch (e: Exception) {
            Plog.w("guard file failed: $e")
        }
    }

    private fun walk(dir: File, depth: Int, cb: (File) -> Unit) {
        val list = try { dir.listFiles() } catch (_: Exception) { null } ?: return
        for (f in list) {
            if (f.isDirectory) { if (depth > 0 && f.name !in Av.SKIP_DIRS) walk(f, depth - 1, cb) }
            else if (f.isFile) cb(f)
        }
    }

    /** Safety net in case an inotify event is missed (e.g. folders we could not watch). */
    private fun pollFiles() {
        if (!Dedup.hasAccess(this)) return
        val since = lastPoll - 5_000
        lastPoll = System.currentTimeMillis()
        for (r in Dedup.roots(this)) for (d in Av.SMART_DIRS) {
            val dir = File(r, d)
            if (!dir.isDirectory) continue
            walk(dir, 2) { f ->
                if (f.lastModified() > since && f.name.substringAfterLast('.', "").lowercase() in APK_EXT) onNewFile(f)
            }
        }
        for (r in Dedup.roots(this)) walk(r, 1) { f ->
            if (f.lastModified() > since && f.name.substringAfterLast('.', "").lowercase() in APK_EXT) onNewFile(f)
        }
    }

    // ------------------------------------------------------------------ installer screen

    /** Detects the system package-installer screen coming to the front (needs Usage access). */
    private fun checkInstaller() {
        if (!Fg.granted(this)) return
        val usm = getSystemService(UsageStatsManager::class.java) ?: return
        val now = System.currentTimeMillis()
        val ev = usm.queryEvents(now - 4_000, now)
        val e = UsageEvents.Event()
        var hit = false
        while (ev.hasNextEvent()) {
            ev.getNextEvent(e)
            if (e.eventType == UsageEvents.Event.ACTIVITY_RESUMED && e.packageName in INSTALLERS) hit = true
        }
        if (hit && now - lastInstallerAlert > 20_000) {
            lastInstallerAlert = now
            work?.execute { onInstallerOpened() }
        }
    }

    private fun onInstallerOpened() {
        try {
            val now = System.currentTimeMillis()
            val cand = recentApks.firstOrNull { now - it.second < 15 * 60_000 && File(it.first).isFile }
            if (cand == null) {
                AvNotify.post(
                    this, 3, "نصب برنامه در حال شروع است",
                    "فایل APK تازه‌ای در پوشه‌های دانلود پیدا نشد. بعد از نصب، برنامه به‌صورت خودکار اسکن می‌شود.", false
                )
                return
            }
            val f = File(cand.first)
            val cached = AvGuard.results[f.path]
            val who = AvGuard.guessDownloader(this)?.let { "احتمالاً توسط «$it» دانلود شده" }
            if (cached == null) {
                if (AvPrefs.askBeforeScan(this)) AvGuard.askScan(this, f, who) else AvGuard.scanAndNotify(this, f, who)
            } else AvGuard.scanAndNotify(this, f, who) // re-report the stored verdict right before the install
        } catch (e: Exception) {
            Plog.w("installer check failed: $e")
        }
    }

    // ------------------------------------------------------------------ dangerous capability grants

    /** Alerts when a new Accessibility service / Device Admin / notification listener appears. */
    private fun behaviorCheck() {
        val e = AvEnv(this)
        val now = HashSet<String>()
        e.a11y.forEach { now.add("a:$it") }
        e.admins.forEach { now.add("d:$it") }
        e.notif.forEach { now.add("n:$it") }
        val prev = AvPrefs.snapshot(this)
        AvPrefs.setSnapshot(this, now)
        if (prev == null) return
        for (x in now - prev) {
            val pkg = x.substring(2)
            if (pkg == e.self || e.isSystem(pkg) || pkg in e.trusted) continue
            val what = when (x[0]) {
                'a' -> "سرویس Accessibility"
                'd' -> "دسترسی مدیر دستگاه"
                else -> "دسترسی خواندن اعلان‌ها"
            }
            AvNotify.post(
                this, x.hashCode(), "دسترسی حساس جدید",
                "${e.label(pkg)}: $what فعال شد. اگر خودت انجام نداده‌ای، برنامه را بررسی یا حذف کن.", true
            )
        }
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED && AvPrefs.enabled(ctx)) {
            try { ctx.startForegroundService(Intent(ctx, GuardService::class.java)) } catch (_: Exception) {}
        }
    }
}
