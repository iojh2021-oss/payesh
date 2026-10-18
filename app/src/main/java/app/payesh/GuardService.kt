package app.payesh

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Real-time protection: checks every newly installed/updated app at once, watches new APK files in
 * download folders, and alerts when an app gets a dangerous capability (Accessibility, Device Admin,
 * notification access).
 */
class GuardService : Service() {
    companion object { const val ACTION_STOP = "app.payesh.GUARD_STOP" }

    private var sched: ScheduledExecutorService? = null
    private var recv: BroadcastReceiver? = null
    @Volatile private var lastApk = 0L
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
                .setContentTitle("آنتی‌ویروس پایش").setContentText("محافظت لحظه‌ای فعال است")
                .setContentIntent(pi).setOngoing(true).build()
            if (Build.VERSION.SDK_INT >= 34) startForeground(2, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(2, n)
        } catch (e: Exception) {
            Plog.w("guard foreground failed: $e")
        }
    }

    private fun begin() {
        lastApk = System.currentTimeMillis()
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
        sched = Executors.newSingleThreadScheduledExecutor().also {
            it.scheduleWithFixedDelay({
                try {
                    tick++
                    if (tick == 1 || tick % 360 == 0) AvDbStore.updateIfDue(this)
                    if (tick % 2 == 0) scanNewFiles()
                    if (tick % 5 == 0) behaviorCheck()
                } catch (e: Exception) {
                    Plog.w("guard tick failed: $e")
                }
            }, 60, 60, TimeUnit.SECONDS)
        }
        Plog.w("guard started")
    }

    private fun shutdown() {
        sched?.shutdownNow()
        sched = null
        try { recv?.let { unregisterReceiver(it) } } catch (_: Exception) {}
        recv = null
    }

    private fun onPkg(i: Intent) {
        val pkg = i.data?.schemeSpecificPart ?: return
        if (i.action == Intent.ACTION_PACKAGE_ADDED && i.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        sched?.execute { checkPackage(pkg) }
    }

    private fun checkPackage(pkg: String) {
        try {
            val env = AvEnv(this)
            if (pkg == env.self || pkg in env.trusted) return
            val pi = packageManager.getPackageInfo(pkg, Av.FLAGS)
            val label = pi.applicationInfo?.loadLabel(packageManager)?.toString() ?: pkg
            val f = Av.analyze(env, pi, label, true, true)
            Plog.w("guard: $pkg score=${f.score}")
            if (f.level > 0) AvNotify.alert(
                this, pkg.hashCode(),
                if (f.level == 2) "⚠ برنامهٔ خطرناک نصب شد" else "برنامهٔ مشکوک نصب شد",
                "$label (ریسک ${f.score}): ${f.reasons.firstOrNull() ?: ""}"
            )
        } catch (e: Exception) {
            Plog.w("guard pkg failed: $e")
        }
    }

    private fun walk(dir: File, depth: Int, cb: (File) -> Unit) {
        val list = try { dir.listFiles() } catch (_: Exception) { null } ?: return
        for (f in list) {
            if (f.isDirectory) { if (depth > 0 && f.name !in Av.SKIP_DIRS) walk(f, depth - 1, cb) }
            else if (f.isFile) cb(f)
        }
    }

    private fun scanNewFiles() {
        if (!Dedup.hasAccess(this)) return
        val since = lastApk - 5_000
        lastApk = System.currentTimeMillis()
        val env = AvEnv(this)
        for (r in Dedup.roots(this)) for (d in Av.SMART_DIRS) {
            val dir = File(r, d)
            if (!dir.isDirectory) continue
            walk(dir, 3) { f ->
                if (f.lastModified() > since && f.path !in env.trusted) {
                    Av.analyzeFile(env, f)?.let {
                        AvNotify.alert(
                            this, f.path.hashCode(),
                            if (it.level == 2) "⚠ فایل خطرناک پیدا شد" else "فایل مشکوک پیدا شد",
                            "${it.title}: ${it.reasons.firstOrNull() ?: ""}"
                        )
                    }
                }
            }
        }
    }

    /** Alerts when a new Accessibility service / Device Admin / notification listener appears. */
    private fun behaviorCheck() {
        val env = AvEnv(this)
        val now = HashSet<String>()
        env.a11y.forEach { now.add("a:$it") }
        env.admins.forEach { now.add("d:$it") }
        env.notif.forEach { now.add("n:$it") }
        val prev = AvPrefs.snapshot(this)
        AvPrefs.setSnapshot(this, now)
        if (prev == null) return
        for (e in now - prev) {
            val pkg = e.substring(2)
            if (pkg == env.self || env.isSystem(pkg) || pkg in env.trusted) continue
            val what = when (e[0]) {
                'a' -> "سرویس Accessibility"
                'd' -> "دسترسی مدیر دستگاه"
                else -> "دسترسی خواندن اعلان‌ها"
            }
            AvNotify.alert(this, e.hashCode(), "دسترسی حساس جدید", "${env.label(pkg)}: $what فعال شد. اگر خودت انجام نداده‌ای، برنامه را بررسی یا حذف کن.")
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
