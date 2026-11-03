package app.payesh

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Base64
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Updates Payesh from inside itself, from the public GitHub release "latest" of this repository.
 * The CI publishes payesh.apk + update.json (version, SHA-256, size) + update.json.mldsa (post-quantum signature).
 * Checks before anything is installed:
 *  1. update.json must be for this package and the download URL must stay inside this repository's releases;
 *  2. if the ML-DSA public key is bundled in the APK, update.json must carry a valid ML-DSA-65 signature;
 *  3. the downloaded APK must match the SHA-256 and size of update.json;
 *  4. the APK must be signed by the same key as the installed app (Android enforces this again at install time).
 * Android 12+ may install a self-update without a prompt (USER_ACTION_NOT_REQUIRED); if the phone still wants a confirmation,
 * the confirmation is shown (on a button press) or offered in a notification (automatic mode).
 */
object AppUpdater {
    private const val PREF = "app_updater"
    private const val ACTION = "app.payesh.UPDATE_STATUS"
    private const val REPO_RELEASES = "https://github.com/iojh2021-oss/payesh/releases/download/"
    private const val FEED = REPO_RELEASES + "latest/"

    class Info(val versionCode: Long, val versionName: String, val sha256: String, val size: Long, val url: String, val notes: String)

    val status = MutableStateFlow("")
    val progress = MutableStateFlow(-1)
    val latest = MutableStateFlow<Info?>(null)
    @Volatile var autoCheck = false
    @Volatile var autoInstall = false
    private val running = AtomicBoolean(false)
    private var inited = false

    fun init(ctx: Context) {
        if (inited) return
        inited = true
        val sp = ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE)
        autoCheck = sp.getBoolean("auto", false)
        autoInstall = sp.getBoolean("auto_install", false)
    }

    fun save(ctx: Context) {
        ctx.applicationContext.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean("auto", autoCheck).putBoolean("auto_install", autoInstall).apply()
    }

    @Suppress("DEPRECATION")
    fun installedCode(ctx: Context): Long = try { ctx.packageManager.getPackageInfo(ctx.packageName, 0).longVersionCode } catch (_: Exception) { 0L }
    fun installedName(ctx: Context): String = try { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "?" } catch (_: Exception) { "?" }
    fun canInstall(ctx: Context): Boolean = try { ctx.packageManager.canRequestPackageInstalls() } catch (_: Exception) { false }
    fun settingsIntent(ctx: Context): Intent =
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + ctx.packageName)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    private fun hex(b: ByteArray): String {
        val sb = StringBuilder()
        for (x in b) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }

    private fun readLimited(c: java.net.HttpURLConnection, max: Int): ByteArray? {
        c.connectTimeout = 15_000
        c.readTimeout = 20_000
        if (c.responseCode != 200) return null
        val out = java.io.ByteArrayOutputStream()
        c.inputStream.use { ins ->
            val buf = ByteArray(8192)
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
                if (out.size() > max) return null
            }
        }
        return out.toByteArray()
    }

    /** ML-DSA-65 signature of update.json, enforced only when the public key is bundled in the APK. */
    private fun pqOk(app: Context, body: ByteArray): Boolean {
        val pem = try { app.assets.open(MlDsa.ASSET).bufferedReader().use { it.readText() } } catch (_: Exception) { return true }
        val raw = MlDsa.rawKey(pem)
        if (raw == null) { status.value = "کلید عمومی ML-DSA داخل برنامه خراب است؛ به‌روزرسانی رد شد"; return false }
        val sigB64 = readLimited(Pq.open(FEED + "update.json.mldsa"), 8192)
        if (sigB64 == null) { status.value = "امضای پسا‌کوانتومی به‌روزرسانی پیدا نشد؛ رد شد"; return false }
        val sig = try { Base64.decode(String(sigB64, Charsets.UTF_8).trim(), Base64.DEFAULT) } catch (_: Exception) { null }
        if (sig == null || !MlDsa.verify(raw, body, sig)) {
            status.value = "امضای ML-DSA به‌روزرسانی نامعتبر است؛ رد شد (${MlDsa.lastError.ifEmpty { "نامشخص" }})"
            return false
        }
        return true
    }

    /** Blocking: call from a background thread. */
    fun check(ctx: Context): Info? {
        val app = ctx.applicationContext
        status.value = "در حال بررسی..."
        val body = try { readLimited(Pq.open(FEED + "update.json"), 65_536) } catch (e: Exception) {
            status.value = "اتصال ناموفق: " + e.javaClass.simpleName; return null
        }
        if (body == null) { status.value = "هنوز نسخه‌ای منتشر نشده یا اطلاعات نسخه دریافت نشد"; return null }
        if (!pqOk(app, body)) return null
        return try {
            val j = JSONObject(String(body, Charsets.UTF_8))
            require(j.optString("kind") == "app-update") { "نوع فایل درست نیست" }
            require(j.optString("package") == app.packageName) { "بستهٔ دیگری است" }
            val info = Info(j.getLong("versionCode"), j.getString("versionName"), j.getString("sha256").lowercase(), j.getLong("size"), j.getString("url"), j.optString("notes"))
            require(info.url.startsWith(REPO_RELEASES)) { "آدرس دانلود خارج از ریپو است" }
            require(Regex("[0-9a-f]{64}").matches(info.sha256)) { "هش نامعتبر" }
            require(info.size in 1..200_000_000L) { "اندازه نامعتبر" }
            latest.value = info
            status.value = if (info.versionCode > installedCode(app)) "نسخهٔ جدید ${info.versionName} آماده است" else "نسخهٔ نصب‌شده به‌روز است (${installedName(app)})"
            info
        } catch (e: Exception) {
            status.value = "اطلاعات نسخه معتبر نیست: " + (e.message ?: e.javaClass.simpleName)
            null
        }
    }

    private fun certDigests(info: android.content.pm.PackageInfo?): Set<String>? {
        val signers = info?.signingInfo?.apkContentsSigners ?: return null
        return signers.map { hex(MessageDigest.getInstance("SHA-256").digest(it.toByteArray())) }.toSet()
    }

    /** true = same signer or not determinable (Android itself decides at install time); false = clearly a different key. */
    private fun sameSigner(app: Context, apk: File): Boolean = try {
        val pm = app.packageManager
        val fresh = pm.getPackageArchiveInfo(apk.path, PackageManager.GET_SIGNING_CERTIFICATES)
        if (fresh != null && fresh.packageName != app.packageName) false
        else {
            val a = certDigests(pm.getPackageInfo(app.packageName, PackageManager.GET_SIGNING_CERTIFICATES))
            val b = certDigests(fresh)
            a == null || b == null || a == b
        }
    } catch (_: Exception) { true }

    /** Blocking. Returns the verified APK file or null (reason in [status]). */
    fun download(ctx: Context, info: Info): File? {
        val app = ctx.applicationContext
        val dir = File(app.cacheDir, "update").apply { mkdirs() }
        val f = File(dir, "payesh-${info.versionCode}.apk")
        dir.listFiles()?.filter { it.name != f.name }?.forEach { it.delete() }
        try {
            if (f.exists() && f.length() == info.size && hex(MessageDigest.getInstance("SHA-256").digest(f.readBytes())) == info.sha256) {
                progress.value = 100
                return f
            }
            val c = Pq.open(info.url)
            c.connectTimeout = 15_000
            c.readTimeout = 30_000
            c.instanceFollowRedirects = true
            if (c.responseCode != 200) { status.value = "دانلود ناموفق (کد ${c.responseCode})"; return null }
            val md = MessageDigest.getInstance("SHA-256")
            var total = 0L
            progress.value = 0
            c.inputStream.use { ins ->
                f.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = ins.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > info.size) throw IOException("فایل بزرگ‌تر از اندازهٔ اعلام‌شده است")
                        md.update(buf, 0, n)
                        out.write(buf, 0, n)
                        progress.value = (total * 100 / info.size).toInt()
                    }
                }
            }
            if (total != info.size || hex(md.digest()) != info.sha256) {
                f.delete(); status.value = "SHA-256 فایل با اطلاعات نسخه مطابقت ندارد؛ نصب نشد"; progress.value = -1; return null
            }
            if (!sameSigner(app, f)) {
                f.delete(); status.value = "امضای APK با نسخهٔ نصب‌شده یکی نیست؛ نصب نشد"; progress.value = -1; return null
            }
            status.value = "دانلود و راستی‌آزمایی انجام شد"
            return f
        } catch (e: Exception) {
            f.delete(); progress.value = -1
            status.value = "دانلود ناموفق: " + e.javaClass.simpleName
            return null
        }
    }

    /** Hands the verified APK to the system installer. [manual] = the user pressed the button (a confirmation may be shown right away). */
    fun install(ctx: Context, f: File, manual: Boolean) {
        val app = ctx.applicationContext
        try {
            val pi = app.packageManager.packageInstaller
            val p = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            p.setAppPackageName(app.packageName)
            p.setSize(f.length())
            if (Build.VERSION.SDK_INT >= 31) p.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            val id = pi.createSession(p)
            pi.openSession(id).use { s ->
                f.inputStream().use { ins -> s.openWrite("payesh.apk", 0, f.length()).use { out -> ins.copyTo(out); s.fsync(out) } }
                val intent = Intent(app, UpdateReceiver::class.java).setAction(ACTION).putExtra("manual", manual)
                val pend = PendingIntent.getBroadcast(app, id, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                status.value = "در حال نصب..."
                s.commit(pend.intentSender)
            }
        } catch (e: Exception) {
            status.value = "نصب ناموفق: " + e.javaClass.simpleName + (e.message?.let { " (" + it.take(60) + ")" } ?: "")
        }
    }

    private fun notifyReady(ctx: Context, text: String) {
        AvNotify.post(ctx, 4242, "به‌روزرسانی پایش", text, false)
    }

    /** Background run (from the guard loop): check, download, and either install or tell the user. */
    fun autoRun(ctx: Context) {
        if (!autoCheck || !running.compareAndSet(false, true)) return
        try {
            val app = ctx.applicationContext
            val cm = app.getSystemService(ConnectivityManager::class.java)
            if (cm != null && cm.isActiveNetworkMetered) return // no big download on mobile data
            val info = check(app) ?: return
            if (info.versionCode <= installedCode(app)) return
            val f = download(app, info) ?: return
            val fg = try { Fg.foreground(app) } catch (_: Exception) { null }
            val inUse = fg != null && app.packageName in fg
            if (autoInstall && canInstall(app) && !inUse) install(app, f, false)
            else notifyReady(app, "نسخهٔ ${info.versionName} آماده است. در برنامه (کارت به‌روزرسانی) دکمهٔ نصب را بزن.")
        } catch (e: Exception) {
            Plog.w("auto update failed: $e")
        } finally {
            running.set(false)
        }
    }
}

/** Receives the installer's answer for the update session. */
class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, i: Intent) {
        when (i.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm: Intent? = if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) else i.getParcelableExtra(Intent.EXTRA_INTENT)
                AppUpdater.status.value = "اندروید تأیید شما را برای نصب می‌خواهد"
                if (confirm != null) {
                    if (i.getBooleanExtra("manual", false)) {
                        try { ctx.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (e: Exception) { Plog.w("update confirm failed: $e") }
                    } else {
                        try {
                            val nm = ctx.getSystemService(NotificationManager::class.java)
                            nm.createNotificationChannel(NotificationChannel("av_info", "اطلاعیه‌های آنتی‌ویروس", NotificationManager.IMPORTANCE_DEFAULT))
                            val pi = PendingIntent.getActivity(ctx, 7, confirm, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                            nm.notify(4243, Notification.Builder(ctx, "av_info").setSmallIcon(R.drawable.ic_notif)
                                .setContentTitle("به‌روزرسانی پایش آماده نصب است").setContentText("برای تأیید نصب اینجا را بزن")
                                .setContentIntent(pi).setAutoCancel(true).build())
                        } catch (e: Exception) { Plog.w("update notification failed: $e") }
                    }
                }
            }
            PackageInstaller.STATUS_SUCCESS -> AppUpdater.status.value = "نصب شد"
            else -> {
                val msg = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "نامشخص"
                AppUpdater.status.value = "نصب ناموفق: $msg"
                Plog.w("update install failed: $msg")
            }
        }
    }
}
