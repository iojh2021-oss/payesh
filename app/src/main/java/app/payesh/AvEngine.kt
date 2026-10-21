package app.payesh

import android.app.AppOpsManager
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.zip.ZipFile

/** level: 0 safe, 1 suspicious, 2 dangerous. kind: 0 installed app, 1 file, 2 APK file. */
data class Finding(
    val id: String, val kind: Int, val title: String, val sub: String,
    val score: Int, val level: Int, val reasons: List<String>,
    val pkg: String? = null, val path: String? = null, val sha: String? = null, val side: Boolean = false
)

/** severity: 1 warning, 2 critical */
data class Posture(val title: String, val detail: String, val ok: Boolean, val severity: Int)

/** Everything the analyzers need to know about the device state (read once per scan). */
class AvEnv(val ctx: Context) {
    val pm: PackageManager = ctx.packageManager
    private val ops: AppOpsManager? = ctx.getSystemService(AppOpsManager::class.java)
    val self: String = ctx.packageName
    val a11y: Set<String> = enabledPkgs(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
    val notif: Set<String> = enabledPkgs("enabled_notification_listeners")
    val admins: Set<String> = try {
        (ctx.getSystemService(DevicePolicyManager::class.java).activeAdmins ?: emptyList()).map { it.packageName }.toSet()
    } catch (_: Exception) { emptySet() }
    val smsDefault: String? = try { Telephony.Sms.getDefaultSmsPackage(ctx) } catch (_: Exception) { null }
    val trusted: Set<String> = AvPrefs.trusted(ctx)
    val db: AvDb = AvDbStore.load(ctx)
    val sigs: Map<String, String> = AvPrefs.signatures(ctx) + db.hashes

    private fun enabledPkgs(key: String): Set<String> {
        val raw = try { Settings.Secure.getString(ctx.contentResolver, key) } catch (_: Exception) { null } ?: ""
        return raw.split(':').map { it.substringBefore('/') }.filter { it.isNotBlank() }.toSet()
    }

    fun op(op: String, uid: Int, pkg: String): Boolean = try {
        ops?.unsafeCheckOpNoThrow(op, uid, pkg) == AppOpsManager.MODE_ALLOWED
    } catch (_: Exception) { false }

    fun isSystem(pkg: String): Boolean = try {
        (pm.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM) != 0
    } catch (_: Exception) { false }

    fun label(pkg: String): String = try {
        pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString()
    } catch (_: Exception) { pkg }
}

class ContentRes(val c2: List<String>, val packed: List<String>)

class VtRes(val mal: Int, val susp: Int, val cached: Boolean)
class VtError(val code: Int) : Exception("VirusTotal $code")

/** Cloud reputation lookup by SHA-256 only (the file itself is never uploaded). */
object Vt {
    private fun prefs(ctx: Context) = ctx.applicationContext.getSharedPreferences("payesh_vt", Context.MODE_PRIVATE)

    fun cached(ctx: Context, sha: String): Boolean {
        val a = prefs(ctx).getString(sha, null)?.split("|") ?: return false
        return a.size == 3 && System.currentTimeMillis() - (a[2].toLongOrNull() ?: 0L) < 7 * 86_400_000L
    }

    fun lookup(ctx: Context, key: String, sha: String): VtRes {
        val p = prefs(ctx)
        if (cached(ctx, sha)) {
            val a = p.getString(sha, "0|0|0")!!.split("|")
            return VtRes(a[0].toIntOrNull() ?: 0, a[1].toIntOrNull() ?: 0, true)
        }
        val con = URL("https://www.virustotal.com/api/v3/files/$sha").openConnection() as HttpURLConnection
        con.connectTimeout = 10_000
        con.readTimeout = 15_000
        con.setRequestProperty("x-apikey", key)
        try {
            val code = con.responseCode
            var mal = 0
            var susp = 0
            if (code == 200) {
                val text = con.inputStream.bufferedReader().use { it.readText() }
                val st = JSONObject(text).getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats")
                mal = st.optInt("malicious")
                susp = st.optInt("suspicious")
            } else if (code != 404) throw VtError(code)
            p.edit().putString(sha, "$mal|$susp|${System.currentTimeMillis()}").apply()
            return VtRes(mal, susp, false)
        } finally {
            con.disconnect()
        }
    }
}

object Av {
    val FLAGS = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or
        PackageManager.GET_RECEIVERS or PackageManager.GET_SIGNING_CERTIFICATES

    val SMART_DIRS = listOf("Download", "Downloads", "Documents", "Telegram", "Bluetooth", "WhatsApp", "Android/media", "Movies", "Pictures")
    val SKIP_DIRS = setOf(".thumbnails", ".cache", ".trash", ".Trash", ".trashed", ".tmp", ".temp", ".face", ".gs_fs0")

    private val STORES = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket", "com.xiaomi.mipicks",
        "com.amazon.venezia", "org.fdroid.fdroid", "com.farsitel.bazaar", "ir.mservices.market",
        "com.heytap.market", "com.oppo.market", "com.vivo.appstore"
    )
    private val SMS = setOf(
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_MMS", "android.permission.RECEIVE_WAP_PUSH"
    )
    private val SPY = setOf(
        "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG", "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_SMS", "android.permission.PROCESS_OUTGOING_CALLS"
    )
    private val payloadRe = Regex("^(assets|res/raw|res/xml|lib)/.*\\.(apk|dex|jar)$", RegexOption.IGNORE_CASE)
    private val rootDexRe = Regex("^(?!classes\\d*\\.dex$)[^/]+\\.dex$", RegexOption.IGNORE_CASE)
    private val classesRe = Regex("classes\\d*\\.dex")
    private val dblExt = Regex("""\.(jpe?g|png|gif|pdf|mp4|mp3|docx?|xlsx?|txt)\.(apk|exe|scr|bat|js|vbs|jar|sh)$""", RegexOption.IGNORE_CASE)
    private val zipLike = setOf("apk", "zip", "jar", "xapk", "apks", "apkm", "docx", "xlsx", "pptx", "odt", "ods", "epub", "aar", "kmz")

    fun level(score: Int) = if (score >= 70) 2 else if (score >= 35) 1 else 0

    fun sha256(f: File): String? {
        if (NativeEngine.ok) NativeEngine.sha256File(f.path)?.let { return it }
        return sha256Kotlin(f)
    }

    private fun sha256Kotlin(f: File): String? = try {
        val md = MessageDigest.getInstance("SHA-256")
        FileInputStream(f).use { ins ->
            val b = ByteArray(256 * 1024)
            while (true) {
                val n = ins.read(b)
                if (n < 0) break
                md.update(b, 0, n)
            }
        }
        md.digest().joinToString("") { "%02x".format(it) }
    } catch (_: Exception) { null }

    private fun debugSigned(pi: PackageInfo): Boolean = try {
        val si = pi.signingInfo
        val signers = if (si == null) null else if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        signers?.any { s ->
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(s.toByteArray())) as X509Certificate
            cert.subjectX500Principal.name.contains("Android Debug", true)
        } == true
    } catch (_: Exception) { false }

    private fun certHashes(pi: PackageInfo): List<String> = try {
        val si = pi.signingInfo
        val signers = if (si == null) null else if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        val out = ArrayList<String>()
        signers?.forEach { s ->
            val der = s.toByteArray()
            out.add(MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) })
            out.add(MessageDigest.getInstance("SHA-1").digest(der).joinToString("") { "%02x".format(it) })
        }
        out
    } catch (_: Exception) { emptyList() }

    private val blobExt = setOf("", "dat", "bin", "data", "enc", "cfg", "res", "tmp", "lib")

    private fun feedAll(h: Long, ins: java.io.InputStream, limit: Long = Long.MAX_VALUE) {
        val b = ByteArray(64 * 1024)
        var total = 0L
        while (total < limit) {
            val r = ins.read(b)
            if (r < 0) break
            NativeEngine.scannerFeed(h, b, r)
            total += r
        }
    }

    /**
     * Native content scan of an APK: (1) known malicious domains / patterns inside the DEX code
     * (Aho-Corasick over the decompressed bytes), (2) encrypted/packed data blobs in assets (byte entropy).
     */
    fun contentScan(apkPath: String, db: AvDb): ContentRes? {
        if (!NativeEngine.ok) return null
        val pats = ArrayList<String>()
        val labels = ArrayList<String>()
        for ((d, fam) in db.domains) if (d.length >= 6) { pats.add(d); labels.add("$d ($fam)") }
        for ((p, fam) in db.patterns) { pats.add(p); labels.add("$p ($fam)") }
        return try {
            val c2 = ArrayList<String>()
            val packed = ArrayList<String>()
            ZipFile(apkPath).use { z ->
                if (pats.isNotEmpty()) {
                    val h = NativeEngine.scannerCreate(pats.toTypedArray())
                    if (h != 0L) try {
                        val e = z.entries()
                        while (e.hasMoreElements()) {
                            val en = e.nextElement()
                            if (!en.name.endsWith(".dex", true) || en.size > 80_000_000L) continue
                            z.getInputStream(en).use { ins -> feedAll(h, ins) }
                        }
                        for (i in NativeEngine.scannerMatches(h)) if (i in labels.indices) c2.add(labels[i])
                    } finally {
                        NativeEngine.scannerFree(h)
                    }
                }
                val e2 = z.entries()
                while (e2.hasMoreElements()) {
                    val en = e2.nextElement()
                    val n = en.name
                    if (en.isDirectory || en.size < 30_000 || !(n.startsWith("assets/") || n.startsWith("res/raw/"))) continue
                    val file = n.substringAfterLast('/')
                    if (file.contains('.') && file.substringAfterLast('.').lowercase() !in blobExt) continue
                    val h = NativeEngine.scannerCreate(emptyArray())
                    if (h == 0L) continue
                    try {
                        z.getInputStream(en).use { ins -> feedAll(h, ins, 256 * 1024) }
                        if (NativeEngine.scannerEntropy(h) >= 7.6) packed.add(file)
                    } finally {
                        NativeEngine.scannerFree(h)
                    }
                }
            }
            ContentRes(c2, packed)
        } catch (_: Exception) {
            null
        }
    }

    /** One pass over the APK entries: (embedded executable payload?, known indicator file name from the database). */
    private fun inspectApk(apkPath: String, indicators: Map<String, String>): Pair<Boolean, String?> = try {
        ZipFile(apkPath).use { z ->
            val e = z.entries()
            var payload = false
            var fam: String? = null
            while (e.hasMoreElements()) {
                val n = e.nextElement().name
                if (payloadRe.containsMatchIn(n) || rootDexRe.containsMatchIn(n)) payload = true
                if (fam == null && indicators.isNotEmpty()) fam = indicators[n.substringAfterLast('/').lowercase()]
            }
            payload to fam
        }
    } catch (_: Exception) { false to null }

    /** Multi-layer static + behavioral analysis of one app (installed or an APK file). */
    @Suppress("DEPRECATION")
    fun analyze(env: AvEnv, pi: PackageInfo, label: String, installed: Boolean, hashAll: Boolean): Finding {
        val ai = pi.applicationInfo
        val pkg = pi.packageName
        val reasons = ArrayList<String>()
        var score = 0
        fun add(n: Int, r: String) { score += n; reasons.add(r) }

        val perms = pi.requestedPermissions?.toSet() ?: emptySet()
        val system = installed && ai != null && (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val installer: String? = if (!installed) null else try {
            if (Build.VERSION.SDK_INT >= 30) env.pm.getInstallSourceInfo(pkg).installingPackageName
            else env.pm.getInstallerPackageName(pkg)
        } catch (_: Exception) { null }
        val fromStore = installer != null && installer in STORES
        val sideloaded = !system && !fromStore
        val uid = ai?.uid ?: -1

        val a11yDecl = pi.services?.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" } == true
        val notifDecl = pi.services?.any { it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" } == true
        val adminDecl = pi.receivers?.any { it.permission == "android.permission.BIND_DEVICE_ADMIN" } == true
        val a11yOn = installed && pkg in env.a11y
        val adminOn = installed && pkg in env.admins
        val notifOn = installed && pkg in env.notif
        val overlayOn = installed && env.op("android:system_alert_window", uid, pkg)
        val installPerm = "android.permission.REQUEST_INSTALL_PACKAGES" in perms
        val hasNet = "android.permission.INTERNET" in perms
        val hidden = installed && !system && env.pm.getLaunchIntentForPackage(pkg) == null

        if (a11yOn) add(30, "سرویس دسترسی‌پذیری (Accessibility) فعال است؛ مسیر اصلی بدافزارهای بانکی و جاسوسی")
        else if (a11yDecl && sideloaded) add(15, "سرویس Accessibility تعریف کرده (هنوز فعال نیست)")
        if (adminOn) add(30, "مدیر دستگاه (Device Admin) فعال است؛ حذف برنامه را سخت می‌کند")
        else if (adminDecl && sideloaded) add(10, "درخواست مدیر دستگاه دارد")
        if (notifOn) add(15, "به همهٔ اعلان‌ها دسترسی دارد (امکان خواندن کدهای پیامکی/OTP)")
        else if (notifDecl && sideloaded) add(6, "سرویس شنود اعلان‌ها تعریف کرده")
        if (overlayOn) add(10 + (if (a11yOn || a11yDecl) 15 else 0), "اجازهٔ نمایش روی برنامه‌های دیگر (Overlay)" + if (a11yOn || a11yDecl) " همراه با Accessibility؛ الگوی حملهٔ پوششی" else "")

        val sms = perms.count { it in SMS }
        if (sms > 0 && pkg != env.smsDefault) add(15, "دسترسی پیامک بدون اینکه برنامهٔ پیش‌فرض پیامک باشد")
        if (sms > 0 && (a11yOn || a11yDecl || overlayOn)) add(20, "ترکیب پیامک + Accessibility/Overlay؛ الگوی تروجان بانکی")
        if (installPerm && sideloaded) add(12, "می‌تواند برنامهٔ دیگر نصب کند (الگوی Dropper)")
        if (hidden && hasNet) add(12, "آیکون ندارد (پنهان) ولی به اینترنت دسترسی دارد")
        if (hidden && (a11yOn || adminOn || a11yDecl || adminDecl)) add(18, "برنامهٔ پنهان با دسترسی‌های حساس؛ الگوی استاکرویر")
        val spy = perms.count { it in SPY }
        if (spy >= 5 && sideloaded) add(15, "درخواست بیش‌ازحد دسترسی‌های حساس ($spy مورد)")
        if (sideloaded) add(8, "از فروشگاه معتبر نصب نشده (نصب دستی / منبع ناشناس)")
        val dbg = sideloaded && pkg != env.self && debugSigned(pi)
        if (dbg) add(12, "با گواهی Debug اندروید امضا شده (برنامهٔ منتشرنشده یا دستکاری‌شده)")
        if (sideloaded && ai != null && ai.targetSdkVersion < 23) add(10, "targetSdk قدیمی (کمتر از ۲۳): مجوزها بدون پرسش داده می‌شود؛ ترفند رایج بدافزار")
        if (!system && !fromStore && (pkg.startsWith("com.google.") || pkg.startsWith("com.android.") || pkg.startsWith("com.samsung.")))
            add(20, "نام پکیج شبیه برنامه‌های گوگل/سیستمی است ولی از منبع معتبر نیامده (جعل هویت)")

        var sha: String? = null
        var payload = false
        var packerFam: String? = null
        var c2hit = false
        var packedBlob = false
        if (ai != null && (hashAll || sideloaded)) {
            val path = ai.sourceDir
            if (path != null) {
                sha = sha256(File(path))
                val (pl, fam) = inspectApk(path, env.db.entries)
                if (sideloaded && pl) { payload = true; add(20, "فایل اجرایی یا APK داخل بستهٔ برنامه تعبیه شده (Payload)") }
                if (fam != null) { packerFam = fam; add(15, "نشانهٔ شناخته‌شده داخل APK (پایگاه تهدیدها): $fam") }
                if (sideloaded) {
                    val cs = contentScan(path, env.db)
                    if (cs != null) {
                        if (cs.c2.isNotEmpty()) {
                            c2hit = true
                            add(60, "دامنهٔ مخرب شناخته‌شده داخل کد برنامه: " + cs.c2.take(3).joinToString("، "))
                            if (cs.c2.size >= 2) add(20, "چند نشانهٔ شبکه‌ای مخرب در کد (${cs.c2.size} مورد)")
                        }
                        if (cs.packed.isNotEmpty()) {
                            packedBlob = true
                            add(12, "فایل داده با آنتروپی بسیار بالا (احتمالاً رمز/بسته‌بندی‌شده): " + cs.packed.take(2).joinToString("، "))
                        }
                    }
                }
            }
        }
        if (installed && sideloaded && score >= 25 && System.currentTimeMillis() - pi.firstInstallTime < 48 * 3_600_000L)
            add(5, "تازه (کمتر از ۴۸ ساعت) نصب شده")

        // dynamic (over-the-air) database: package / certificate blacklists + declarative behavior rules
        var forced = false
        env.db.pkgs[pkg]?.let { forced = true; add(100, "پکیج در فهرست بدافزار پایگاه تهدیدها: $it") }
        if (env.db.certs.isNotEmpty()) {
            val bad = certHashes(pi).firstNotNullOfOrNull { env.db.certs[it] }
            if (bad != null) { forced = true; add(100, "گواهی امضا در فهرست سیاه پایگاه تهدیدها: $bad") }
        }
        if (env.db.rules.isNotEmpty()) {
            val feat = HashSet<String>()
            fun f(c: Boolean, n: String) { if (c) feat.add(n) }
            f(a11yOn, "a11y_on"); f(a11yDecl, "a11y_decl"); f(adminOn, "admin_on"); f(adminDecl, "admin_decl")
            f(notifOn, "notif_on"); f(notifDecl, "notif_decl"); f(overlayOn, "overlay_on"); f(hidden, "hidden")
            f(sideloaded, "sideloaded"); f(fromStore, "from_store"); f(system, "system"); f(hasNet, "net")
            f(installPerm, "install_perm"); f(sms > 0, "sms_any"); f(sms > 0 && pkg != env.smsDefault, "sms_not_default")
            f(dbg, "debug_cert"); f(payload, "payload"); f(spy >= 5, "spy_many"); f(packerFam != null, "packer"); f(c2hit, "c2_domain"); f(packedBlob, "packed_blob")
            f(sideloaded && ai != null && ai.targetSdkVersion < 23, "old_target")
            for (pn in perms) feat.add("perm:" + pn.substringAfterLast('.'))
            for (r in env.db.rules) if (r.matches(feat)) add(r.score, "قانون پایگاه تهدیدها: ${r.name}")
        }

        var s = score
        if (fromStore) s = (s * 0.6).toInt()
        if (system) s = (s * 0.35).toInt()
        val sigName = sha?.let { env.sigs[it] }
        if (sigName != null) { s = 100; reasons.add(0, "مطابقت با پایگاه امضای بدافزار: $sigName") }
        if (forced) s = 100
        s = s.coerceIn(0, 100)
        return Finding(pkg, 0, label, pkg, s, level(s), reasons, pkg = pkg, sha = sha, side = sideloaded)
    }

    fun withCloud(f: Finding, mal: Int, susp: Int): Finding {
        var s = f.score
        val r = f.reasons.toMutableList()
        if (mal >= 3) { s = 100; r.add(0, "$mal موتور آنتی‌ویروس در VirusTotal این فایل را بدافزار تشخیص داده‌اند") }
        else if (mal >= 1 || susp >= 3) { s += 35; r.add(0, "VirusTotal: $mal تشخیص بدافزار / $susp مشکوک") }
        s = s.coerceIn(0, 100)
        return f.copy(score = s, level = level(s), reasons = r)
    }

    private fun innerExecutable(f: File): String? = try {
        ZipFile(f).use { z ->
            var res: String? = null
            val e = z.entries()
            while (e.hasMoreElements()) {
                val n = e.nextElement().name
                if (n == "AndroidManifest.xml" || classesRe.matches(n)) { res = "APK"; break }
                if (n.endsWith(".apk", true)) res = "حاوی APK"
            }
            res
        }
    } catch (_: Exception) { null }

    /** File-level checks: EICAR, disguised executables, double extensions, APK files, ELF/DEX, signature hashes. */
    fun analyzeFile(env: AvEnv, f: File): Finding? {
        val name = f.name
        val ext = name.substringAfterLast('.', "").lowercase()
        val len = f.length()
        if (len < 64) return null
        val reasons = ArrayList<String>()
        var score = 0
        fun add(n: Int, r: String) { score += n; reasons.add(r) }

        if (len <= 2048) {
            val txt = try { f.readText(Charsets.ISO_8859_1) } catch (_: Exception) { "" }
            if (txt.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"))
                return Finding(f.path, 1, name, f.path, 100, 2,
                    listOf("فایل تست استاندارد EICAR؛ بی‌خطر است ولی همهٔ آنتی‌ویروس‌ها آن را برای آزمایش تهدید اعلام می‌کنند"), path = f.path)
        }
        val head = ByteArray(4)
        val n = try { FileInputStream(f).use { it.read(head) } } catch (_: Exception) { -1 }
        if (n < 4 && !dblExt.containsMatchIn(name)) return null
        fun b(i: Int) = head[i].toInt() and 0xff
        val pk = n >= 4 && b(0) == 0x50 && b(1) == 0x4B && b(2) == 3 && b(3) == 4
        val elf = n >= 4 && b(0) == 0x7F && b(1) == 'E'.code && b(2) == 'L'.code && b(3) == 'F'.code
        val dex = n >= 4 && b(0) == 'd'.code && b(1) == 'e'.code && b(2) == 'x'.code && b(3) == 10
        val mz = n >= 2 && b(0) == 'M'.code && b(1) == 'Z'.code

        if (dblExt.containsMatchIn(name)) add(40, "پسوند دوگانهٔ فریب‌دهنده ($name)")
        if (pk && ext !in zipLike) {
            val inner = innerExecutable(f)
            if (inner != null) add(70, "فایل با پسوند «$ext» در واقع بستهٔ $inner است (پنهان‌سازی)")
        }
        if (elf) add(25, "فایل اجرایی ELF در حافظهٔ مشترک (غیرعادی)")
        if (dex) add(30, "فایل DEX مستقل (کد اجرایی اندروید)")
        if (mz && (ext == "exe" || ext == "scr" || ext == "dll")) add(20, "فایل اجرایی ویندوز روی گوشی")

        var title = name
        var kind = 1
        var extraReasons: List<String> = emptyList()
        var apkScore = 0
        var sha: String? = null
        if (ext == "apk" && pk) {
            val pi = try { env.pm.getPackageArchiveInfo(f.path, FLAGS) } catch (_: Exception) { null }
            if (pi != null) {
                pi.applicationInfo?.let { it.sourceDir = f.path; it.publicSourceDir = f.path }
                val label = try { pi.applicationInfo?.loadLabel(env.pm)?.toString() } catch (_: Exception) { null } ?: pi.packageName
                val fa = analyze(env, pi, label, false, true)
                apkScore = fa.score
                extraReasons = fa.reasons
                sha = fa.sha
                title = "$label (APK دانلودی)"
                kind = 2
            } else add(20, "فایل APK خراب یا نامعتبر")
        }
        if (sha == null && (elf || dex || mz || ext == "apk" || (pk && ext !in zipLike && score >= 70))) sha = sha256(f)
        val sig = sha?.let { env.sigs[it] }
        var total = maxOf(score, apkScore)
        val all = ArrayList(reasons).also { it.addAll(extraReasons) }
        if (sig != null) { total = 100; all.add(0, "مطابقت با پایگاه امضای بدافزار: $sig") }
        total = total.coerceIn(0, 100)
        if (total < 35) return null
        return Finding(f.path, kind, title, f.path, total, level(total), all, path = f.path, sha = sha)
    }

    fun posture(ctx: Context, env: AvEnv): List<Posture> {
        val out = ArrayList<Posture>()
        val cr = ctx.contentResolver
        val secure = try { ctx.getSystemService(KeyguardManager::class.java).isDeviceSecure } catch (_: Exception) { true }
        out.add(Posture("قفل صفحه", if (secure) "فعال است" else "رمز / الگو / اثر انگشت تنظیم نشده", secure, 2))

        val patch = Build.VERSION.SECURITY_PATCH
        val age = try {
            (System.currentTimeMillis() - SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(patch)!!.time) / 86_400_000L
        } catch (_: Exception) { -1L }
        out.add(Posture("وصلهٔ امنیتی اندروید", "تاریخ $patch" + if (age >= 0) " ($age روز پیش)" else "", age < 0 || age <= 180, 1))

        val adb = try { Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1 } catch (_: Exception) { false }
        out.add(Posture("اشکال‌زدایی USB", if (adb) "روشن است؛ در صورت دسترسی فیزیکی خطرناک است" else "خاموش است", !adb, 1))

        val verifier = try { Settings.Global.getInt(cr, "package_verifier_enable", -1) } catch (_: Exception) { -1 }
        if (verifier != -1) out.add(Posture("Google Play Protect", if (verifier == 1) "بررسی برنامه‌ها فعال است" else "غیرفعال است", verifier == 1, 1))

        val rootHints = ArrayList<String>()
        if (Build.TAGS?.contains("test-keys") == true) rootHints.add("test-keys")
        for (p in listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/app/Superuser.apk"))
            if (File(p).exists()) rootHints.add(p.substringAfterLast('/'))
        for (p in listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu"))
            try { env.pm.getPackageInfo(p, 0); rootHints.add(p.substringAfterLast('.')) } catch (_: Exception) {}
        out.add(Posture("علائم روت / دستکاری سیستم", if (rootHints.isEmpty()) "نشانه‌ای پیدا نشد" else rootHints.joinToString("، "), rootHints.isEmpty(), 1))

        fun list(title: String, pkgs: Collection<String>, why: String) {
            val user = pkgs.filter { it != env.self && !env.isSystem(it) }
            out.add(Posture(title, if (user.isEmpty()) "موردی نیست" else user.take(6).joinToString("، ") { env.label(it) } + why, user.isEmpty(), 1))
        }
        list("سرویس‌های Accessibility فعال", env.a11y, "")
        list("مدیران دستگاه فعال", env.admins, "")
        list("برنامه‌هایی که اعلان‌ها را می‌خوانند", env.notif, "")

        val installers = ArrayList<String>()
        val overlays = ArrayList<String>()
        try {
            for (ai in env.pm.getInstalledApplications(0)) {
                if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 || ai.packageName == env.self) continue
                if (env.op("android:request_install_packages", ai.uid, ai.packageName)) installers.add(ai.packageName)
                if (env.op("android:system_alert_window", ai.uid, ai.packageName)) overlays.add(ai.packageName)
            }
        } catch (_: Exception) {}
        list("اجازهٔ نصب برنامه از منبع ناشناس", installers, "")
        list("اجازهٔ نمایش روی برنامه‌های دیگر", overlays, "")
        return out
    }

    fun score(findings: List<Finding>, posture: List<Posture>): Int {
        var s = 100
        s -= findings.count { it.level == 2 } * 25
        s -= findings.count { it.level == 1 } * 8
        s -= posture.filter { !it.ok }.sumOf { it.severity * 4 }
        return s.coerceIn(0, 100)
    }
}
