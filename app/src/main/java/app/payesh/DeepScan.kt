package app.payesh

import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import java.io.File
import java.io.RandomAccessFile
import java.util.zip.ZipFile
import kotlin.math.ln

class DeepRes(val feats: Set<String>, val notes: List<Pair<Int, String>>)

/**
 * Deep static analysis ("اسکن عمیق"). It looks inside the code instead of only at permissions and hashes:
 *  - DEX string tables: dangerous API / class names and strings are grouped into behaviors (dynamic code loading, shell/root commands,
 *    SMS interception, accessibility control, device-admin wipe, screen/audio capture, installer, anti-analysis, Telegram/Discord C2,
 *    ransomware wording), and COMBINATIONS of behaviors are scored (one API alone is normal; the combination is the signal);
 *  - obfuscation ratio, very long base64 strings (hidden payload), URLs that use raw IP addresses or throw-away domains;
 *  - native libraries (packers like UPX, Frida/Xposed/Metasploit strings, high entropy);
 *  - manifest traits (exported components without permission, task hijacking, shared UID, debuggable);
 *  - files: reverse-shell scripts, APK/DEX hidden at the end of images/PDFs/media, APKs inside ZIP-like archives.
 * Everything is local and read-only. System apps are skipped; store apps get half weight; all deep points are capped.
 */
object Deep {
    val FLAGS_EXTRA = PackageManager.GET_ACTIVITIES or PackageManager.GET_PROVIDERS
    private const val CAP = 75

    private class Ind(val feat: String, val why: String, val needles: List<String>, val ignoreCase: Boolean = false)

    private val INDS = listOf(
        Ind("dyn_code", "بارگذاری کد پویا", listOf("Ldalvik/system/DexClassLoader;", "Ldalvik/system/InMemoryDexClassLoader;")),
        Ind("root_shell", "فرمان شل/روت", listOf("/system/bin/su", "/system/xbin/su", "su -c", "chmod 777", "pm install", "pm grant", "mount -o rw,remount", "settings put secure")),
        Ind("sms_send", "ارسال پیامک", listOf("sendTextMessage", "sendMultipartTextMessage", "sendDataMessage")),
        Ind("sms_intercept", "رهگیری پیامک", listOf("content://sms", "Landroid/provider/Telephony\$Sms\$Inbox;", "android.provider.Telephony.SMS_RECEIVED", "abortBroadcast")),
        Ind("contacts_calllog", "مخاطبین/تماس‌ها", listOf("content://contacts", "content://call_log", "Landroid/provider/ContactsContract\$", "Landroid/provider/CallLog\$")),
        Ind("a11y_control", "کنترل Accessibility", listOf("performGlobalAction", "dispatchGesture", "getRootInActiveWindow", "findAccessibilityNodeInfosByText")),
        Ind("admin_abuse", "عملیات مدیر دستگاه", listOf("wipeData", "lockNow", "resetPassword", "ACTION_ADD_DEVICE_ADMIN")),
        Ind("screen_capture", "ضبط صفحه/صدا", listOf("Landroid/media/projection/MediaProjection;", "createVirtualDisplay", "Landroid/media/AudioRecord;")),
        Ind("clipboard_watch", "پایش کلیپ‌بورد", listOf("setOnPrimaryClipChangedListener", "getPrimaryClip")),
        Ind("self_install", "نصب برنامه", listOf("application/vnd.android.package-archive", "Landroid/content/pm/PackageInstaller;", "ACTION_INSTALL_PACKAGE")),
        Ind("anti_analysis", "ضدتحلیل", listOf("ro.kernel.qemu", "goldfish", "ranchu", "isDebuggerConnected", "TracerPid", "de/robv/android/xposed", "frida", "magisk")),
        Ind("c2_chat", "کانال فرمان پیام‌رسان", listOf("api.telegram.org/bot", "discord.com/api/webhooks", "discordapp.com/api/webhooks")),
        Ind("ddns", "DNS پویا/تونل", listOf(".ngrok.io", ".ngrok-free.app", ".duckdns.org", ".ddns.net", ".no-ip.", "serveo.net", ".hopto.org", ".zapto.org"), true),
        Ind("ransom_words", "متن باج‌افزار", listOf("your files", "bitcoin", "ransom", ".locked", "decrypt your", "wallet address"), true),
        Ind("crypto_cipher", "رمزنگاری فایل", listOf("Ljavax/crypto/Cipher;"))
    )
    private val SENSITIVE = listOf("dyn_code", "root_shell", "sms_send", "sms_intercept", "a11y_control", "admin_abuse", "screen_capture", "self_install", "c2_chat")

    private class Agg {
        val hits = HashMap<String, MutableSet<String>>()
        var classes = 0
        var obf = 0
        var blobs = 0
        var dexFiles = 0
        val ipHosts = HashSet<String>()
        val oddHosts = HashSet<String>()
        val packedLibs = ArrayList<String>()
        val libHits = HashMap<String, MutableSet<String>>()
    }

    private val dexName = Regex("^classes\\d*\\.dex$")
    private val ipRe = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val knownIps = setOf("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "0.0.0.0")
    private val oddTld = setOf("top", "xyz", "tk", "gq", "ml", "cf", "ga", "click", "work", "icu", "cyou", "buzz", "monster", "rest")
    private val LIB_NEEDLES = listOf("UPX!", "/system/bin/su", "/system/xbin/su", "libfrida", "frida-gadget", "xposed", "metasploit", "meterpreter", "/proc/self/mem")

    // ------------------------------------------------------------------ DEX

    private fun u32(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xff) or ((b[o + 1].toLong() and 0xff) shl 8) or ((b[o + 2].toLong() and 0xff) shl 16) or ((b[o + 3].toLong() and 0xff) shl 24)

    private fun looksBase64(b: ByteArray, p: Int, e: Int): Boolean {
        var ok = 0
        for (i in p until e) {
            val c = b[i].toInt()
            if ((c in 'A'.code..'Z'.code) || (c in 'a'.code..'z'.code) || (c in '0'.code..'9'.code) || c == '+'.code || c == '/'.code || c == '='.code) ok++
        }
        return ok * 100 >= (e - p) * 97
    }

    /** "La/b/c;" : every package / class segment has one or two characters (typical for aggressive obfuscation). */
    private fun shortPath(s: String): Boolean {
        var seg = 0
        var segs = 0
        for (i in 1 until s.length - 1) {
            if (s[i] == '/') { if (seg > 2 || seg == 0) return false; segs++; seg = 0 } else seg++
        }
        return segs >= 1 && seg in 1..2
    }

    private fun urlHost(s: String, agg: Agg) {
        val host = s.substringAfter("://").substringBefore('/').substringBefore(':').substringBefore('?').lowercase()
        if (host.length < 4) return
        if (ipRe.matches(host)) {
            if (host !in knownIps && !host.startsWith("127.") && !host.startsWith("10.") && !host.startsWith("192.168.")) agg.ipHosts.add(host)
        } else if (host.substringAfterLast('.') in oddTld) agg.oddHosts.add(host)
    }

    /** Walks the DEX string table (string_ids at 0x3C, entries are ULEB128 length + MUTF-8 text). */
    private fun scanDex(b: ByteArray, agg: Agg) {
        if (b.size < 0x70 || b[0] != 'd'.code.toByte() || b[1] != 'e'.code.toByte() || b[2] != 'x'.code.toByte() || b[3].toInt() != 10) return
        val n = u32(b, 0x38)
        val off = u32(b, 0x3C)
        if (n <= 0 || n > 3_000_000 || off < 0x70 || off + 4 * n > b.size) return
        agg.dexFiles++
        for (i in 0 until n.toInt()) {
            var p = u32(b, off.toInt() + 4 * i).toInt()
            if (p < 0 || p >= b.size) continue
            var guard = 0
            while (p < b.size) {
                val c = b[p++].toInt()
                if ((c and 0x80) == 0 || ++guard > 5) break
            }
            var e = p
            while (e < b.size && b[e].toInt() != 0) e++
            val len = e - p
            if (len < 4) continue
            if (len > 400) { if (len in 300..400_000 && looksBase64(b, p, e)) agg.blobs++; continue }
            val s = String(b, p, len, Charsets.ISO_8859_1)
            if (s[0] == 'L' && s[len - 1] == ';') {
                agg.classes++
                if (shortPath(s)) agg.obf++
            }
            for (ind in INDS) {
                for (nd in ind.needles) {
                    if (len >= nd.length && s.contains(nd, ind.ignoreCase)) { agg.hits.getOrPut(ind.feat) { HashSet() }.add(nd); if (!ind.ignoreCase) break } // wording groups: count every word of one message
                }
            }
            if (s.startsWith("http://") || s.startsWith("https://")) urlHost(s, agg)
        }
    }

    // ------------------------------------------------------------------ native libraries

    private fun find(h: ByteArray, n: Int, nd: ByteArray): Boolean {
        val first = nd[0]
        val last = n - nd.size
        var i = 0
        while (i <= last) {
            if (h[i] == first) {
                var j = 1
                while (j < nd.size && h[i + j] == nd[j]) j++
                if (j == nd.size) return true
            }
            i++
        }
        return false
    }

    private fun entropy(b: ByteArray, n: Int): Double {
        val h = IntArray(256)
        for (i in 0 until n) h[b[i].toInt() and 0xff]++
        var e = 0.0
        for (c in h) if (c > 0) { val q = c.toDouble() / n; e -= q * ln(q) / ln(2.0) }
        return e
    }

    private fun scanLib(z: ZipFile, en: java.util.zip.ZipEntry, agg: Agg) {
        if (en.size > 40_000_000L || en.size < 2048) return
        val buf = ByteArray(minOf(en.size, 6_000_000L).toInt())
        var got = 0
        z.getInputStream(en).use { ins ->
            while (got < buf.size) {
                val r = ins.read(buf, got, buf.size - got)
                if (r < 0) break
                got += r
            }
        }
        if (got < 2048 || buf[0].toInt() != 0x7f || buf[1] != 'E'.code.toByte()) return
        val name = en.name.substringAfterLast('/')
        for (nd in LIB_NEEDLES) if (find(buf, got, nd.toByteArray(Charsets.ISO_8859_1))) agg.libHits.getOrPut(nd) { HashSet() }.add(name)
        if (entropy(buf, minOf(got, 1_000_000)) >= 7.4) agg.packedLibs.add(name)
    }

    // ------------------------------------------------------------------ apps and APK files

    fun app(env: AvEnv, pi: PackageInfo, ai: ApplicationInfo, sideloaded: Boolean): DeepRes {
        val paths = ArrayList<String>()
        ai.sourceDir?.let { paths.add(it) }
        ai.splitSourceDirs?.let { paths.addAll(it) }
        return run(paths, pi, ai.flags, sideloaded, pi.packageName == env.smsDefault)
    }

    private fun run(paths: List<String>, pi: PackageInfo?, appFlags: Int, sideloaded: Boolean, defaultSms: Boolean): DeepRes {
        val agg = Agg()
        for (path in paths) {
            try {
                ZipFile(path).use { z ->
                    val e = z.entries()
                    var libs = 0
                    while (e.hasMoreElements()) {
                        val en = e.nextElement()
                        if (en.isDirectory) continue
                        val n = en.name
                        if (dexName.matches(n) && en.size in 1..60_000_000L) z.getInputStream(en).use { scanDex(it.readBytes(), agg) }
                        else if (n.startsWith("lib/") && n.endsWith(".so") && libs < 12) { libs++; scanLib(z, en, agg) }
                    }
                }
            } catch (_: Exception) {}
        }
        return evaluate(agg, pi, appFlags, sideloaded, defaultSms)
    }

    private fun evaluate(agg: Agg, pi: PackageInfo?, appFlags: Int, sideloaded: Boolean, defaultSms: Boolean): DeepRes {
        val k = if (sideloaded) 1.0 else 0.5
        val raw = ArrayList<Pair<Int, String>>()
        val feats = HashSet<String>(agg.hits.keys)
        fun add(n: Int, r: String) { raw.add((n * k).toInt() to r) }
        fun has(f: String) = agg.hits.containsKey(f)
        fun ev(f: String) = agg.hits[f]?.take(2)?.joinToString("، ") ?: ""

        if (has("dyn_code")) add(10, "بارگذاری کد پویا (${ev("dyn_code")})؛ برنامه می‌تواند کد جدید را بعد از نصب دانلود/باز کند")
        if (has("dyn_code") && (agg.blobs >= 1 || has("root_shell") || has("self_install"))) { add(15, "کد پویا همراه با payload پنهان/شل/نصب‌کننده؛ الگوی Dropper"); feats.add("dropper") }
        if (has("root_shell")) add(8, "فرمان‌های شل/روت داخل کد (${ev("root_shell")})")
        if (has("root_shell") && (has("sms_intercept") || has("a11y_control") || has("self_install"))) add(10, "فرمان‌های روت همراه با رفتار حساس")
        if (has("sms_send") && !defaultSms) add(12, "ارسال پیامک از داخل کد (${ev("sms_send")}) بدون اینکه برنامهٔ پیش‌فرض پیامک باشد")
        if (has("sms_intercept") && !defaultSms) add(12, "رهگیری/خواندن پیامک در کد (${ev("sms_intercept")})")
        if ((has("sms_send") || has("sms_intercept")) && has("a11y_control") && !defaultSms) { add(25, "پیامک + کنترل Accessibility در خود کد؛ الگوی تروجان بانکی"); feats.add("banker_pattern") }
        if (has("a11y_control") && (has("screen_capture") || has("clipboard_watch") || has("contacts_calllog"))) { add(20, "کنترل Accessibility همراه با ضبط صفحه/کلیپ‌بورد/مخاطبین؛ الگوی جاسوسی"); feats.add("spy_pattern") }
        if (agg.hits["admin_abuse"]?.any { it == "wipeData" || it == "lockNow" || it == "resetPassword" } == true) add(15, "قفل‌کردن/پاک‌کردن/تغییر رمز دستگاه در کد (${ev("admin_abuse")})")
        val ransom = agg.hits["ransom_words"]?.size ?: 0
        if (ransom >= 2 && has("crypto_cipher")) { add(45, "الگوی باج‌افزار: متن‌های باج‌خواهی (${ev("ransom_words")}) همراه با رمزنگاری فایل"); feats.add("ransom_pattern") }
        if (has("c2_chat")) add(20, "آدرس کانال فرمان/نشت داده از راه پیام‌رسان (${ev("c2_chat")})")
        if (has("c2_chat") && (has("contacts_calllog") || has("sms_intercept") || has("screen_capture"))) add(20, "نشت داده به ربات پیام‌رسان همراه با خواندن پیامک/مخاطبین/ضبط")
        if (has("ddns")) add(10, "دامنهٔ DNS پویا یا تونل داخل کد (${ev("ddns")})")
        if ((agg.hits["anti_analysis"]?.size ?: 0) >= 2) {
            add(8, "تشخیص شبیه‌ساز/دیباگر/Frida (${ev("anti_analysis")})")
            if (SENSITIVE.count { has(it) } >= 2) add(8, "ضدتحلیل همراه با رفتار حساس؛ بدافزار از بررسی فرار می‌کند")
        }
        val obfPct = if (agg.classes >= 300) agg.obf * 100 / agg.classes else 0
        if (obfPct >= 70) feats.add("obfuscated")
        if (obfPct >= 70 && SENSITIVE.count { has(it) } >= 2) add(8, "کد بسیار مبهم‌سازی‌شده ($obfPct٪ کلاس‌ها نام ۱ـ۲ حرفی) همراه با APIهای حساس")
        if (agg.blobs >= 3) { add(10, "${agg.blobs} رشتهٔ بسیار بلند base64 داخل کد (احتمال payload پنهان)"); feats.add("b64_blobs") }
        if (agg.ipHosts.isNotEmpty()) { add(if (agg.ipHosts.size >= 2) 12 else 8, "آدرس سرور با IP خام در کد: " + agg.ipHosts.take(3).joinToString("، ")); feats.add("ip_url") }
        if (agg.oddHosts.size >= 3) add(6, "چند دامنهٔ ارزان/پرسوءاستفاده (.top/.xyz/.tk ...): " + agg.oddHosts.take(3).joinToString("، "))
        if (agg.libHits.containsKey("UPX!")) { add(20, "کتابخانهٔ native با packer UPX: " + agg.libHits["UPX!"]!!.take(2).joinToString("، ")); feats.add("packed_lib") }
        val hookNd = listOf("libfrida", "frida-gadget", "xposed", "metasploit", "meterpreter").filter { agg.libHits.containsKey(it) }
        if (hookNd.isNotEmpty()) add(15, "کتابخانهٔ native حاوی نشانهٔ ابزار تزریق/نفوذ (${hookNd.take(2).joinToString("، ")})")
        if (agg.libHits.containsKey("/system/bin/su") || agg.libHits.containsKey("/system/xbin/su")) add(8, "کتابخانهٔ native به su (روت) اشاره دارد")
        if (agg.packedLibs.isNotEmpty()) { add(10, "کتابخانهٔ native با آنتروپی بسیار بالا (احتمالاً رمز/بسته‌بندی‌شده): " + agg.packedLibs.take(2).joinToString("، ")); feats.add("packed_lib") }

        if (pi != null) {
            var exposed = 0
            var grant = 0
            for (s in pi.services.orEmpty()) if (s.exported && s.permission == null) exposed++
            for (r in pi.receivers.orEmpty()) if (r.exported && r.permission == null) exposed++
            for (p in pi.providers.orEmpty()) if (p.exported && p.permission == null && p.readPermission == null && p.writePermission == null) { exposed++; if (p.grantUriPermissions) grant++ }
            val hijack = pi.activities.orEmpty().count {
                it.exported && it.taskAffinity != null && it.taskAffinity != pi.packageName && (it.flags and ActivityInfo.FLAG_ALLOW_TASK_REPARENTING) != 0
            }
            if (exposed >= 5) add(6, "$exposed مؤلفهٔ در دسترس برنامه‌های دیگر بدون مجوز (سطح حملهٔ بزرگ)")
            if (grant > 0) add(8, "ContentProvider باز با اجازهٔ دسترسی به فایل (ریسک سرقت فایل)")
            if (hijack > 0) add(12, "$hijack Activity با taskAffinity جعلی و جابه‌جایی وظیفه؛ ریسک ربایش صفحه (StrandHogg)")
            @Suppress("DEPRECATION")
            if (pi.sharedUserId != null) add(8, "sharedUserId تعریف کرده (هم‌هویت‌شدن با برنامهٔ دیگر)")
        }
        if (sideloaded && (appFlags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) add(10, "برنامهٔ قابل‌دیباگ (debuggable) روی گوشی؛ امکان تزریق کد به آن")
        if (sideloaded && (appFlags and ApplicationInfo.FLAG_TEST_ONLY) != 0) add(8, "برنامهٔ testOnly")

        var total = 0
        val capped = ArrayList<Pair<Int, String>>()
        for ((n, r) in raw) {
            val a = minOf(n, CAP - total)
            if (a > 0) { total += a; capped.add(a to r) } else capped.add(0 to r)
        }
        return DeepRes(feats, capped)
    }

    // ------------------------------------------------------------------ plain files

    private val SCRIPT_EXT = setOf("sh", "bash", "py", "pl", "rb", "js", "php", "bat", "cmd", "ps1", "vbs", "lua")
    private val CARRIER_EXT = setOf("jpg", "jpeg", "png", "gif", "webp", "bmp", "pdf", "mp3", "mp4", "mkv", "3gp", "ico")
    private val ARCHIVE_EXT = setOf("zip", "xapk", "apks", "apkm")
    private val SCRIPT_PATTERNS = listOf(
        Triple("/dev/tcp/", 45, "اتصال معکوس (reverse shell) با /dev/tcp"),
        Triple("nc -e", 45, "اتصال معکوس با netcat"),
        Triple("bash -i", 40, "شل تعاملی bash -i"),
        Triple("mkfifo", 25, "ساخت fifo (الگوی reverse shell)"),
        Triple("meterpreter", 60, "نشانهٔ Metasploit/Meterpreter"),
        Triple("msfvenom", 50, "نشانهٔ msfvenom"),
        Triple("base64 -d | sh", 40, "رمزگشایی و اجرای مستقیم base64"),
        Triple("base64 -d|sh", 40, "رمزگشایی و اجرای مستقیم base64"),
        Triple("powershell -enc", 40, "PowerShell رمزشده"),
        Triple("/data/local/tmp", 15, "اجرای فایل از /data/local/tmp")
    )

    private fun head2(f: File): String = try { f.inputStream().use { val b = ByteArray(2); if (it.read(b) == 2) String(b, Charsets.ISO_8859_1) else "" } } catch (_: Exception) { "" }

    /** An APK glued to the end of an image / PDF / media file: its zip directory (with the file names) sits at the very end. */
    private fun tailHasApk(f: File): Boolean = try {
        RandomAccessFile(f, "r").use { r ->
            val n = minOf(r.length(), 3_000_000L).toInt()
            val buf = ByteArray(n)
            r.seek(r.length() - n)
            r.readFully(buf)
            find(buf, n, "AndroidManifest.xml".toByteArray()) && (find(buf, n, "classes.dex".toByteArray()) || find(buf, n, "resources.arsc".toByteArray()))
        }
    } catch (_: Exception) { false }

    private fun nested(env: AvEnv, f: File): List<Pair<Int, String>> {
        val out = ArrayList<Pair<Int, String>>()
        try {
            ZipFile(f).use { z ->
                var cnt = 0
                val e = z.entries()
                while (e.hasMoreElements() && cnt < 6) {
                    val en = e.nextElement()
                    if (en.isDirectory || !en.name.endsWith(".apk", true) || en.size > 150_000_000L || en.size < 1000) continue
                    cnt++
                    val tmp = File(env.ctx.cacheDir, "deep_nested.apk")
                    try {
                        z.getInputStream(en).use { i -> tmp.outputStream().use { o -> i.copyTo(o) } }
                        val pi = env.pm.getPackageArchiveInfo(tmp.path, Av.FLAGS or FLAGS_EXTRA) ?: continue
                        pi.applicationInfo?.let { it.sourceDir = tmp.path; it.publicSourceDir = tmp.path }
                        val fa = Av.analyze(env, pi, pi.packageName, false, true)
                        if (fa.score >= 35) out.add(fa.score to "APK داخل آرشیو (${en.name.substringAfterLast('/')}): " + fa.reasons.take(2).joinToString("؛ "))
                    } finally {
                        tmp.delete()
                    }
                }
            }
        } catch (_: Exception) {}
        return out
    }

    /** Extra checks for ordinary files (called only in deep mode). */
    fun fileNotes(env: AvEnv, f: File, ext: String, len: Long): List<Pair<Int, String>> {
        val out = ArrayList<Pair<Int, String>>()
        try {
            if (len in 16..262_144 && (ext in SCRIPT_EXT || (ext.isEmpty() && head2(f) == "#!"))) {
                val t = f.readText(Charsets.ISO_8859_1).lowercase()
                for ((p, w, why) in SCRIPT_PATTERNS) if (t.contains(p)) out.add(w to "اسکریپت مشکوک: $why")
                if (t.contains("| sh") && (t.contains("curl ") || t.contains("wget "))) out.add(35 to "اسکریپت: دانلود و اجرای مستقیم (curl/wget ... | sh)")
            }
            if (ext in CARRIER_EXT && len in 2048..80_000_000L && tailHasApk(f)) out.add(55 to "APK پنهان در انتهای فایل «$ext» (Polyglot)")
            if (ext in ARCHIVE_EXT && len in 1000..400_000_000L) out.addAll(nested(env, f))
        } catch (_: Exception) {}
        return out
    }
}
