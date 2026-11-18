package app.payesh

import android.app.ActivityManager
import android.app.usage.StorageStatsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.Process
import android.os.StatFs
import android.os.storage.StorageManager

/**
 * Data layer of the "system monitor" page. The heavy lifting (reading /proc and /sys) is done by the
 * native Rust engine (sysinfo.rs); this file only parses its "key=value" text and adds the facts
 * Android exposes through official APIs (Build, battery, storage stats, usage events).
 * If the native library is missing, memory still works through ActivityManager and the rest degrades.
 */
data class CoreInfo(val idx: Int, val pct: Float, val curKhz: Long, val maxKhz: Long, val online: Boolean)

data class SysSnap(
    val memTotal: Long, val memAvail: Long, val memFree: Long, val cached: Long, val buffers: Long,
    val swapTotal: Long, val swapFree: Long, val active: Long, val inactive: Long,
    val cpuSrc: String,            // "stat" = real load, "freq" = estimated from clock speed, "none"
    val cpuTotal: Float,
    val cores: List<CoreInfo>,
    val governor: String, val clusters: List<Pair<Int, Long>>,   // (core count, max kHz)
    val uptimeS: Long, val loadAvg: String,
    val temps: List<Pair<String, Float>>,
    val selfRssKb: Long, val selfThreads: Int, val selfCpu: Float,
    val native: Boolean
) {
    val memUsed: Long get() = (memTotal - memAvail).coerceAtLeast(0)
    val memPct: Float get() = if (memTotal > 0) memUsed * 100f / memTotal else 0f
    val swapUsed: Long get() = (swapTotal - swapFree).coerceAtLeast(0)
}

data class ProcRow(val pid: Int, val name: String, val state: Char, val threads: Int, val rssKb: Long, val ticks: Long, val uid: Int)
data class ThreadRow(val tid: Int, val name: String, val state: Char, val ticks: Long)
data class ProcSnap(val procs: List<ProcRow>, val threads: List<ThreadRow>)

data class VolumeInfo(val label: String, val total: Long, val free: Long)
data class AppStorage(val pkg: String, val label: String, val app: Long, val data: Long, val cache: Long) {
    val total: Long get() = app + data + cache
}
data class RecentApp(val pkg: String, val label: String, val lastUsed: Long, val foreground: Boolean)

data class BatteryInfo(
    val pct: Int, val charging: Boolean, val plugged: String, val tempC: Float, val voltageV: Float,
    val health: String, val tech: String
)

data class HardwareInfo(val rows: List<Pair<String, String>>, val features: List<String>)

object SysMonitor {
    private fun kv(text: String?): Map<String, String> {
        val m = HashMap<String, String>()
        if (text == null) return m
        for (line in text.lineSequence()) {
            val i = line.indexOf('=')
            if (i > 0) m[line.substring(0, i)] = line.substring(i + 1)
        }
        return m
    }

    private fun pairs(s: String?): Map<Int, String> {
        val m = HashMap<Int, String>()
        if (s.isNullOrEmpty()) return m
        for (part in s.split(',')) {
            val i = part.indexOf(':')
            val k = if (i > 0) part.substring(0, i).toIntOrNull() else null
            if (k != null) m[k] = part.substring(i + 1)
        }
        return m
    }

    fun read(ctx: Context): SysSnap {
        val raw = if (NativeEngine.ok) try { NativeEngine.sysSnapshot() } catch (_: Throwable) { null } else null
        val m = kv(raw)
        var total = (m["mem_total_kb"]?.toLongOrNull() ?: 0L) * 1024
        var avail = (m["mem_avail_kb"]?.toLongOrNull() ?: 0L) * 1024
        var free = (m["mem_free_kb"]?.toLongOrNull() ?: 0L) * 1024
        if (total <= 0) {   // /proc/meminfo unreadable or no native lib: use the official API
            val mi = ActivityManager.MemoryInfo()
            ctx.getSystemService(ActivityManager::class.java)?.getMemoryInfo(mi)
            total = mi.totalMem; avail = mi.availMem; free = mi.availMem
        }
        val on = pairs(m["core_online"]); val fr = pairs(m["core_freq"]); val mx = pairs(m["core_max"]); val pc = pairs(m["core_pct"])
        val idxs = (on.keys + fr.keys + pc.keys).toSortedSet()
        val cores = idxs.map { i ->
            CoreInfo(
                i, pc[i]?.toFloatOrNull() ?: 0f, fr[i]?.toLongOrNull() ?: 0L, mx[i]?.toLongOrNull() ?: 0L,
                (on[i] ?: "1") == "1"
            )
        }
        val clusters = (m["clusters"] ?: "").split(',').mapNotNull {
            val p = it.split('x'); val n = p.getOrNull(0)?.toIntOrNull(); val f = p.getOrNull(1)?.toLongOrNull()
            if (n != null && f != null) n to f else null
        }
        val temps = (m["temps"] ?: "").split(';').mapNotNull {
            val i = it.lastIndexOf(':')
            val t = if (i > 0) it.substring(i + 1).toFloatOrNull() else null
            if (t != null) it.substring(0, i) to t else null
        }
        return SysSnap(
            memTotal = total, memAvail = avail, memFree = free,
            cached = (m["cached_kb"]?.toLongOrNull() ?: 0L) * 1024, buffers = (m["buffers_kb"]?.toLongOrNull() ?: 0L) * 1024,
            swapTotal = (m["swap_total_kb"]?.toLongOrNull() ?: 0L) * 1024, swapFree = (m["swap_free_kb"]?.toLongOrNull() ?: 0L) * 1024,
            active = (m["active_kb"]?.toLongOrNull() ?: 0L) * 1024, inactive = (m["inactive_kb"]?.toLongOrNull() ?: 0L) * 1024,
            cpuSrc = m["cpu_src"] ?: "none", cpuTotal = m["cpu_total"]?.toFloatOrNull() ?: 0f,
            cores = cores, governor = m["governor"] ?: "", clusters = clusters,
            uptimeS = m["uptime_s"]?.toLongOrNull() ?: (android.os.SystemClock.elapsedRealtime() / 1000),
            loadAvg = m["loadavg"] ?: "", temps = temps,
            selfRssKb = m["self_rss_kb"]?.toLongOrNull() ?: 0L, selfThreads = m["self_threads"]?.toIntOrNull() ?: 0,
            selfCpu = m["self_cpu"]?.toFloatOrNull() ?: 0f,
            native = raw != null
        )
    }

    fun processes(): ProcSnap {
        val rows = if (NativeEngine.ok) try { NativeEngine.sysProcesses() } catch (_: Throwable) { null } else null
        val procs = ArrayList<ProcRow>(); val threads = ArrayList<ThreadRow>()
        rows?.forEach { line ->
            val p = line.split('|')
            if (p.firstOrNull() == "P" && p.size >= 8) {
                procs.add(ProcRow(p[1].toIntOrNull() ?: 0, p[2], p[3].firstOrNull() ?: '?', p[4].toIntOrNull() ?: 0,
                    p[5].toLongOrNull() ?: 0L, p[6].toLongOrNull() ?: 0L, p[7].toIntOrNull() ?: 0))
            } else if (p.firstOrNull() == "T" && p.size >= 5) {
                threads.add(ThreadRow(p[1].toIntOrNull() ?: 0, p[2], p[3].firstOrNull() ?: '?', p[4].toLongOrNull() ?: 0L))
            }
        }
        return ProcSnap(procs, threads)
    }

    /** Internal storage (+ SD card if mounted), measured by the native statvfs call. */
    fun volumes(ctx: Context): List<VolumeInfo> {
        val out = ArrayList<VolumeInfo>()
        fun stat(path: String): LongArray? {
            val n = if (NativeEngine.ok) try { NativeEngine.sysStorage(path) } catch (_: Throwable) { null } else null
            if (n != null && n.size >= 3 && n[0] > 0) return longArrayOf(n[0], n[2])
            return try { val s = StatFs(path); longArrayOf(s.totalBytes, s.availableBytes) } catch (_: Exception) { null }
        }
        stat(Environment.getDataDirectory().path)?.let { out.add(VolumeInfo("حافظهٔ داخلی", it[0], it[1])) }
        try {
            ctx.getExternalFilesDirs(null).drop(1).filterNotNull().forEachIndexed { i, f ->
                stat(f.path)?.let { out.add(VolumeInfo(if (i == 0) "کارت حافظه" else "کارت حافظه ${i + 1}", it[0], it[1])) }
            }
        } catch (_: Exception) {
        }
        return out
    }

    /** Biggest apps by (app + data + cache). Needs Usage access, which Payesh already asks for. */
    fun appStorage(ctx: Context, top: Int = 8): List<AppStorage> {
        if (!Fg.granted(ctx)) return emptyList()
        val ssm = ctx.getSystemService(StorageStatsManager::class.java) ?: return emptyList()
        val pm = ctx.packageManager
        val list = ArrayList<AppStorage>()
        @Suppress("DEPRECATION")
        val apps = try { pm.getInstalledApplications(0) } catch (_: Exception) { emptyList<ApplicationInfo>() }
        for (ai in apps) {
            try {
                val st = ssm.queryStatsForPackage(StorageManager.UUID_DEFAULT, ai.packageName, Process.myUserHandle())
                val sum = st.appBytes + st.dataBytes
                if (sum > 0) list.add(AppStorage(ai.packageName, ai.loadLabel(pm).toString(), st.appBytes, st.dataBytes - st.cacheBytes, st.cacheBytes))
            } catch (_: Exception) {
            }
        }
        return list.sortedByDescending { it.total }.take(top)
    }

    /** Apps that ran in the last 3 hours, newest first (what Android lets a normal app know about "running"). */
    fun recentApps(ctx: Context, top: Int = 12): List<RecentApp> {
        if (!Fg.granted(ctx)) return emptyList()
        return try {
            val usm = ctx.getSystemService(UsageStatsManager::class.java)
            val now = System.currentTimeMillis()
            val ev = usm.queryEvents(now - 3 * 3_600_000L, now)
            val e = UsageEvents.Event()
            val last = HashMap<String, Long>(); val fg = HashMap<String, Boolean>()
            while (ev.hasNextEvent()) {
                ev.getNextEvent(e)
                when (e.eventType) {
                    UsageEvents.Event.ACTIVITY_RESUMED -> { fg[e.packageName] = true; last[e.packageName] = e.timeStamp }
                    UsageEvents.Event.ACTIVITY_PAUSED, UsageEvents.Event.ACTIVITY_STOPPED -> { fg[e.packageName] = false; last[e.packageName] = e.timeStamp }
                }
            }
            val pm = ctx.packageManager
            last.entries.sortedByDescending { it.value }.filter { it.key != ctx.packageName }.take(top).map {
                val label = try { pm.getApplicationInfo(it.key, 0).loadLabel(pm).toString() } catch (_: Exception) { it.key }
                RecentApp(it.key, label, it.value, fg[it.key] == true)
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun battery(ctx: Context): BatteryInfo? {
        val i: Intent = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: return null
        val level = i.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = i.getIntExtra(BatteryManager.EXTRA_SCALE, 100).coerceAtLeast(1)
        val status = i.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val plug = i.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)
        val health = when (i.getIntExtra(BatteryManager.EXTRA_HEALTH, 0)) {
            BatteryManager.BATTERY_HEALTH_GOOD -> "سالم"
            BatteryManager.BATTERY_HEALTH_OVERHEAT -> "داغ‌شده"
            BatteryManager.BATTERY_HEALTH_DEAD -> "خراب"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "ولتاژ بالا"
            BatteryManager.BATTERY_HEALTH_COLD -> "سرد"
            else -> "نامشخص"
        }
        return BatteryInfo(
            pct = if (level < 0) 0 else level * 100 / scale,
            charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL,
            plugged = when (plug) { BatteryManager.BATTERY_PLUGGED_AC -> "شارژر"; BatteryManager.BATTERY_PLUGGED_USB -> "USB"; BatteryManager.BATTERY_PLUGGED_WIRELESS -> "بی‌سیم"; else -> "" },
            tempC = i.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) / 10f,
            voltageV = i.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0) / 1000f,
            health = health,
            tech = i.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY) ?: ""
        )
    }

    /** Device + SoC facts: Build fields (official API) merged with what the native engine read from /proc/cpuinfo. */
    fun hardware(ctx: Context): HardwareInfo {
        val n = kv(if (NativeEngine.ok) try { NativeEngine.sysInfo() } catch (_: Throwable) { null } else null)
        val rows = ArrayList<Pair<String, String>>()
        fun add(k: String, v: String?) { if (!v.isNullOrBlank() && v != "unknown") rows.add(k to v) }
        add("سازنده", Build.MANUFACTURER.replaceFirstChar { it.uppercase() })
        add("مدل", Build.MODEL)
        add("نام کد دستگاه", Build.DEVICE)
        add("برد (Board)", Build.BOARD)
        if (Build.VERSION.SDK_INT >= 31) {
            add("تراشه (SoC)", listOf(Build.SOC_MANUFACTURER, Build.SOC_MODEL).filter { it.isNotBlank() && it != "unknown" }.joinToString(" "))
        }
        add("پلتفرم", n["hardware"] ?: Build.HARDWARE)
        add("هسته‌ها", n["core_names"])
        add("معماری", (n["arch"] ?: "") + "  (" + Build.SUPPORTED_ABIS.joinToString(", ") + ")")
        add("اندروید", "${Build.VERSION.RELEASE}  (SDK ${Build.VERSION.SDK_INT})")
        if (Build.VERSION.SDK_INT >= 23) add("وصلهٔ امنیتی", Build.VERSION.SECURITY_PATCH)
        add("کرنل", n["kernel"]?.let { Regex("Linux version (\\S+)").find(it)?.groupValues?.get(1) ?: it.take(40) })
        add("ساخت (Build)", Build.DISPLAY)
        val dm = ctx.resources.displayMetrics
        add("صفحه‌نمایش", "${dm.widthPixels} × ${dm.heightPixels}  •  ${dm.densityDpi} dpi")
        try {
            val gl = ctx.getSystemService(ActivityManager::class.java)?.deviceConfigurationInfo?.glEsVersion
            add("OpenGL ES", gl)
        } catch (_: Exception) {
        }
        try {
            val sm = ctx.getSystemService(SensorManager::class.java)
            add("حسگرها", "${sm.getSensorList(Sensor.TYPE_ALL).size} عدد")
        } catch (_: Exception) {
        }
        add("اندازهٔ صفحهٔ حافظه", n["page_size"]?.let { "$it B" })
        val feats = (n["features"] ?: "").split(' ').filter { it.isNotBlank() }
        return HardwareInfo(rows, feats)
    }

    fun uptimeText(s: Long): String {
        val d = s / 86_400; val h = (s % 86_400) / 3_600; val mi = (s % 3_600) / 60
        return if (d > 0) "$d روز $h ساعت" else if (h > 0) "$h ساعت $mi دقیقه" else "$mi دقیقه"
    }
}
