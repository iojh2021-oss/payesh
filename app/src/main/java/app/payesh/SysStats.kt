package app.payesh

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager

/** Per-app traffic as counted by Android itself: Wi-Fi/mobile x foreground/background. No VPN needed. */
class SApp(val uid: Int, val pkg: String, val label: String, val system: Boolean) {
    // index: 0 = wifi background, 1 = wifi foreground, 2 = mobile background, 3 = mobile foreground
    val rx = LongArray(4)
    val tx = LongArray(4)
}

object SysStats {
    private val cache = HashMap<Int, Triple<String, String, Boolean>>()

    private fun who(ctx: Context, uid: Int): Triple<String, String, Boolean> = cache.getOrPut(uid) {
        when (uid) {
            -5 -> Triple("tethering", "اشتراک اینترنت (هات‌اسپات)", true)
            -4 -> Triple("removed", "برنامه‌های حذف‌شده", true)
            0 -> Triple("root", "سیستم (root)", true)
            else -> {
                val pm = ctx.packageManager
                val pkgs = try { pm.getPackagesForUid(uid)?.toList() } catch (_: Exception) { null }
                if (pkgs.isNullOrEmpty()) Triple("uid:$uid", "سیستم ($uid)", true)
                else try {
                    val ai = pm.getApplicationInfo(pkgs[0], 0)
                    val sys = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
                    Triple(pkgs[0], ai.loadLabel(pm).toString(), sys)
                } catch (_: Exception) {
                    Triple(pkgs[0], pkgs[0], true)
                }
            }
        }
    }

    fun load(ctx: Context, hours: Int): List<SApp> {
        val end = System.currentTimeMillis()
        return loadRange(ctx, end - hours * 3_600_000L, end)
    }

    /**
     * Apps whose traffic counted by Android (since the current monitoring session began) is clearly
     * larger than what Payesh saw through the VPN -> traffic that bypassed monitoring.
     */
    fun outsideList(ctx: Context): List<Pair<SApp, Long>> {
        val start = Tracker.sessionStart
        val now = System.currentTimeMillis()
        if (!Tracker.running.value || start == 0L || now - start < 30 * 60_000L) return emptyList()
        val out = ArrayList<Pair<SApp, Long>>()
        for (a in loadRange(ctx, start, now)) {
            val sysTotal = a.rx.sum() + a.tx.sum()
            var obs = 0L
            Tracker.uids[a.uid]?.conns?.values?.forEach { obs += it.up.get() + it.down.get() }
            val excess = sysTotal - obs
            if (excess > maxOf(1_500_000L, (sysTotal * 0.3).toLong())) out.add(a to excess)
        }
        return out.sortedByDescending { it.second }
    }

    fun outside(ctx: Context): Map<Int, Long> = outsideList(ctx).associate { it.first.uid to it.second }

    @Suppress("DEPRECATION")
    fun loadRange(ctx: Context, start: Long, end: Long): List<SApp> {
        val nsm = ctx.getSystemService(NetworkStatsManager::class.java) ?: return emptyList()
        val map = HashMap<Int, SApp>()
        val types = listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)
        for ((ti, type) in types.withIndex()) {
            try {
                val st = nsm.querySummary(type, null, start, end)
                val b = NetworkStats.Bucket()
                while (st.hasNextBucket()) {
                    st.getNextBucket(b)
                    val fg = b.state == NetworkStats.Bucket.STATE_FOREGROUND
                    val idx = ti * 2 + (if (fg) 1 else 0)
                    val a = map.getOrPut(b.uid) {
                        val w = who(ctx, b.uid)
                        SApp(b.uid, w.first, w.second, w.third)
                    }
                    a.rx[idx] += b.rxBytes
                    a.tx[idx] += b.txBytes
                }
                st.close()
            } catch (_: Exception) {
            }
        }
        return map.values.toList()
    }
}
