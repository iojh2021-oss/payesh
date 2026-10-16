package app.payesh

import android.app.AppOpsManager
import android.app.Application
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Process
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

data class ConnUi(
    val dest: String, val ip: String, val port: Int, val proto: String,
    val up: Long, val down: Long, val rate: Long, val url: String?,
    val active: Boolean, val last: Long
)

data class AppUi(
    val uid: Int, val pkg: String, val label: String, val system: Boolean,
    val icon: ImageBitmap?, val up: Long, val down: Long, val rate: Long,
    val active: Boolean, val foreground: Boolean?, val downloading: Boolean,
    val last: Long, val conns: List<ConnUi>
)

private class Meta(val pkgs: List<String>, val label: String, val system: Boolean, val icon: ImageBitmap?)

object Fg {
    fun granted(c: Context): Boolean {
        val ao = c.getSystemService(AppOpsManager::class.java)
        return ao.unsafeCheckOpNoThrow(
            AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), c.packageName
        ) == AppOpsManager.MODE_ALLOWED
    }

    fun foreground(c: Context): Set<String>? {
        if (!granted(c)) return null
        return try {
            val usm = c.getSystemService(UsageStatsManager::class.java)
            val now = System.currentTimeMillis()
            val ev = usm.queryEvents(now - 3_600_000, now)
            val e = UsageEvents.Event()
            val map = HashMap<String, Boolean>()
            while (ev.hasNextEvent()) {
                ev.getNextEvent(e)
                when (e.eventType) {
                    UsageEvents.Event.ACTIVITY_RESUMED -> map[e.packageName] = true
                    UsageEvents.Event.ACTIVITY_PAUSED, UsageEvents.Event.ACTIVITY_STOPPED -> map[e.packageName] = false
                }
            }
            map.filterValues { it }.keys
        } catch (_: Exception) {
            null
        }
    }
}

class MainVM(app: Application) : AndroidViewModel(app) {
    private val ctx = app
    val apps = MutableStateFlow<List<AppUi>>(emptyList())
    val usageGranted = MutableStateFlow(true)
    private val cache = HashMap<Int, Meta>()
    private var installedUids: Set<Int> = emptySet()

    init {
        viewModelScope.launch(Dispatchers.Default) {
            loadInstalled()
            var last = System.currentTimeMillis()
            var round = 0
            while (isActive) {
                delay(1500)
                val now = System.currentTimeMillis()
                Tracker.tick(now - last)
                last = now
                if (++round % 40 == 0) loadInstalled()
                usageGranted.value = Fg.granted(ctx)
                apps.value = build(Fg.foreground(ctx), now)
            }
        }
    }

    private fun loadInstalled() {
        try {
            installedUids = ctx.packageManager.getInstalledApplications(0).map { it.uid }.toSet()
        } catch (_: Exception) {
        }
    }

    private fun meta(uid: Int): Meta = cache.getOrPut(uid) {
        val pm = ctx.packageManager
        val pkgs = try { pm.getPackagesForUid(uid)?.toList() } catch (_: Exception) { null }
        if (pkgs.isNullOrEmpty()) {
            Meta(emptyList(), if (uid < 0) "نامشخص" else "سیستم ($uid)", true, null)
        } else try {
            val ai = pm.getApplicationInfo(pkgs[0], 0)
            val sys = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            val icon = try { ai.loadIcon(pm).toBitmap(72, 72).asImageBitmap() } catch (_: Exception) { null }
            Meta(pkgs, ai.loadLabel(pm).toString(), sys, icon)
        } catch (_: Exception) {
            Meta(pkgs, pkgs[0], true, null)
        }
    }

    private fun build(fg: Set<String>?, now: Long): List<AppUi> {
        val ids = HashSet<Int>(installedUids)
        ids.addAll(Tracker.uids.keys)
        return ids.map { uid ->
            val m = meta(uid)
            val conns = (Tracker.uids[uid]?.conns?.values ?: emptyList<Conn>()).map { c ->
                ConnUi(
                    c.name(), c.ip, c.port, c.proto, c.up.get(), c.down.get(), c.rate,
                    c.url, now - c.last < 5000, c.last
                )
            }.sortedByDescending { it.last }
            AppUi(
                uid = uid,
                pkg = m.pkgs.firstOrNull() ?: "uid:$uid",
                label = m.label,
                system = m.system,
                icon = m.icon,
                up = conns.sumOf { it.up },
                down = conns.sumOf { it.down },
                rate = conns.sumOf { it.rate },
                active = conns.any { it.active },
                foreground = fg?.let { s -> m.pkgs.any { it in s } },
                downloading = conns.any { it.rate > 30_000 },
                last = conns.maxOfOrNull { it.last } ?: 0L,
                conns = conns
            )
        }.sortedWith(
            compareByDescending<AppUi> { it.downloading }
                .thenByDescending { it.active }
                .thenByDescending { it.last }
                .thenBy { it.label.lowercase() }
        )
    }
}
