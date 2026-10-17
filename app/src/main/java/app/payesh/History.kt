package app.payesh

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/** State of the app when the traffic happened. */
object St { const val BG = 0; const val FG = 1; const val UNKNOWN = 2 }

data class HDest(val dest: String, val port: Int, val proto: String, val up: Long, val down: Long, val bgDown: Long)

data class HApp(
    val uid: Int, val pkg: String, val label: String, val system: Boolean,
    val fgUp: Long, val bgUp: Long, val unUp: Long,
    val fgDown: Long, val bgDown: Long, val unDown: Long,
    val dests: List<HDest>
) {
    val up get() = fgUp + bgUp + unUp
    val down get() = fgDown + bgDown + unDown
}

data class HDay(val day: String, val up: Long, val down: Long, val apps: Int)

private class HistoryDb(ctx: Context) : SQLiteOpenHelper(ctx, "history.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE usage(" +
                "ts INTEGER NOT NULL, day TEXT NOT NULL, uid INTEGER NOT NULL, pkg TEXT, label TEXT, system INTEGER, " +
                "proto TEXT NOT NULL, dest TEXT NOT NULL, port INTEGER NOT NULL, state INTEGER NOT NULL, " +
                "up INTEGER NOT NULL, down INTEGER NOT NULL, " +
                "PRIMARY KEY(ts, uid, proto, dest, port, state))"
        )
        db.execSQL("CREATE INDEX idx_day ON usage(day)")
    }

    override fun onUpgrade(db: SQLiteDatabase, o: Int, n: Int) {}
}

/**
 * Persistent traffic history. Every 30 s the service adds the new bytes of each connection to an
 * hourly row (with the date, app, destination and fg/bg state). Old rows are deleted automatically
 * after the chosen retention (default 7 days).
 */
object History {
    private var helper: HistoryDb? = null
    private var lastPrune = 0L
    private class M(val pkgs: List<String>, val label: String, val system: Boolean)
    private val metaCache = HashMap<Int, M>()
    private val iconCache = HashMap<String, ImageBitmap?>()

    private fun db(ctx: Context): SQLiteDatabase {
        val h = helper ?: HistoryDb(ctx.applicationContext).also { helper = it }
        return h.writableDatabase
    }

    private fun prefs(ctx: Context) = ctx.applicationContext.getSharedPreferences("payesh", Context.MODE_PRIVATE)

    fun retention(ctx: Context): Int = prefs(ctx).getInt("retention_days", 7)

    fun setRetention(ctx: Context, days: Int) {
        prefs(ctx).edit().putInt("retention_days", days).apply()
        prune(ctx, true)
    }

    fun hourStart(t: Long): Long {
        val c = Calendar.getInstance()
        c.timeInMillis = t
        c.set(Calendar.MINUTE, 0); c.set(Calendar.SECOND, 0); c.set(Calendar.MILLISECOND, 0)
        return c.timeInMillis
    }

    private fun metaOf(pm: PackageManager, uid: Int): M = metaCache.getOrPut(uid) {
        val pkgs = try { pm.getPackagesForUid(uid)?.toList() } catch (_: Exception) { null }
        if (pkgs.isNullOrEmpty()) {
            M(emptyList(), if (uid < 0) "نامشخص" else "سیستم ($uid)", true)
        } else try {
            val ai = pm.getApplicationInfo(pkgs[0], 0)
            val sys = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            M(pkgs, ai.loadLabel(pm).toString(), sys)
        } catch (_: Exception) {
            M(pkgs, pkgs[0], true)
        }
    }

    /** Writes the traffic that happened since the last flush into the database. */
    @Synchronized
    fun flush(ctx: Context) {
        try {
            val now = System.currentTimeMillis()
            val ts = hourStart(now)
            val day = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(now))
            val fg = Fg.foreground(ctx)
            val pm = ctx.packageManager
            val d = db(ctx)
            d.beginTransaction()
            try {
                for (u in Tracker.uids.values) {
                    val m = metaOf(pm, u.uid)
                    val state = if (fg == null) St.UNKNOWN else if (m.pkgs.any { it in fg }) St.FG else St.BG
                    val pkg = m.pkgs.firstOrNull() ?: "uid:${u.uid}"
                    for (c in u.conns.values) {
                        val up = c.up.get()
                        val down = c.down.get()
                        val dUp = up - c.fUp
                        val dDown = down - c.fDown
                        if (dUp <= 0 && dDown <= 0) continue
                        c.fUp = up; c.fDown = down
                        d.execSQL(
                            "INSERT OR IGNORE INTO usage(ts,day,uid,pkg,label,system,proto,dest,port,state,up,down) VALUES(?,?,?,?,?,?,?,?,?,?,0,0)",
                            arrayOf<Any>(ts, day, u.uid, pkg, m.label, if (m.system) 1 else 0, c.proto, c.name(), c.port, state)
                        )
                        d.execSQL(
                            "UPDATE usage SET up=up+?, down=down+? WHERE ts=? AND uid=? AND proto=? AND dest=? AND port=? AND state=?",
                            arrayOf<Any>(dUp, dDown, ts, u.uid, c.proto, c.name(), c.port, state)
                        )
                    }
                }
                d.setTransactionSuccessful()
            } finally {
                d.endTransaction()
            }
            prune(ctx, false)
        } catch (_: Exception) {
        }
    }

    /** Deletes everything older than the retention period. */
    fun prune(ctx: Context, force: Boolean) {
        try {
            val now = System.currentTimeMillis()
            if (!force && now - lastPrune < 600_000) return
            lastPrune = now
            val cutoff = now - retention(ctx) * 86_400_000L
            db(ctx).delete("usage", "ts < ?", arrayOf(cutoff.toString()))
        } catch (_: Exception) {
        }
    }

    fun loadSince(ctx: Context): List<HApp> =
        load(ctx, "ts >= ?", arrayOf(hourStart(System.currentTimeMillis() - 24 * 3_600_000L).toString()))

    fun loadDay(ctx: Context, day: String): List<HApp> = load(ctx, "day = ?", arrayOf(day))

    private class Acc(val uid: Int, val pkg: String, val label: String, val system: Boolean) {
        val up = LongArray(3)
        val down = LongArray(3)
        val dests = LinkedHashMap<String, LongArray>() // key -> [up, down, bgDown]
    }

    private fun load(ctx: Context, where: String, args: Array<String>): List<HApp> {
        flush(ctx)
        val d = db(ctx)
        val map = LinkedHashMap<Int, Acc>()
        d.rawQuery(
            "SELECT uid, MAX(pkg), MAX(label), MAX(system), state, SUM(up), SUM(down) FROM usage WHERE $where GROUP BY uid, state",
            args
        ).use { c ->
            while (c.moveToNext()) {
                val uid = c.getInt(0)
                val a = map.getOrPut(uid) { Acc(uid, c.getString(1) ?: "", c.getString(2) ?: "", c.getInt(3) == 1) }
                val st = c.getInt(4).coerceIn(0, 2)
                a.up[st] += c.getLong(5)
                a.down[st] += c.getLong(6)
            }
        }
        d.rawQuery(
            "SELECT uid, proto, dest, port, state, SUM(up), SUM(down) FROM usage WHERE $where GROUP BY uid, proto, dest, port, state",
            args
        ).use { c ->
            while (c.moveToNext()) {
                val a = map[c.getInt(0)] ?: continue
                val key = "${c.getString(1)}|${c.getString(2)}|${c.getInt(3)}"
                val v = a.dests.getOrPut(key) { LongArray(3) }
                v[0] += c.getLong(5)
                v[1] += c.getLong(6)
                if (c.getInt(4) == St.BG) v[2] += c.getLong(6)
            }
        }
        return map.values.map { a ->
            HApp(
                a.uid, a.pkg, a.label, a.system,
                a.up[St.FG], a.up[St.BG], a.up[St.UNKNOWN],
                a.down[St.FG], a.down[St.BG], a.down[St.UNKNOWN],
                a.dests.map { (k, v) ->
                    val p = k.split("|")
                    HDest(p[1], p[2].toIntOrNull() ?: 0, p[0], v[0], v[1], v[2])
                }.sortedByDescending { it.down }
            )
        }.sortedByDescending { it.down }
    }

    fun days(ctx: Context): List<HDay> {
        flush(ctx)
        val out = ArrayList<HDay>()
        db(ctx).rawQuery(
            "SELECT day, SUM(up), SUM(down), COUNT(DISTINCT uid) FROM usage GROUP BY day ORDER BY day DESC", null
        ).use { c ->
            while (c.moveToNext()) out.add(HDay(c.getString(0), c.getLong(1), c.getLong(2), c.getInt(3)))
        }
        return out
    }

    /** Persian (Jalali) date for a yyyy-MM-dd day. */
    fun jalali(day: String): String = try {
        val d = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(day)!!
        android.icu.text.SimpleDateFormat("EEEE d MMMM yyyy", android.icu.util.ULocale("fa_IR@calendar=persian")).format(d)
    } catch (_: Exception) {
        day
    }

    fun icon(ctx: Context, pkg: String): ImageBitmap? = iconCache.getOrPut(pkg) {
        try {
            ctx.packageManager.getApplicationIcon(pkg).toBitmap(72, 72).asImageBitmap()
        } catch (_: Exception) {
            null
        }
    }
}
