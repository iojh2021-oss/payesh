package app.payesh

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Environment
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.security.MessageDigest

data class DFile(val path: String, val size: Long, val modified: Long)

/** A set of files with identical content. [files] is sorted best-original-first; [keep] is the one that stays. */
class DGroup(val size: Long, val files: List<DFile>, val type: Int) {
    var keep by mutableStateOf(files.first().path)
    val skip = mutableStateListOf<String>() // copies the user chose NOT to delete
    fun toDelete(): List<DFile> = files.filter { it.path != keep && it.path !in skip }
}

class DelResult(val deleted: Int, val bytes: Long, val failed: Int, val removed: List<String>)

object Dedup {
    private const val HEAD = 65536L

    private val img = setOf("jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "bmp", "dng")
    private val vid = setOf("mp4", "mkv", "avi", "mov", "3gp", "webm", "flv", "ts")
    private val aud = setOf("mp3", "m4a", "aac", "ogg", "wav", "flac", "opus", "amr", "oga")
    private val doc = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "epub", "csv", "odt")
    private val arc = setOf("apk", "zip", "rar", "7z", "tar", "gz", "xapk", "apks")
    private val copyRe = Regex("""(\(\d+\)|[\s_-]copy\b|copy of|کپی)""", RegexOption.IGNORE_CASE)

    /** 0 other, 1 image, 2 video, 3 audio, 4 document, 5 archive/apk */
    fun typeOf(path: String): Int {
        val e = path.substringAfterLast('.', "").lowercase()
        return when {
            e in img -> 1; e in vid -> 2; e in aud -> 3; e in doc -> 4; e in arc -> 5; else -> 0
        }
    }

    fun hasAccess(ctx: Context): Boolean =
        if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else ctx.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    /** Internal shared storage plus any SD card / USB volume. */
    fun roots(ctx: Context): List<File> {
        val out = LinkedHashSet<File>()
        try { out.add(Environment.getExternalStorageDirectory().canonicalFile) } catch (_: Exception) {}
        try {
            for (f in ctx.getExternalFilesDirs(null)) {
                if (f == null) continue
                val p = f.absolutePath
                val i = p.indexOf("/Android/data")
                if (i > 0) out.add(File(p.substring(0, i)).canonicalFile)
            }
        } catch (_: Exception) {}
        return out.toList()
    }

    private fun hash(path: String, limit: Long, cancelled: () -> Boolean): String? {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            FileInputStream(path).use { ins ->
                val buf = ByteArray(256 * 1024)
                var left = limit
                while (left > 0) {
                    if (cancelled()) return null
                    val n = ins.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
                    if (n < 0) break
                    md.update(buf, 0, n)
                    left -= n.toLong()
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            null
        }
    }

    fun scan(
        ctx: Context, minSize: Long, cancelled: () -> Boolean,
        progress: (phase: String, done: Long, total: Long, note: String) -> Unit
    ): List<DGroup> {
        val roots = roots(ctx)
        val skipDirs = HashSet<String>()
        for (r in roots) { skipDirs.add(File(r, "Android/data").path); skipDirs.add(File(r, "Android/obb").path) }

        // 1) walk the storage, group by size
        val bySize = HashMap<Long, MutableList<DFile>>()
        var seen = 0L
        val stack = java.util.ArrayDeque<File>()
        roots.forEach { stack.push(it) }
        while (stack.isNotEmpty()) {
            if (cancelled()) return emptyList()
            val dir = stack.pop()
            val list = (try { dir.listFiles() } catch (_: Exception) { null }) ?: continue
            for (f in list) {
                try {
                    if (Files.isSymbolicLink(f.toPath())) continue // never follow links: could point at the "original"
                    if (f.isDirectory) {
                        if (f.name.startsWith(".")) continue
                        if (f.path in skipDirs) continue
                        stack.push(f)
                    } else if (f.isFile) {
                        val len = f.length()
                        if (len >= minSize) bySize.getOrPut(len) { ArrayList() }.add(DFile(f.path, len, f.lastModified()))
                        seen++
                        if (seen % 400L == 0L) progress("فهرست‌گیری فایل‌ها", seen, 0, dir.path)
                    }
                } catch (_: Exception) {
                }
            }
        }

        // 2) same size -> compare first 64 KB -> compare whole content (SHA-256)
        val cand = bySize.values.filter { it.size >= 2 }
        val total = cand.sumOf { it.size }.toLong()
        var done = 0L
        val groups = ArrayList<DGroup>()
        val order = compareBy<DFile>(
            { copyRe.containsMatchIn(File(it.path).nameWithoutExtension) },
            { it.path.contains("/Download", true) },
            { it.modified },
            { it.path.length }
        )
        fun add(sub: List<DFile>) {
            val sorted = sub.sortedWith(order)
            groups.add(DGroup(sorted[0].size, sorted, typeOf(sorted[0].path)))
        }
        for (same in cand) {
            if (cancelled()) return emptyList()
            val byHead = HashMap<String, MutableList<DFile>>()
            for (f in same) {
                val h = hash(f.path, HEAD, cancelled) ?: continue
                byHead.getOrPut(h) { ArrayList() }.add(f)
            }
            for (sub in byHead.values) {
                if (sub.size < 2) continue
                if (sub[0].size <= HEAD) { add(sub); continue } // the head hash already covers the whole file
                val byFull = HashMap<String, MutableList<DFile>>()
                for (f in sub) {
                    if (cancelled()) return emptyList()
                    progress("مقایسهٔ محتوا", done, total, f.path)
                    val h = hash(f.path, Long.MAX_VALUE, cancelled) ?: continue
                    byFull.getOrPut(h) { ArrayList() }.add(f)
                }
                byFull.values.filter { it.size >= 2 }.forEach { add(it) }
            }
            done += same.size
            progress("مقایسهٔ محتوا", done, total, same[0].path)
        }
        return groups.sortedByDescending { it.size * (it.files.size - 1) }
    }

    private fun sameEnds(a: File, b: File): Boolean {
        return try {
            val len = a.length()
            if (len != b.length()) return false
            val n = minOf(65536L, len).toInt()
            val x = ByteArray(n)
            val y = ByteArray(n)
            RandomAccessFile(a, "r").use { ra ->
                RandomAccessFile(b, "r").use { rb ->
                    ra.readFully(x); rb.readFully(y)
                    if (!x.contentEquals(y)) return false
                    if (len > n) {
                        ra.seek(len - n); rb.seek(len - n)
                        ra.readFully(x); rb.readFully(y)
                        if (!x.contentEquals(y)) return false
                    }
                }
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    /** Deletes only the extra copies. Every copy is re-checked against the kept file first. */
    fun delete(ctx: Context, plan: List<Pair<DFile, List<DFile>>>): DelResult {
        var n = 0
        var bytes = 0L
        var failed = 0
        val removed = ArrayList<String>()
        for ((keeper, dels) in plan) {
            val kf = File(keeper.path)
            if (!kf.isFile || kf.length() != keeper.size) { failed += dels.size; continue } // original missing -> delete nothing
            for (d in dels) {
                if (d.path == keeper.path) continue
                val f = File(d.path)
                val ok = f.isFile && f.length() == d.size && f.lastModified() == d.modified &&
                    (try { f.canonicalPath != kf.canonicalPath } catch (_: Exception) { false }) &&
                    sameEnds(kf, f)
                if (ok && f.delete()) { n++; bytes += d.size; removed.add(d.path) } else failed++
            }
        }
        try {
            if (removed.isNotEmpty()) MediaScannerConnection.scanFile(ctx, removed.toTypedArray(), null, null)
        } catch (_: Exception) {
        }
        return DelResult(n, bytes, failed, removed)
    }
}

/** status.state: 0 idle, 1 scanning, 2 results ready, 3 deleting */
data class CStatus(val state: Int = 0, val phase: String = "", val done: Long = 0, val total: Long = 0, val note: String = "")

/** Lives for the whole process so a scan keeps running while you look at other pages. */
object CleanerState {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val status = MutableStateFlow(CStatus())
    val groups = MutableStateFlow<List<DGroup>>(emptyList())
    val message = MutableStateFlow<String?>(null)
    @Volatile private var cancel = false
    private var job: Job? = null

    fun start(ctx: Context) {
        if (job?.isActive == true) return
        val app = ctx.applicationContext
        cancel = false
        message.value = null
        groups.value = emptyList()
        status.value = CStatus(1, "فهرست‌گیری فایل‌ها")
        job = scope.launch {
            val res = try {
                Dedup.scan(app, 4096, { cancel }) { p, d, t, n -> status.value = CStatus(1, p, d, t, n) }
            } catch (e: Exception) {
                Plog.w("dedup scan failed: $e"); emptyList()
            }
            groups.value = if (cancel) emptyList() else res
            status.value = CStatus(if (cancel) 0 else 2)
        }
    }

    fun cancelScan() { cancel = true }

    fun delete(ctx: Context, list: List<DGroup>) {
        if (job?.isActive == true) return
        val app = ctx.applicationContext
        job = scope.launch {
            status.value = CStatus(3, "در حال حذف…")
            val plan = list.map { g -> g.files.first { it.path == g.keep } to g.toDelete() }
                .filter { it.second.isNotEmpty() }
            val r = try { Dedup.delete(app, plan) } catch (e: Exception) {
                Plog.w("dedup delete failed: $e"); DelResult(0, 0, 0, emptyList())
            }
            val gone = r.removed.toSet()
            groups.value = groups.value.mapNotNull { g ->
                val left = g.files.filter { it.path !in gone }
                if (left.size < 2) null
                else DGroup(g.size, left, g.type).also { ng ->
                    ng.keep = if (left.any { it.path == g.keep }) g.keep else left.first().path
                    ng.skip.addAll(g.skip.filter { p -> left.any { it.path == p } })
                }
            }
            message.value = "${r.deleted} فایل حذف شد • ${fmt(r.bytes)} آزاد شد" +
                if (r.failed > 0) " • ${r.failed} مورد حذف نشد (تغییر کرده یا بدون دسترسی)" else ""
            status.value = CStatus(2)
        }
    }
}
