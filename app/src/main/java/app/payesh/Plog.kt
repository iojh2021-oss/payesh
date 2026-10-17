package app.payesh

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Tiny persistent log (survives crashes) used to diagnose service problems. */
object Plog {
    private var file: File? = null

    fun init(ctx: Context) {
        if (file == null) file = File(ctx.applicationContext.filesDir, "payesh.log")
    }

    @Synchronized
    fun w(msg: String) {
        try {
            val f = file ?: return
            if (f.length() > 64_000) f.writeText(f.readText().takeLast(24_000))
            f.appendText("${SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(Date())} $msg\n")
        } catch (_: Exception) {
        }
    }

    @Synchronized
    fun tail(n: Int = 40): List<String> = try {
        file?.readLines()?.takeLast(n) ?: emptyList()
    } catch (_: Exception) {
        emptyList()
    }
}
