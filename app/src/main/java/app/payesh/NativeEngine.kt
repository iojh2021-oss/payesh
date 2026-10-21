package app.payesh

/**
 * Bridge to the native (Rust) engine in libpayeshav.so: SHA-256, a streaming multi-pattern scanner with
 * byte entropy, a raw-inotify file watcher, and user-space system-integrity indicators.
 * If the library cannot be loaded the app silently falls back to the Kotlin implementations.
 */
object NativeEngine {
    val ok: Boolean = try {
        System.loadLibrary("payeshav")
        true
    } catch (_: Throwable) {
        false
    }

    external fun sha256File(path: String): String?
    external fun scannerCreate(patterns: Array<String>): Long
    external fun scannerFeed(handle: Long, buf: ByteArray, len: Int)
    external fun scannerMatches(handle: Long): IntArray
    external fun scannerEntropy(handle: Long): Double
    external fun scannerBytes(handle: Long): Long
    external fun scannerFree(handle: Long)

    // real-time watcher (inotify). watchNext blocks up to timeoutMs; null = woken for shutdown.
    external fun watchCreate(): Long
    external fun watchAdd(handle: Long, path: String): Int
    external fun watchNext(handle: Long, timeoutMs: Int): Array<String>?
    external fun watchWake(handle: Long)
    external fun watchFree(handle: Long)

    /** Lines of "H|CODE|detail" or "M|CODE|detail" (H = high, M = medium). */
    external fun integrityProbe(): Array<String>?
}
