package app.payesh

import kotlinx.coroutines.flow.MutableStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** One destination (proto + ip + port) used by one app. */
class Conn(val proto: String, val ip: String, val port: Int) {
    @Volatile var domain: String? = null
    @Volatile var url: String? = null
    val up = AtomicLong()
    val down = AtomicLong()
    @Volatile var last = System.currentTimeMillis()
    @Volatile var prevDown = 0L
    @Volatile var rate = 0L // bytes/sec received

    fun touch() { last = System.currentTimeMillis() }
    fun name(): String = domain ?: Tracker.dns[ip] ?: ip
}

class UidStats(val uid: Int) {
    val conns = ConcurrentHashMap<String, Conn>()
}

/** Shared in-process state between the VPN service and the UI. */
object Tracker {
    val uids = ConcurrentHashMap<Int, UidStats>()
    val dns = ConcurrentHashMap<String, String>() // ip -> domain
    val running = MutableStateFlow(false)

    fun conn(uid: Int, proto: String, ip: String, port: Int): Conn {
        val u = uids.getOrPut(uid) { UidStats(uid) }
        return u.conns.getOrPut("$proto|$ip|$port") { Conn(proto, ip, port) }
    }

    fun tick(dtMs: Long) {
        if (dtMs <= 0) return
        for (u in uids.values) for (c in u.conns.values) {
            val d = c.down.get()
            c.rate = (d - c.prevDown) * 1000 / dtMs
            c.prevDown = d
        }
    }

    fun clear() { uids.clear(); dns.clear() }
}
