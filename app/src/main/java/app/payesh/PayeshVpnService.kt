package app.payesh

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock
import kotlin.random.Random

/** Runs tasks one after another on the shared pool (no dedicated thread per flow). */
private class SerialExec(private val submit: (Runnable) -> Boolean) {
    private val q = java.util.ArrayDeque<Runnable>()
    private var active = false

    @Synchronized
    fun execute(r: Runnable) {
        q.add(r)
        if (!active) next()
    }

    @Synchronized
    private fun next() {
        val r = q.poll()
        if (r == null) { active = false; return }
        active = true
        val ok = submit(Runnable { try { r.run() } finally { next() } })
        if (!ok) { active = false; q.clear() }
    }

    @Synchronized
    fun shutdown() { q.clear() }
}

/**
 * Local VPN that sees every packet of every app, attributes it to an app (UID),
 * records destination / port / bytes, and forwards it to the real network via protected sockets.
 */
class PayeshVpnService : VpnService() {

    companion object {
        const val ACTION_STOP = "app.payesh.STOP"
        const val CLIENT_IP = "10.8.0.2"
        const val MTU = 1400
        private var crashHook = false
    }

    private var tun: ParcelFileDescriptor? = null
    private var flusher: ScheduledExecutorService? = null
    @Volatile private var running = false
    @Volatile private var wantRunning = false
    private val restarts = ArrayList<Long>()
    private lateinit var out: FileOutputStream
    private val outLock = Any()
    // bounded pool: never create unlimited threads (that crashes the process -> internet blackout)
    private val pool = ThreadPoolExecutor(0, 900, 30L, TimeUnit.SECONDS, SynchronousQueue<Runnable>())
    @Volatile private var rejected = 0
    private val handler = Handler(Looper.getMainLooper())
    private val tcpFlows = ConcurrentHashMap<String, TcpFlow>()
    private val udpFlows = ConcurrentHashMap<String, UdpFlow>()
    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }
    private val clientAddr: InetAddress = InetAddress.getByName(CLIENT_IP)

    private fun runAsync(r: Runnable): Boolean = try {
        pool.execute(r); true
    } catch (_: RejectedExecutionException) {
        rejected++; false
    }

    override fun onCreate() {
        super.onCreate()
        Plog.init(this)
        if (!crashHook) {
            crashHook = true
            val old = Thread.getDefaultUncaughtExceptionHandler()
            Thread.setDefaultUncaughtExceptionHandler { t, e ->
                Plog.w("CRASH in ${t.name}: $e | " + e.stackTrace.take(8).joinToString(" <- "))
                old?.uncaughtException(t, e)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Plog.w("onStartCommand action=${intent?.action} running=$running")
        if (intent?.action == ACTION_STOP) {
            stopVpn("user"); return START_NOT_STICKY
        }
        wantRunning = true
        startVpn()
        return START_STICKY
    }

    override fun onRevoke() {
        val authorized = try { VpnService.prepare(this) == null } catch (_: Exception) { false }
        Plog.w("onRevoke authorized=$authorized want=$wantRunning")
        closeTunnel()
        // revoked by the system (e.g. always-on was toggled) while we are still authorized -> come back
        if (authorized && wantRunning && canRestart()) handler.postDelayed({ startVpn() }, 800)
        else stopVpn("revoked")
    }

    override fun onDestroy() {
        Plog.w("onDestroy")
        closeTunnel()
        super.onDestroy()
    }

    private fun canRestart(): Boolean {
        val now = System.currentTimeMillis()
        restarts.removeAll { now - it > 120_000 }
        if (restarts.size >= 6) return false
        restarts.add(now)
        return true
    }

    private fun startVpn() {
        if (running) { Plog.w("startVpn: already running"); return }
        goForeground()
        val b = Builder()
            .setSession("Payesh")
            .addAddress(CLIENT_IP, 32)
            .addRoute("0.0.0.0", 0)
            // IPv6 is routed into the tunnel too, so it cannot bypass monitoring (apps fall back to IPv4)
            .addAddress("fd00:8::2", 128)
            .addRoute("::", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .setMtu(MTU)
            .setBlocking(true)
        try { b.addDisallowedApplication(packageName) } catch (_: Exception) {}
        val fd = try { b.establish() } catch (e: Exception) { Plog.w("establish failed: $e"); null }
        if (fd == null) {
            Plog.w("establish returned null")
            Tracker.running.value = false
            if (wantRunning && canRestart()) handler.postDelayed({ startVpn() }, 2000)
            return
        }
        tun = fd
        out = FileOutputStream(fd.fileDescriptor)
        running = true
        Tracker.clear()
        Tracker.running.value = true
        Tracker.sessionStart = System.currentTimeMillis()
        Plog.w("VPN established")
        var round = 0
        flusher = Executors.newSingleThreadScheduledExecutor().also {
            it.scheduleWithFixedDelay({
                try {
                    History.flush(applicationContext)
                    reap()
                    AvState.checkTraffic(applicationContext)
                    if (++round % 2 == 0) logStats()
                } catch (_: Exception) {
                }
            }, 30, 30, TimeUnit.SECONDS)
        }
        thread(name = "payesh-tun", isDaemon = true) {
            var reason = "?"
            try {
                val input = FileInputStream(fd.fileDescriptor)
                val buf = ByteArray(32767)
                while (running && tun === fd) {
                    val n = input.read(buf)
                    if (n < 0) { reason = "EOF"; break }
                    if (n > 0) try { handle(buf, n) } catch (_: Exception) {}
                }
                if (reason == "?") reason = "stopped"
            } catch (e: Exception) {
                reason = "error: $e"
            }
            Plog.w("tun loop ended: $reason")
            if (running && tun === fd) {
                closeTunnel()
                if (wantRunning && canRestart()) handler.postDelayed({ startVpn() }, 500)
                else stopVpn("loop ended: $reason")
            }
        }
    }

    /** Closes the tunnel and all flows but keeps the service alive (so it can be re-established). */
    private fun closeTunnel() {
        if (!running && tun == null) { Tracker.running.value = false; return }
        running = false
        flusher?.shutdownNow()
        flusher = null
        try { History.flush(applicationContext) } catch (_: Exception) {}
        tcpFlows.values.toList().forEach { it.doClose() }
        udpFlows.values.toList().forEach { it.close() }
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        Tracker.running.value = false
    }

    private fun stopVpn(reason: String) {
        Plog.w("stopVpn: $reason")
        wantRunning = false
        closeTunnel()
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Exception) {}
        stopSelf()
    }

    private fun reap() {
        val now = System.currentTimeMillis()
        tcpFlows.values.toList().forEach { if (now - it.lastAct > 600_000) it.reset() }
        udpFlows.values.toList().forEach { if (now - it.lastAct > 90_000) it.close() }
        val extra = udpFlows.size - 400
        if (extra > 0) udpFlows.values.sortedBy { it.lastAct }.take(extra).forEach { it.close() }
    }

    private fun logStats() {
        val rt = Runtime.getRuntime()
        Plog.w(
            "stats tcp=${tcpFlows.size} udp=${udpFlows.size} threads=${Thread.activeCount()} " +
                "rejected=$rejected mem=${(rt.totalMemory() - rt.freeMemory()) / 1048576}MB"
        )
    }

    private fun writeTun(p: ByteArray) {
        if (!running) return
        try { synchronized(outLock) { out.write(p) } } catch (_: Exception) {}
    }

    private fun ownerOf(proto: Int, local: InetAddress, sp: Int, remote: InetAddress, dp: Int): Int = try {
        cm.getConnectionOwnerUid(proto, InetSocketAddress(local, sp), InetSocketAddress(remote, dp))
    } catch (_: Exception) { -1 }

    private fun owner(proto: Int, sp: Int, rem: ByteArray, dp: Int, retry: Boolean = false): Int {
        val r = InetAddress.getByAddress(rem)
        var uid = ownerOf(proto, clientAddr, sp, r, dp)
        var i = 0
        while (retry && uid < 0 && i < 3) {
            try { Thread.sleep(40) } catch (_: Exception) {}
            uid = ownerOf(proto, clientAddr, sp, r, dp); i++
        }
        return uid
    }

    private fun goForeground() {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel("payesh", "Payesh", NotificationManager.IMPORTANCE_LOW))
            val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            val n = Notification.Builder(this, "payesh")
                .setSmallIcon(R.drawable.ic_notif)
                .setContentTitle("پایش")
                .setContentText("رصد ترافیک برنامه‌ها فعال است")
                .setContentIntent(pi)
                .setOngoing(true)
                .build()
            if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(1, n)
        } catch (e: Exception) {
            Plog.w("startForeground failed: $e")
        }
    }

    // ---------------------------------------------------------------- packet dispatch

    private fun handle(buf: ByteArray, n: Int) {
        val ver = buf[0].toInt() shr 4
        if (ver == 6) { handle6(buf, n); return }
        if (n < 20 || ver != 4) return
        val ihl = (buf[0].toInt() and 0x0f) * 4
        val total = minOf(Pkt.u16(buf, 2), n)
        val proto = buf[9].toInt() and 0xff
        val cli = buf.copyOfRange(12, 16)
        val rem = buf.copyOfRange(16, 20)
        when (proto) {
            6 -> handleTcp(buf, ihl, total, cli, rem)
            17 -> handleUdp(buf, ihl, total, cli, rem)
            1 -> handleIcmp(buf, ihl, total, cli, rem)
        }
    }

    private val pingSlots = Semaphore(6)

    /** ICMP echo (ping): recorded and forwarded with the system ping tool. Android cannot tell which app sent it. */
    private fun handleIcmp(buf: ByteArray, ihl: Int, total: Int, cli: ByteArray, rem: ByteArray) {
        if (total < ihl + 8 || buf[ihl].toInt() != 8) return // echo requests only
        val len = total - ihl
        val msg = buf.copyOfRange(ihl, ihl + len)
        val c = Tracker.conn(-1, "ICMP", Pkt.ip(rem), 0)
        c.up.addAndGet(len.toLong()); c.touch()
        if (!pingSlots.tryAcquire()) return
        val ip = Pkt.ip(rem)
        if (!runAsync(Runnable {
                try { doPing(ip, msg, cli, rem, c) } finally { pingSlots.release() }
            })) pingSlots.release()
    }

    private fun doPing(ip: String, msg: ByteArray, cli: ByteArray, rem: ByteArray, c: Conn) {
        try {
            val payload = (msg.size - 8).coerceIn(0, 1000)
            val p = ProcessBuilder("ping", "-c", "1", "-W", "2", "-s", payload.toString(), ip)
                .redirectErrorStream(true).start()
            if (!p.waitFor(5, TimeUnit.SECONDS)) { p.destroy(); return }
            if (p.exitValue() == 0) {
                c.down.addAndGet(msg.size.toLong()); c.touch()
                writeTun(Pkt.icmpReply(rem, cli, msg, 0, msg.size))
            }
        } catch (_: Exception) {
        }
    }

    /** IPv6: record who tried to connect where, and refuse (TCP RST) so the app falls back to IPv4. */
    private fun handle6(buf: ByteArray, n: Int) {
        if (n < 44) return
        val nh = buf[6].toInt() and 0xff
        if (nh != 6 && nh != 17) return
        val src = buf.copyOfRange(8, 24)
        val dst = buf.copyOfRange(24, 40)
        val sp = Pkt.u16(buf, 40)
        val dp = Pkt.u16(buf, 42)
        val srcA = InetAddress.getByAddress(src)
        val dstA = InetAddress.getByAddress(dst)
        val proto = if (nh == 6) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP
        val uid = ownerOf(proto, srcA, sp, dstA, dp)
        val c = Tracker.conn(uid, "IPv6", dstA.hostAddress ?: "?", dp)
        c.touch()
        if (nh == 6 && n >= 54) {
            val flags = buf[53].toInt() and 0x3f
            if ((flags and Pkt.SYN) != 0 && (flags and Pkt.ACK) == 0) {
                val seq = Pkt.u32(buf, 44)
                writeTun(Pkt.tcp6Rst(dst, src, dp, sp, 0, (seq + 1) and Pkt.MASK, Pkt.RST or Pkt.ACK))
            }
        }
    }

    private fun handleTcp(buf: ByteArray, ihl: Int, total: Int, cli: ByteArray, rem: ByteArray) {
        if (total < ihl + 20) return
        val t = ihl
        val sp = Pkt.u16(buf, t)
        val dp = Pkt.u16(buf, t + 2)
        val seq = Pkt.u32(buf, t + 4)
        val ack = Pkt.u32(buf, t + 8)
        val doff = ((buf[t + 12].toInt() shr 4) and 15) * 4
        val flags = buf[t + 13].toInt() and 0x3f
        val win = Pkt.u16(buf, t + 14)
        val payOff = t + doff
        val payLen = maxOf(0, total - payOff)
        val key = "$sp>${Pkt.ip(rem)}:$dp"
        val f = tcpFlows[key]

        if ((flags and Pkt.SYN) != 0 && (flags and Pkt.ACK) == 0) {
            if (f == null) {
                val nf = TcpFlow(cli, rem, sp, dp, key)
                tcpFlows[key] = nf
                nf.start(seq)
            }
            return
        }
        if (f == null) {
            if ((flags and Pkt.RST) == 0 && (payLen > 0 || (flags and Pkt.FIN) != 0)) {
                val p = if ((flags and Pkt.ACK) != 0)
                    Pkt.tcp(rem, cli, dp, sp, ack, 0, Pkt.RST, 0, null, 0, 0)
                else
                    Pkt.tcp(rem, cli, dp, sp, 0, seq + payLen, Pkt.RST or Pkt.ACK, 0, null, 0, 0)
                writeTun(p)
            }
            return
        }
        f.onPacket(flags, seq, ack, win, buf, payOff, payLen)
    }

    private fun handleUdp(buf: ByteArray, ihl: Int, total: Int, cli: ByteArray, rem: ByteArray) {
        if (total < ihl + 8) return
        val sp = Pkt.u16(buf, ihl)
        val dp = Pkt.u16(buf, ihl + 2)
        val payOff = ihl + 8
        val payLen = minOf(Pkt.u16(buf, ihl + 4) - 8, total - payOff)
        if (payLen < 0) return
        val key = "$sp>${Pkt.ip(rem)}:$dp"
        val flow = udpFlows[key] ?: try {
            UdpFlow(cli, rem, sp, dp, key).also { udpFlows[key] = it }
        } catch (_: Exception) { return }
        flow.send(buf, payOff, payLen)
    }

    // ---------------------------------------------------------------- UDP

    inner class UdpFlow(val cli: ByteArray, val rem: ByteArray, val sp: Int, val dp: Int, val key: String) {
        private val remStr = Pkt.ip(rem)
        private var conn: Conn? = null
        private val ds = DatagramSocket()
        @Volatile private var closed = false
        @Volatile var lastAct = System.currentTimeMillis()

        init {
            protect(ds)
            val uid = owner(OsConstants.IPPROTO_UDP, sp, rem, dp)
            conn = Tracker.conn(uid, "UDP", remStr, dp)
            ds.connect(InetAddress.getByAddress(rem), dp)
            ds.soTimeout = if (dp == 53) 5000 else 20000
            if (!runAsync(Runnable { receiveLoop() })) {
                try { ds.close() } catch (_: Exception) {}
                throw RejectedExecutionException("pool full")
            }
        }

        fun send(d: ByteArray, off: Int, len: Int) {
            lastAct = System.currentTimeMillis()
            try {
                ds.send(DatagramPacket(d, off, len))
                conn?.let { it.up.addAndGet(len.toLong()); it.touch() }
                if (dp == 53) Sniff.dnsQuery(d.copyOfRange(off, off + len))?.let { conn?.url = "DNS: $it" }
            } catch (_: Exception) { close() }
        }

        private fun receiveLoop() {
            val buf = ByteArray(2048)
            try {
                while (!closed) {
                    val p = DatagramPacket(buf, buf.size)
                    ds.receive(p)
                    lastAct = System.currentTimeMillis()
                    if (dp == 53) Sniff.dns(buf.copyOf(p.length))
                    conn?.let { it.down.addAndGet(p.length.toLong()); it.touch() }
                    if (p.length <= MTU - 28) writeTun(Pkt.udp(rem, cli, dp, sp, buf, p.length))
                }
            } catch (_: Exception) {
            } finally { close() }
        }

        fun close() {
            if (closed) return
            closed = true
            try { ds.close() } catch (_: Exception) {}
            udpFlows.remove(key)
        }
    }

    // ---------------------------------------------------------------- TCP

    inner class TcpFlow(val cli: ByteArray, val rem: ByteArray, val sp: Int, val dp: Int, val key: String) {
        private val remStr = Pkt.ip(rem)
        private val lock = ReentrantLock()
        private val cond = lock.newCondition()
        private val writer = SerialExec { runAsync(it) }
        private var socket: Socket? = null
        private var conn: Conn? = null
        private var clientNext = 0L
        private var mySeq = 0L
        private var acked = 0L
        private var window = 65535
        @Volatile private var closed = false
        @Volatile var lastAct = System.currentTimeMillis()
        private var finSent = false
        private var clientFin = false
        private var acc = ByteArray(0)
        private var tries = 0

        private fun send(flags: Int, seq: Long, ack: Long, data: ByteArray? = null, off: Int = 0, len: Int = 0) {
            writeTun(Pkt.tcp(rem, cli, dp, sp, seq, ack, flags, 65535, data, off, len))
        }

        private fun sendAck() = send(Pkt.ACK, mySeq, clientNext)

        fun start(isn: Long) {
            clientNext = (isn + 1) and Pkt.MASK
            mySeq = Random.nextLong(1, 0x7fffffffL)
            acked = mySeq
            if (!runAsync(Runnable { connectAndPump() })) {
                lock.withLock { send(Pkt.RST or Pkt.ACK, 0, clientNext) }
                doClose()
            }
        }

        private fun connectAndPump() {
            val s = Socket()
            try {
                val uid = owner(OsConstants.IPPROTO_TCP, sp, rem, dp, true)
                conn = Tracker.conn(uid, "TCP", remStr, dp)
                protect(s)
                s.connect(InetSocketAddress(InetAddress.getByAddress(rem), dp), 10000)
                s.tcpNoDelay = true
                lock.withLock {
                    socket = s
                    send(Pkt.SYN or Pkt.ACK, mySeq, clientNext)
                    mySeq = (mySeq + 1) and Pkt.MASK
                    acked = mySeq
                }
            } catch (_: Exception) {
                lock.withLock { send(Pkt.RST or Pkt.ACK, 0, clientNext) }
                try { s.close() } catch (_: Exception) {}
                doClose()
                return
            }
            readLoop(s)
        }

        private fun readLoop(s: Socket) {
            val buf = ByteArray(1360)
            try {
                val inp = s.getInputStream()
                while (!closed) {
                    val n = inp.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    lastAct = System.currentTimeMillis()
                    lock.withLock {
                        var t = 0
                        while (!closed && ((mySeq - acked) and Pkt.MASK) >= window.toLong() && t < 600) {
                            cond.await(50, TimeUnit.MILLISECONDS); t++
                        }
                        if (closed) return@withLock
                        send(Pkt.PSH or Pkt.ACK, mySeq, clientNext, buf, 0, n)
                        mySeq = (mySeq + n) and Pkt.MASK
                    }
                    conn?.let { it.down.addAndGet(n.toLong()); it.touch() }
                }
            } catch (_: Exception) {
            }
            lock.withLock {
                if (!closed) {
                    send(Pkt.FIN or Pkt.ACK, mySeq, clientNext)
                    mySeq = (mySeq + 1) and Pkt.MASK
                    finSent = true
                    var t = 0
                    while (!closed && !clientFin && t < 60) { cond.await(500, TimeUnit.MILLISECONDS); t++ }
                }
            }
            doClose()
        }

        fun onPacket(flags: Int, seq: Long, ack: Long, win: Int, d: ByteArray, off: Int, len: Int) {
            lastAct = System.currentTimeMillis()
            lock.withLock {
                if (closed) return
                if ((flags and Pkt.RST) != 0) { doClose(); return }
                if ((flags and Pkt.ACK) != 0) {
                    if (((ack - acked) and Pkt.MASK) < 0x80000000L) acked = ack
                    window = win
                    cond.signalAll()
                    if (finSent && clientFin && acked == mySeq) { doClose(); return }
                }
                var fin = (flags and Pkt.FIN) != 0
                if (len > 0) {
                    if (seq == clientNext) {
                        val data = d.copyOfRange(off, off + len)
                        clientNext = (clientNext + len) and Pkt.MASK
                        conn?.let { it.up.addAndGet(len.toLong()); it.touch() }
                        inspect(data)
                        val s = socket
                        if (s != null) writer.execute(Runnable {
                            try { s.getOutputStream().write(data) } catch (_: Exception) { reset() }
                        })
                        sendAck()
                    } else {
                        sendAck(); fin = false
                    }
                }
                if (fin && ((seq + len) and Pkt.MASK) == clientNext) {
                    clientNext = (clientNext + 1) and Pkt.MASK
                    clientFin = true
                    sendAck()
                    val s = socket
                    writer.execute(Runnable { try { s?.shutdownOutput() } catch (_: Exception) {} })
                    cond.signalAll()
                }
            }
        }

        private fun inspect(d: ByteArray) {
            val c = conn ?: return
            if (dp == 443 && c.domain == null && tries < 4) {
                tries++
                acc += d
                Sniff.sni(acc)?.let { c.domain = it }
            } else if ((dp == 80 || dp == 8080) && tries < 1) {
                tries++
                Sniff.http(d)?.let { c.url = it }
            }
        }

        fun reset() {
            lock.withLock { send(Pkt.RST or Pkt.ACK, mySeq, clientNext) }
            doClose()
        }

        fun doClose() {
            lock.withLock {
                if (closed) return
                closed = true
                try { socket?.close() } catch (_: Exception) {}
                writer.shutdown()
                tcpFlows.remove(key)
                cond.signalAll()
            }
        }
    }
}
