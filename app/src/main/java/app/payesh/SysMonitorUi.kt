package app.payesh

import android.content.ClipData
import android.content.ClipboardManager
import android.widget.Toast
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private val SmRed = Color(0xFFFF5A5F)
private val SmCyan = Color(0xFF5BD6FF)
private const val HIST = 60

private fun smLoadColor(p: Float): Color = if (p < 60f) Accent else if (p < 85f) Orange else SmRed
private fun smPct(v: Float): String = ltr(String.format("%.0f%%", v))
private fun smGhz(khz: Long): String = if (khz <= 0) "—" else ltr(String.format("%.2f GHz", khz / 1_000_000f))

private fun smAgo(ms: Long): String {
    val m = (System.currentTimeMillis() - ms) / 60_000
    return if (m < 1) "همین الان" else if (m < 60) "$m دقیقه پیش" else "${m / 60} ساعت پیش"
}

/** Quick 0-100 "device health" score from RAM pressure, CPU, free storage and temperatures. */
private fun smHealth(s: SysSnap?, vols: List<VolumeInfo>, bat: BatteryInfo?): Int {
    if (s == null) return 0
    var h = 100
    if (s.memPct > 85f) h -= 20 else if (s.memPct > 70f) h -= 8
    if (s.cpuSrc != "none") { if (s.cpuTotal > 85f) h -= 15 else if (s.cpuTotal > 65f) h -= 6 }
    vols.firstOrNull()?.let {
        val free = if (it.total > 0) it.free * 100f / it.total else 100f
        if (free < 10f) h -= 20 else if (free < 20f) h -= 8
    }
    val hot = maxOf(s.temps.maxOfOrNull { it.second } ?: 0f, bat?.tempC ?: 0f)
    if (hot > 48f) h -= 18 else if (hot > 42f) h -= 8
    return h.coerceIn(0, 100)
}

// ------------------------------------------------------------------ building blocks

@Composable
private fun SmCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp),
        content = content
    )
}

@Composable
private fun SmTitle(text: String, sub: String? = null, color: Color = Color.White) {
    Text(text, color = color, fontWeight = FontWeight.Bold, fontSize = 14.sp)
    if (sub != null) Text(sub, color = Muted, fontSize = 11.sp)
    Spacer(Modifier.height(10.dp))
}

@Composable
private fun SmRow(k: String, v: String, vColor: Color = Color.White) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.Top) {
        Text(k, color = Muted, fontSize = 12.sp, modifier = Modifier.width(112.dp))
        Text(ltr(v), color = vColor, fontSize = 12.sp, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun SmBar(frac: Float, color: Color, modifier: Modifier = Modifier, h: Int = 8) {
    Box(modifier.fillMaxWidth().height(h.dp).clip(RoundedCornerShape(h.dp)).background(Color.White.copy(alpha = .07f))) {
        Box(Modifier.fillMaxHeight().fillMaxWidth(frac.coerceIn(0f, 1f)).clip(RoundedCornerShape(h.dp)).background(color))
    }
}

/** Animated 270° ring gauge with a soft glow. */
@Composable
private fun SmGauge(pct: Float, big: String, title: String, color: Color, modifier: Modifier = Modifier) {
    val anim by animateFloatAsState(pct.coerceIn(0f, 100f) / 100f, tween(650), label = "gauge")
    Box(modifier.aspectRatio(1f), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize().padding(10.dp)) {
            val stroke = size.minDimension * 0.11f
            val d = size.minDimension - stroke
            val tl = Offset((size.width - d) / 2f, (size.height - d) / 2f)
            val sz = Size(d, d)
            drawArc(Color.White.copy(alpha = .07f), 135f, 270f, false, tl, sz, style = Stroke(stroke, cap = StrokeCap.Round))
            if (anim > 0.004f) {
                drawArc(color.copy(alpha = .20f), 135f, 270f * anim, false, tl, sz, style = Stroke(stroke * 1.8f, cap = StrokeCap.Round))
                drawArc(color, 135f, 270f * anim, false, tl, sz, style = Stroke(stroke, cap = StrokeCap.Round))
            }
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(big, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 26.sp)
            Text(title, color = Muted, fontSize = 11.sp)
        }
    }
}

/** Rolling line chart (last ~60 samples) with gradient fill. */
@Composable
private fun SmSpark(values: List<Float>, color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val w = size.width
        val h = size.height
        for (g in listOf(0.25f, 0.5f, 0.75f)) drawLine(Color.White.copy(alpha = .05f), Offset(0f, h * g), Offset(w, h * g), 1f)
        val n = values.size
        if (n < 2) return@Canvas
        val step = w / (HIST - 1).toFloat()
        val line = Path()
        val fill = Path()
        values.forEachIndexed { i, v ->
            val x = i * step
            val y = h - (v.coerceIn(0f, 100f) / 100f) * h * 0.92f - h * 0.04f
            if (i == 0) { line.moveTo(x, y); fill.moveTo(x, h); fill.lineTo(x, y) } else { line.lineTo(x, y); fill.lineTo(x, y) }
        }
        fill.lineTo((n - 1) * step, h)
        fill.close()
        drawPath(fill, Brush.verticalGradient(listOf(color.copy(alpha = .35f), Color.Transparent)))
        drawPath(line, color, style = Stroke(2.5.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round))
    }
}

@Composable
private fun SmChip(text: String, color: Color = Muted) = Badge(text, color)

@Composable
private fun SmCoreGrid(cores: List<CoreInfo>, estimated: Boolean) {
    Row(Modifier.fillMaxWidth().height(118.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        cores.forEach { c ->
            val col = if (!c.online) Color(0xFF3A3F34) else smLoadColor(c.pct)
            Column(Modifier.weight(1f), horizontalAlignment = Alignment.CenterHorizontally) {
                Box(
                    Modifier.weight(1f).fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(Color.White.copy(alpha = .06f)),
                    contentAlignment = Alignment.BottomCenter
                ) {
                    Box(Modifier.fillMaxWidth().fillMaxHeight((if (c.online) c.pct else 0f).coerceIn(0f, 100f) / 100f).background(col))
                }
                Spacer(Modifier.height(4.dp))
                Text(if (c.online) ltr(String.format("%.0f", c.pct)) else "off", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                Text(ltr("C${c.idx}"), color = Muted, fontSize = 9.sp)
            }
        }
    }
    if (estimated) Text(
        "این درصدها تخمینی است (نسبت سرعت کلاک فعلی به بیشینه)، چون اندروید خواندن /proc/stat را برای برنامه‌ها بسته است.",
        color = Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 8.dp)
    )
}

// ------------------------------------------------------------------ screen

@Composable
fun SysMonitorScreen(page: Int, onPage: (Int) -> Unit) {
    val ctx = LocalContext.current
    var snap by remember { mutableStateOf<SysSnap?>(null) }
    val cpuHist = remember { mutableStateListOf<Float>() }
    val ramHist = remember { mutableStateListOf<Float>() }
    var procs by remember { mutableStateOf(ProcSnap(emptyList(), emptyList())) }
    var battery by remember { mutableStateOf<BatteryInfo?>(null) }
    var volumes by remember { mutableStateOf<List<VolumeInfo>>(emptyList()) }
    var recent by remember { mutableStateOf<List<RecentApp>>(emptyList()) }

    val hw by produceState<HardwareInfo?>(null) { value = withContext(Dispatchers.IO) { SysMonitor.hardware(ctx) } }
    val appStore by produceState<List<AppStorage>>(emptyList()) { value = withContext(Dispatchers.IO) { SysMonitor.appStorage(ctx) } }

    // one loop: fast sampling every second, slower things every few seconds; it ends when the page leaves composition
    LaunchedEffect(Unit) {
        var n = 0
        while (true) {
            val s = withContext(Dispatchers.IO) { SysMonitor.read(ctx) }
            snap = s
            cpuHist.add(s.cpuTotal); if (cpuHist.size > HIST) cpuHist.removeAt(0)
            ramHist.add(s.memPct); if (ramHist.size > HIST) ramHist.removeAt(0)
            if (n % 3 == 0) {
                procs = withContext(Dispatchers.IO) { SysMonitor.processes() }
                battery = SysMonitor.battery(ctx)
            }
            if (n % 10 == 0) {
                volumes = withContext(Dispatchers.IO) { SysMonitor.volumes(ctx) }
                recent = withContext(Dispatchers.IO) { SysMonitor.recentApps(ctx) }
            }
            n++
            delay(1000)
        }
    }

    val s = snap
    val health = smHealth(s, volumes, battery)

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 110.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Text(
                "مانیتور سیستم\nلحظه‌ای", color = Color.White, fontSize = 34.sp,
                fontWeight = FontWeight.Bold, lineHeight = 40.sp, modifier = Modifier.padding(vertical = 6.dp)
            )
        }
        item { PageSwitch(page, onPage) }

        // ---- hero: device + health + battery
        item {
            val hc = if (health >= 80) Accent else if (health >= 55) Orange else SmRed
            SmCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            hw?.rows?.firstOrNull { it.first == "مدل" }?.second ?: android.os.Build.MODEL,
                            color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp, maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            ltr("Android ${android.os.Build.VERSION.RELEASE}  •  روشن از ${if (s != null) SysMonitor.uptimeText(s.uptimeS) else "—"}"),
                            color = Muted, fontSize = 12.sp
                        )
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("$health", color = hc, fontWeight = FontWeight.Bold, fontSize = 30.sp)
                        Text("سلامت دستگاه", color = Muted, fontSize = 10.sp)
                    }
                }
                Spacer(Modifier.height(10.dp))
                SmBar(health / 100f, hc)
                battery?.let { b ->
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        SmChip(ltr("باتری ${b.pct}%"), if (b.pct < 20 && !b.charging) SmRed else Accent)
                        if (b.charging) SmChip("در حال شارژ ${b.plugged}", Accent)
                        SmChip(ltr(String.format("%.1f°C", b.tempC)), if (b.tempC > 42f) Orange else Muted)
                        SmChip(ltr(String.format("%.2f V", b.voltageV)))
                    }
                }
            }
        }

        // ---- CPU + RAM gauges
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                val cpuColor = smLoadColor(s?.cpuTotal ?: 0f)
                SmCard(Modifier.weight(1f)) {
                    SmGauge(
                        s?.cpuTotal ?: 0f, if (s == null || s.cpuSrc == "none") "—" else smPct(s.cpuTotal),
                        if (s?.cpuSrc == "freq") "پردازنده (تخمینی)" else "پردازنده", cpuColor, Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    SmSpark(cpuHist.toList(), cpuColor, Modifier.fillMaxWidth().height(46.dp))
                }
                val ramColor = smLoadColor(s?.memPct ?: 0f)
                SmCard(Modifier.weight(1f)) {
                    SmGauge(s?.memPct ?: 0f, if (s == null) "—" else smPct(s.memPct), "حافظهٔ رم", ramColor, Modifier.fillMaxWidth())
                    Spacer(Modifier.height(8.dp))
                    SmSpark(ramHist.toList(), ramColor, Modifier.fillMaxWidth().height(46.dp))
                }
            }
        }

        // ---- CPU detail
        if (s != null) item {
            SmCard {
                SmTitle("هسته‌های پردازنده", "${s.cores.size} هسته" + if (s.cpuSrc == "stat") " • بار واقعی هر هسته" else "")
                if (s.cores.isEmpty()) {
                    Text("اندروید اجازهٔ خواندن اطلاعات هسته‌ها را به این برنامه نداده است.", color = Muted, fontSize = 12.sp)
                } else {
                    SmCoreGrid(s.cores, s.cpuSrc == "freq")
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        s.clusters.forEach { (n, f) -> SmChip("${n}× ${smGhz(f)}", SmCyan) }
                        if (s.governor.isNotEmpty()) SmChip(s.governor, Violet)
                    }
                }
                if (s.loadAvg.isNotEmpty()) SmRow("میانگین بار (۱/۵/۱۵ دقیقه)", s.loadAvg.replace(",", "  "))
            }
        }

        // ---- memory detail
        if (s != null) item {
            SmCard {
                SmTitle("حافظهٔ رم", "${fmt(s.memUsed)} در حال استفاده از ${fmt(s.memTotal)}")
                val used = s.memUsed.toFloat().coerceAtLeast(1f)
                val cache = minOf(s.cached + s.buffers, s.memAvail).toFloat().coerceAtLeast(1f)
                val freeP = s.memFree.toFloat().coerceAtLeast(1f)
                Row(Modifier.fillMaxWidth().height(14.dp).clip(RoundedCornerShape(8.dp)).background(Color.White.copy(alpha = .07f))) {
                    Box(Modifier.weight(used).fillMaxHeight().background(smLoadColor(s.memPct)))
                    Box(Modifier.weight(cache).fillMaxHeight().background(Violet.copy(alpha = .7f)))
                    Box(Modifier.weight(freeP).fillMaxHeight().background(Color.Transparent))
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    SmChip("در استفاده", smLoadColor(s.memPct)); SmChip("کش و بافر", Violet); SmChip("آزاد", Muted)
                }
                Spacer(Modifier.height(8.dp))
                SmRow("قابل‌استفاده (Available)", fmt(s.memAvail))
                SmRow("آزاد (Free)", fmt(s.memFree))
                if (s.cached > 0) SmRow("کش + بافر", fmt(s.cached + s.buffers))
                if (s.active > 0) SmRow("فعال / غیرفعال", "${fmt(s.active)}  /  ${fmt(s.inactive)}")
                if (s.swapTotal > 0) SmRow("حافظهٔ مبادله (Swap/zRAM)", "${fmt(s.swapUsed)} از ${fmt(s.swapTotal)}")
            }
        }

        // ---- storage
        item {
            SmCard {
                SmTitle("فضای ذخیره‌سازی", "حجم اشغال‌شده و آزاد")
                if (volumes.isEmpty()) Text("در حال خواندن…", color = Muted, fontSize = 12.sp)
                volumes.forEach { v ->
                    val used = (v.total - v.free).coerceAtLeast(0)
                    val frac = if (v.total > 0) used.toFloat() / v.total else 0f
                    Row(Modifier.fillMaxWidth()) {
                        Text(v.label, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp, modifier = Modifier.weight(1f))
                        Text(ltr("${fmt(used)} / ${fmt(v.total)}"), color = Muted, fontSize = 12.sp)
                    }
                    Spacer(Modifier.height(6.dp))
                    SmBar(frac, smLoadColor(frac * 100f), h = 12)
                    Text("آزاد: ${fmt(v.free)}  (${smPct(100f - frac * 100f)})", color = Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp, bottom = 10.dp))
                }
                if (appStore.isNotEmpty()) {
                    Text("پرحجم‌ترین برنامه‌ها", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp, modifier = Modifier.padding(top = 4.dp))
                    Spacer(Modifier.height(8.dp))
                    val top = appStore.first().total.toFloat().coerceAtLeast(1f)
                    appStore.forEach { a ->
                        val icon = remember(a.pkg) { History.icon(ctx, a.pkg) }
                        Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
                            if (icon != null) Image(icon, null, Modifier.size(34.dp).clip(RoundedCornerShape(10.dp)))
                            else Box(Modifier.size(34.dp).clip(RoundedCornerShape(10.dp)).background(Color(0xFF2A2F24)), contentAlignment = Alignment.Center) {
                                Text(a.label.take(1), color = Color.White, fontWeight = FontWeight.Bold)
                            }
                            Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                                Text(a.label, color = Color.White, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                SmBar(a.total / top, SmCyan, Modifier.padding(top = 4.dp), h = 5)
                                Text(ltr("برنامه ${fmt(a.app)} • داده ${fmt(a.data)} • کش ${fmt(a.cache)}"), color = Muted, fontSize = 9.sp)
                            }
                            Text(fmt(a.total), color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                } else if (!Fg.granted(ctx)) {
                    Text("برای دیدن حجم هر برنامه، دسترسی Usage access را برای پایش فعال کن.", color = Muted, fontSize = 11.sp)
                }
            }
        }

        // ---- temperatures
        val temps = (s?.temps ?: emptyList()).sortedByDescending { it.second }.take(6)
        if (temps.isNotEmpty() || battery != null) item {
            SmCard {
                SmTitle("دما", "حسگرهای حرارتی که اندروید اجازه می‌دهد")
                battery?.let { b -> TempRow("باتری", b.tempC) }
                temps.forEach { (name, t) -> TempRow(name, t) }
            }
        }

        // ---- processes
        item {
            SmCard {
                SmTitle("پردازه‌ها و رشته‌ها", "داده از موتور Rust")
                s?.let {
                    SmRow("مصرف خود پایش", "CPU ${smPct(it.selfCpu)} • RAM ${fmt(it.selfRssKb * 1024)} • ${it.selfThreads} رشته", Accent)
                }
                if (procs.procs.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    procs.procs.take(8).forEach { p ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(p.name, color = Color.White, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, fontFamily = FontFamily.Monospace)
                                Text(ltr("PID ${p.pid} • ${p.threads} threads • ${p.state}"), color = Muted, fontSize = 10.sp)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                Text(fmt(p.rssKb * 1024), color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                Text(ltr(String.format("%.1fs CPU", p.ticks / 100.0)), color = Muted, fontSize = 10.sp)
                            }
                        }
                    }
                }
                if (procs.threads.isNotEmpty()) {
                    Text("پرمصرف‌ترین رشته‌های پایش", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
                    val maxT = procs.threads.first().ticks.toFloat().coerceAtLeast(1f)
                    procs.threads.take(6).forEach { t ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(t.name, color = Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.width(96.dp))
                            SmBar(t.ticks / maxT, SmCyan, Modifier.weight(1f), h = 6)
                            Text(ltr(String.format("%.1fs", t.ticks / 100.0)), color = Muted, fontSize = 10.sp, textAlign = TextAlign.End, modifier = Modifier.width(46.dp))
                        }
                    }
                }
                Text(
                    "از اندروید ۷ به بعد هر برنامه فقط پردازه‌های خودش را در /proc می‌بیند؛ پردازه‌های سایر برنامه‌ها برای هیچ برنامهٔ عادی قابل خواندن نیست. " +
                        "برای بقیه، فهرست «برنامه‌های اخیر» در پایین از آمار رسمی اندروید می‌آید.",
                    color = Muted, fontSize = 10.sp, modifier = Modifier.padding(top = 10.dp)
                )
            }
        }

        // ---- recent apps (official usage events)
        if (recent.isNotEmpty()) item {
            SmCard {
                SmTitle("برنامه‌های اخیر", "اجراشده در ۳ ساعت گذشته")
                recent.forEach { a ->
                    val icon = remember(a.pkg) { History.icon(ctx, a.pkg) }
                    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
                        if (icon != null) Image(icon, null, Modifier.size(32.dp).clip(RoundedCornerShape(9.dp)))
                        else Box(Modifier.size(32.dp).clip(RoundedCornerShape(9.dp)).background(Color(0xFF2A2F24)), contentAlignment = Alignment.Center) {
                            Text(a.label.take(1), color = Color.White, fontWeight = FontWeight.Bold)
                        }
                        Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                            Text(a.label, color = Color.White, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(smAgo(a.lastUsed), color = Muted, fontSize = 10.sp)
                        }
                        if (a.foreground) SmChip("پیش‌زمینه", Accent) else SmChip("پس‌زمینه")
                    }
                }
            }
        }

        // ---- hardware
        item {
            SmCard {
                SmTitle("مشخصات سخت‌افزار", "دستگاه، تراشه و سیستم‌عامل")
                if (hw == null) Text("در حال خواندن…", color = Muted, fontSize = 12.sp)
                hw?.rows?.forEach { (k, v) -> SmRow(k, v) }
                val feats = hw?.features ?: emptyList()
                if (feats.isNotEmpty()) {
                    Text("قابلیت‌های پردازنده", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 6.dp))
                    feats.take(30).chunked(5).forEach { line ->
                        Row(Modifier.padding(bottom = 4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) { line.forEach { SmChip(it) } }
                    }
                }
                Spacer(Modifier.height(10.dp))
                AvBtn("کپی مشخصات", false, Accent, Modifier.fillMaxWidth()) {
                    try {
                        val txt = (hw?.rows ?: emptyList()).joinToString("\n") { "${it.first}: ${it.second}" }
                        ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("payesh-hw", txt))
                        Toast.makeText(ctx, "مشخصات کپی شد", Toast.LENGTH_SHORT).show()
                    } catch (_: Exception) {
                    }
                }
            }
        }

        if (s != null && !s.native) item {
            Text("موتور بومی (Rust) بارگذاری نشد؛ فقط بخشی از آمار از API رسمی اندروید نمایش داده می‌شود.", color = Orange, fontSize = 11.sp)
        }
    }
}

@Composable
private fun TempRow(name: String, c: Float) {
    val col = if (c < 40f) Accent else if (c < 48f) Orange else SmRed
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(name, color = Muted, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.width(100.dp))
        SmBar(c / 80f, col, Modifier.weight(1f), h = 6)
        Text(ltr(String.format("%.1f°", c)), color = col, fontWeight = FontWeight.Bold, fontSize = 12.sp, textAlign = TextAlign.End, modifier = Modifier.width(52.dp))
    }
}
