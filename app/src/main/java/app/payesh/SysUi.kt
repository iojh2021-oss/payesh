package app.payesh

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private const val BG_MIN = 1_048_576L

/** Service log, to find out why the VPN stopped. */
@Composable
fun LogCard() {
    var open by remember { mutableStateOf(false) }
    var lines by remember { mutableStateOf<List<String>>(emptyList()) }
    LaunchedEffect(open) {
        while (open) {
            lines = withContext(Dispatchers.IO) { Plog.tail(40) }
            delay(3000)
        }
    }
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg).padding(14.dp)) {
        Text(
            if (open) "گزارش سرویس (برای عیب‌یابی) ▲" else "گزارش سرویس (برای عیب‌یابی) ▼",
            color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp,
            modifier = Modifier.fillMaxWidth().clickable { open = !open }
        )
        if (open) {
            Spacer(Modifier.height(8.dp))
            if (lines.isEmpty()) Text("هنوز چیزی ثبت نشده.", color = Muted, fontSize = 11.sp)
            lines.forEach {
                Text(ltr(it), color = Muted, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
            }
        }
    }
}

@Composable
fun SysStatsScreen(page: Int, onPage: (Int) -> Unit) {
    val ctx = LocalContext.current
    var hours by remember { mutableStateOf(24) }
    var net by remember { mutableStateOf(0) }      // 0 all, 1 wifi, 2 mobile
    var onlyBg by remember { mutableStateOf(false) }
    var tick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) { while (true) { delay(15_000); tick++ } }
    val granted = remember(tick) { Fg.granted(ctx) }
    val apps by produceState<List<SApp>>(emptyList(), hours, tick) {
        value = withContext(Dispatchers.IO) { SysStats.load(ctx, hours) }
    }

    val running by Tracker.running.collectAsState()
    val outside by produceState<List<Pair<SApp, Long>>>(emptyList(), tick, running) {
        value = withContext(Dispatchers.IO) { if (running) SysStats.outsideList(ctx) else emptyList() }
    }

    val bgIdx = when (net) { 1 -> listOf(0); 2 -> listOf(2); else -> listOf(0, 2) }
    val fgIdx = when (net) { 1 -> listOf(1); 2 -> listOf(3); else -> listOf(1, 3) }
    fun bgRx(a: SApp) = bgIdx.sumOf { a.rx[it] }
    fun bgTx(a: SApp) = bgIdx.sumOf { a.tx[it] }
    fun fgRx(a: SApp) = fgIdx.sumOf { a.rx[it] }
    fun fgTx(a: SApp) = fgIdx.sumOf { a.tx[it] }

    val used = apps.filter { bgRx(it) + bgTx(it) + fgRx(it) + fgTx(it) > 0 }
    val shown = used.filter { !onlyBg || bgRx(it) + bgTx(it) > 0 }
        .sortedByDescending { if (onlyBg) bgRx(it) else bgRx(it) + fgRx(it) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 110.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Text(
                "آمار سیستم\nبدون نیاز به VPN", color = Color.White, fontSize = 34.sp,
                fontWeight = FontWeight.Bold, lineHeight = 40.sp, modifier = Modifier.padding(vertical = 6.dp)
            )
        }
        item { PageSwitch(page, onPage) }
        item {
            Text(
                "این آمار را خود اندروید جمع می‌کند و حتی وقتی رصد پایش خاموش است یا VPN دیگری روشن است کار می‌کند. " +
                    "حجم پس‌زمینه / پیش‌زمینه و وای‌فای / موبایل را نشان می‌دهد، ولی مقصد و پورت ندارد.",
                color = Muted, fontSize = 12.sp
            )
        }
        if (!granted) item {
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp))
                    .border(1.dp, Accent.copy(alpha = .6f), RoundedCornerShape(20.dp))
                    .clickable { ctx.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                    .padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "برای نمایش این آمار، اینجا بزن و Usage access را برای «پایش» فعال کن.",
                    color = Color.White, fontSize = 12.sp
                )
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill("۲۴ ساعت", hours == 24, { hours = 24 }, Modifier.weight(1f))
                Pill("۳ روز", hours == 72, { hours = 72 }, Modifier.weight(1f))
                Pill("۷ روز", hours == 168, { hours = 168 }, Modifier.weight(1f))
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill("همه", net == 0, { net = 0 }, Modifier.weight(1f))
                Pill("وای‌فای", net == 1, { net = 1 }, Modifier.weight(1f))
                Pill("موبایل", net == 2, { net = 2 }, Modifier.weight(1f))
            }
        }
        item {
            val bgApps = used.count { bgRx(it) >= BG_MIN }
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp)) {
                Row {
                    Column(Modifier.weight(1f)) {
                        Text("برنامه‌های دارای مصرف", color = Muted, fontSize = 11.sp)
                        Text("${used.size}", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 22.sp)
                    }
                    Column(Modifier.weight(1f)) {
                        Text("دانلود پس‌زمینه (بالای ۱ مگ)", color = Muted, fontSize = 11.sp)
                        Text("$bgApps", color = Accent, fontWeight = FontWeight.Bold, fontSize = 22.sp)
                    }
                }
                Spacer(Modifier.height(10.dp))
                Text(
                    "کل دریافت پس‌زمینه ${fmt(used.sumOf { bgRx(it) })}  •  پیش‌زمینه ${fmt(used.sumOf { fgRx(it) })}",
                    color = Color.White, fontSize = 12.sp
                )
            }
        }
        item {
            Column(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg)
                    .border(1.dp, Orange.copy(alpha = .5f), RoundedCornerShape(24.dp)).padding(16.dp)
            ) {
                Text("ترافیک خارج از رصد پایش", color = Orange, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Text("مقایسهٔ آمار اندروید با چیزی که پایش از مسیر VPN دیده (از شروع رصد فعلی)", color = Muted, fontSize = 11.sp)
                Spacer(Modifier.height(8.dp))
                val sessionMin = if (Tracker.sessionStart > 0) (System.currentTimeMillis() - Tracker.sessionStart) / 60_000 else 0
                when {
                    !running -> Text("رصد خاموش است.", color = Muted, fontSize = 12.sp)
                    sessionMin < 30 -> Text(
                        "برای مقایسهٔ دقیق، حداقل ۳۰ دقیقه رصد لازم است (الان $sessionMin دقیقه).",
                        color = Muted, fontSize = 12.sp
                    )
                    outside.isEmpty() -> Text("فعلاً ترافیک قابل توجهی بیرون از رصد دیده نشد.", color = Color.White, fontSize = 12.sp)
                    else -> {
                        outside.take(8).forEach { (a, b) ->
                            Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                                Text(a.label, color = Color.White, fontSize = 13.sp, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(fmt(b), color = Orange, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }
                        }
                        Text(
                            "معمولاً: هات‌اسپات، تماس VoLTE / وای‌فای، پیامک تصویری و سرویس‌های اپراتور که اندروید از VPN رد نمی‌کند.",
                            color = Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp)
                        )
                    }
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill("همه برنامه‌ها", !onlyBg, { onlyBg = false })
                Pill("فقط پس‌زمینه", onlyBg, { onlyBg = true })
            }
        }
        if (shown.isEmpty()) item {
            Text(
                if (granted) "داده‌ای برای این بازه ثبت نشده." else "ابتدا دسترسی Usage access را فعال کن.",
                color = Muted, fontSize = 13.sp
            )
        }
        items(shown, key = { it.uid }) { a ->
            val icon = remember(a.pkg) { History.icon(ctx, a.pkg) }
            val bigBg = bgRx(a) >= BG_MIN
            val fgc = if (bigBg) OnAccent else Color.White
            val sub = if (bigBg) OnAccent.copy(alpha = .7f) else Muted
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(if (bigBg) Accent else CardBg).padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (icon != null) {
                    Image(icon, null, Modifier.size(46.dp).clip(RoundedCornerShape(14.dp)))
                } else {
                    Box(
                        Modifier.size(46.dp).clip(RoundedCornerShape(14.dp)).background(Color(0xFF2A2F24)),
                        contentAlignment = Alignment.Center
                    ) { Text(a.label.take(1), color = Color.White, fontWeight = FontWeight.Bold) }
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(a.label, color = fgc, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(ltr("BG ↓${fmt(bgRx(a))} ↑${fmt(bgTx(a))}"), color = sub, fontSize = 11.sp)
                    Text(ltr("FG ↓${fmt(fgRx(a))} ↑${fmt(fgTx(a))}"), color = sub, fontSize = 11.sp)
                    Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                        if (bigBg) Badge("دانلود در پس‌زمینه", OnAccent, OnAccent.copy(alpha = .12f))
                        if (a.system) Badge("سیستمی", sub)
                    }
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(fmt(bgRx(a) + fgRx(a)), color = fgc, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                    Text(ltr("↑ ${fmt(bgTx(a) + fgTx(a))}"), color = sub, fontSize = 11.sp)
                }
            }
        }
    }
}
