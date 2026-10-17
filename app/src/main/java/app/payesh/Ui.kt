package app.payesh

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// Palette taken from the reference design: near-black surfaces + neon lime accent + white "ticket" paper
val Bg = Color(0xFF0A0B09)
val CardBg = Color(0xFF171A14)
val Accent = Color(0xFFC6F432)
val OnAccent = Color(0xFF111700)
val Paper = Color(0xFFF3F4EE)
val Ink = Color(0xFF14160F)
val Orange = Color(0xFFFFB23E)
val Violet = Color(0xFFB9A7FF)
val Muted = Color(0xFF8B9084)

enum class Filter(val label: String) {
    ALL("همه"), ACTIVE("فعال"), DL("دانلود"), USER("غیرسیستمی"), SYS("سیستمی"), IDLE("بدون ترافیک")
}

fun fmt(b: Long): String = when {
    b < 1024 -> "$b B"
    b < 1024 * 1024 -> String.format("%.1f KB", b / 1024.0)
    b < 1024L * 1024 * 1024 -> String.format("%.1f MB", b / 1048576.0)
    else -> String.format("%.2f GB", b / 1073741824.0)
}

fun ltr(s: String) = "\u200E$s"

fun portName(p: Int): String = when (p) {
    443 -> "443 (HTTPS)"; 80 -> "80 (HTTP)"; 53 -> "53 (DNS)"; 853 -> "853 (DoT)"
    123 -> "123 (NTP)"; 5228 -> "5228 (Google/FCM)"; 993 -> "993 (IMAPS)"; 587 -> "587 (SMTP)"
    8080 -> "8080 (HTTP-alt)"; 1935 -> "1935 (RTMP)"; 0 -> "— (ping)"; else -> "$p"
}

@Composable
fun PayeshApp(vm: MainVM, onToggle: () -> Unit, onUsage: () -> Unit, onVpnSettings: () -> Unit) {
    val apps by vm.apps.collectAsState()
    val running by Tracker.running.collectAsState()
    var page by remember { mutableStateOf(0) }
    val down = apps.sumOf { it.down }
    val up = apps.sumOf { it.up }
    val activeCount = apps.count { it.active }

    Box(Modifier.fillMaxSize().background(Bg)) {
        if (page == 0) LiveScreen(vm, apps, running, page, { page = it }, onUsage, onVpnSettings)
        else if (page == 1) HistoryScreen(page) { page = it }
        else if (page == 2) SysStatsScreen(page) { page = it }
        else if (page == 3) CleanerScreen(page) { page = it }
        else AntivirusScreen(page) { page = it }

        // Bottom bar (like the "Buy Ticket" bar in the reference)
        Row(
            Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(12.dp)
                .clip(RoundedCornerShape(28.dp)).background(Color.Black)
                .border(1.dp, Color.White.copy(alpha = .08f), RoundedCornerShape(28.dp))
                .padding(start = 20.dp, end = 10.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    ltr("↓ ${fmt(down)}   ↑ ${fmt(up)}"), color = Color.White,
                    fontSize = 17.sp, fontWeight = FontWeight.Bold
                )
                Text(
                    if (running) "رصد فعال • $activeCount برنامه در حال ارتباط" else "رصد خاموش",
                    color = Muted, fontSize = 12.sp
                )
            }
            Row(
                Modifier.clip(RoundedCornerShape(20.dp)).background(Accent)
                    .clickable(onClick = onToggle).padding(horizontal = 20.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Rounded.PowerSettingsNew, null, tint = OnAccent, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    if (running) "توقف رصد" else "شروع رصد",
                    color = OnAccent, fontWeight = FontWeight.Bold, fontSize = 14.sp
                )
            }
        }
    }
}

@Composable
fun PageSwitch(page: Int, onPage: (Int) -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg)
            .horizontalScroll(rememberScrollState()).padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        listOf("زنده", "تاریخچه", "آمار سیستم", "پاکسازی", "آنتی‌ویروس").forEachIndexed { i, t ->
            val sel = page == i
            Box(
                Modifier.clip(RoundedCornerShape(16.dp))
                    .background(if (sel) Accent else Color.Transparent)
                    .clickable { onPage(i) }.padding(horizontal = 18.dp, vertical = 11.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(t, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = if (sel) OnAccent else Muted)
            }
        }
    }
}

@Composable
fun LiveScreen(
    vm: MainVM, apps: List<AppUi>, running: Boolean, page: Int, onPage: (Int) -> Unit,
    onUsage: () -> Unit, onVpnSettings: () -> Unit
) {
    val granted by vm.usageGranted.collectAsState()
    var filter by remember { mutableStateOf(Filter.ALL) }
    var query by remember { mutableStateOf("") }
    var showSearch by remember { mutableStateOf(false) }

    val shown = apps.filter { a ->
        (query.isBlank() || a.label.contains(query, true) || a.pkg.contains(query, true) ||
            a.conns.any { it.dest.contains(query, true) }) &&
            when (filter) {
                Filter.ALL -> true
                Filter.ACTIVE -> a.active
                Filter.DL -> a.downloading
                Filter.USER -> !a.system
                Filter.SYS -> a.system
                Filter.IDLE -> a.conns.isEmpty()
            }
    }
    val down = apps.sumOf { it.down }
    val up = apps.sumOf { it.up }
    val activeCount = apps.count { it.active }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 110.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item { TopBar(running) }
        item {
            Text(
                "رصد ترافیک\nبرنامه‌ها", color = Color.White, fontSize = 34.sp,
                fontWeight = FontWeight.Bold, lineHeight = 40.sp,
                modifier = Modifier.padding(vertical = 6.dp)
            )
        }
        item { PageSwitch(page, onPage) }
        if (!granted) item {
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp))
                    .border(1.dp, Accent.copy(alpha = .6f), RoundedCornerShape(20.dp))
                    .clickable(onClick = onUsage).padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Rounded.Warning, null, tint = Accent)
                Spacer(Modifier.width(10.dp))
                Text(
                    "برای تشخیص پیش‌زمینه / پس‌زمینه، اینجا بزن و Usage access را فعال کن.",
                    color = Color.White, fontSize = 12.sp
                )
            }
        }
        item {
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg).padding(4.dp)
            ) {
                listOf(Filter.ALL, Filter.ACTIVE, Filter.DL).forEach { f ->
                    val sel = filter == f
                    Box(
                        Modifier.weight(1f).clip(RoundedCornerShape(16.dp))
                            .background(if (sel) Accent else Color.Transparent)
                            .clickable { filter = f }.padding(vertical = 11.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            f.label, fontSize = 13.sp, fontWeight = FontWeight.Bold,
                            color = if (sel) OnAccent else Muted
                        )
                    }
                }
            }
        }
        item { SummaryCard(down, up, activeCount) }
        item {
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg)
                    .clickable(onClick = onVpnSettings).padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Rounded.Shield, null, tint = Accent)
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text("رصد کامل و بدون فرار", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Text(
                        "اینجا بزن و فقط «VPN همیشه روشن» را برای «پایش» فعال کن. گزینهٔ «مسدود کردن اتصال‌های بدون VPN» را فقط وقتی سرویس پایدار بود روشن کن؛ اگر سرویس بایستد، اینترنت کامل قطع می‌شود.",
                        color = Muted, fontSize = 11.sp
                    )
                }
            }
        }
        item { LogCard() }
        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(listOf(Filter.USER, Filter.SYS, Filter.IDLE)) { f ->
                    val sel = filter == f
                    Text(
                        f.label, fontSize = 13.sp, fontWeight = FontWeight.Bold,
                        color = if (sel) OnAccent else Color.White,
                        modifier = Modifier.clip(RoundedCornerShape(16.dp))
                            .background(if (sel) Accent else CardBg)
                            .clickable { filter = if (sel) Filter.ALL else f }
                            .padding(horizontal = 18.dp, vertical = 12.dp)
                    )
                }
            }
        }
        item {
            Row(Modifier.fillMaxWidth().padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "برنامه‌ها (${shown.size})", color = Color.White, fontSize = 20.sp,
                    fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)
                )
                Row(
                    Modifier.clip(RoundedCornerShape(14.dp)).background(CardBg)
                        .clickable { showSearch = !showSearch }.padding(horizontal = 14.dp, vertical = 9.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Rounded.Search, null, tint = Accent, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("جستجو", color = Color.White, fontSize = 13.sp)
                }
            }
        }
        if (showSearch) item {
            OutlinedTextField(
                value = query, onValueChange = { query = it }, singleLine = true,
                placeholder = { Text("نام برنامه یا سایت…", color = Muted) },
                shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()
            )
        }
        if (!running && apps.all { it.conns.isEmpty() }) item {
            Text(
                "رصد خاموش است. «شروع رصد» پایین صفحه را بزن تا ترافیک برنامه‌ها نمایش داده شود.",
                color = Muted, fontSize = 13.sp
            )
        }
        items(shown, key = { it.uid }) { a -> AppRow(a, running) }
    }
}

@Composable
fun TopBar(running: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(44.dp).clip(CircleShape).background(Accent),
            contentAlignment = Alignment.Center
        ) { Icon(Icons.Rounded.Shield, null, tint = OnAccent) }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text("به", color = Muted, fontSize = 11.sp)
            Text("پایش خوش آمدی", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
        }
        Row(
            Modifier.clip(RoundedCornerShape(14.dp)).background(CardBg).padding(horizontal = 12.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(if (running) Accent else Muted))
            Spacer(Modifier.width(6.dp))
            Text(if (running) "فعال" else "خاموش", color = Color.White, fontSize = 12.sp)
        }
    }
}

@Composable
fun SummaryCard(down: Long, up: Long, active: Int) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp)) {
        SumRow(Icons.Rounded.ArrowDownward, "کل دریافت", fmt(down))
        Box(Modifier.fillMaxWidth().padding(vertical = 12.dp).height(1.dp).background(Color.White.copy(alpha = .08f)))
        SumRow(Icons.Rounded.ArrowUpward, "کل ارسال", fmt(up))
        Spacer(Modifier.height(12.dp))
        Text(
            "$active برنامه در ۵ ثانیهٔ اخیر ارتباط داشته‌اند", color = Muted, fontSize = 12.sp
        )
    }
}

@Composable
fun SumRow(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, value: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(34.dp).clip(CircleShape).border(1.5.dp, Accent, CircleShape),
            contentAlignment = Alignment.Center
        ) { Icon(icon, null, tint = Accent, modifier = Modifier.size(18.dp)) }
        Spacer(Modifier.width(12.dp))
        Column {
            Text(label, color = Muted, fontSize = 12.sp)
            Text(value, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 20.sp)
        }
    }
}

@Composable
fun Badge(text: String, color: Color, bg: Color = color.copy(alpha = .16f)) {
    Text(
        text, color = color, fontSize = 10.sp, maxLines = 1, fontWeight = FontWeight.Bold,
        modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(bg)
            .padding(horizontal = 7.dp, vertical = 2.dp)
    )
}

@Composable
fun AppRow(a: AppUi, running: Boolean) {
    var open by remember { mutableStateOf(false) }
    val hot = a.downloading // downloading apps get the lime card, like the selected class in the reference
    val cardBg = if (hot) Accent else CardBg
    val fg = if (hot) OnAccent else Color.White
    val sub = if (hot) OnAccent.copy(alpha = .7f) else Muted

    Column {
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(cardBg)
                .clickable { open = !open }.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (a.icon != null) {
                Image(a.icon, null, Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)))
            } else {
                Box(
                    Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(Color(0xFF2A2F24)),
                    contentAlignment = Alignment.Center
                ) { Text(a.label.take(1), color = Color.White, fontWeight = FontWeight.Bold) }
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(a.label, color = fg, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                val top = a.conns.firstOrNull()
                Text(
                    if (top != null) ltr("${top.dest}:${top.port}") else "—",
                    color = sub, fontSize = 12.sp, fontFamily = FontFamily.Monospace,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                Row(Modifier.padding(top = 5.dp), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    if (a.downloading) Badge("دانلود ${fmt(a.rate)}/s", OnAccent, OnAccent.copy(alpha = .12f))
                    when (a.foreground) {
                        true -> Badge("پیش‌زمینه", if (hot) OnAccent else Accent)
                        false -> if (a.active) Badge("پس‌زمینه", if (hot) OnAccent else Violet)
                        null -> if (a.active) Badge("فعال", if (hot) OnAccent else Accent)
                    }
                    if (a.conns.isEmpty() && running) Badge("بدون ترافیک", sub)
                    if (a.system) Badge("سیستمی", sub)
                    if (a.outside > 0) Badge("خارج از رصد ${fmt(a.outside)}", if (hot) OnAccent else Orange)
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(fmt(a.down), color = fg, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(fmt(a.up), color = sub, fontSize = 11.sp)
                    Icon(Icons.Rounded.ArrowUpward, null, tint = sub, modifier = Modifier.size(12.dp))
                }
                if (a.conns.isNotEmpty())
                    Icon(if (open) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore, null, tint = sub)
            }
        }
        AnimatedVisibility(open && a.conns.isNotEmpty()) { Ticket(a) }
    }
}

/** White "ticket" with a dashed tear line, like the trip ticket in the reference. */
@Composable
fun Ticket(a: AppUi) {
    Column(
        Modifier.fillMaxWidth().padding(top = 8.dp).clip(RoundedCornerShape(24.dp))
            .background(Paper).padding(16.dp)
    ) {
        Row {
            Column(Modifier.weight(1f)) {
                Text("برنامه", color = Muted, fontSize = 11.sp)
                Text(a.label, color = Ink, fontWeight = FontWeight.Bold, fontSize = 17.sp, maxLines = 1)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("اتصال‌ها", color = Muted, fontSize = 11.sp)
                Text("${a.conns.size}", color = Ink, fontWeight = FontWeight.Bold, fontSize = 17.sp)
            }
        }
        Text(ltr(a.pkg), color = Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace, maxLines = 1)
        Canvas(Modifier.fillMaxWidth().padding(vertical = 12.dp).height(2.dp)) {
            drawLine(
                Color(0xFFB8BCAB), Offset(0f, 0f), Offset(size.width, 0f), strokeWidth = 3f,
                pathEffect = PathEffect.dashPathEffect(floatArrayOf(14f, 12f))
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            a.conns.take(40).forEach { ConnRow(it) }
        }
        Spacer(Modifier.height(12.dp))
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Accent).padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("مجموع", color = OnAccent, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Text(
                ltr("↓ ${fmt(a.down)}   ↑ ${fmt(a.up)}"),
                color = OnAccent, fontWeight = FontWeight.Bold, fontSize = 13.sp
            )
        }
    }
}

@Composable
fun ConnRow(c: ConnUi) {
    Column(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(if (c.active) Color(0xFF3A9E00) else Muted))
            Spacer(Modifier.width(8.dp))
            Text(
                ltr(c.dest), color = Ink, fontSize = 13.sp, fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f),
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Badge(c.proto, Ink, Ink.copy(alpha = .08f))
        }
        Text(
            "پورت ${portName(c.port)}" + if (c.dest != c.ip) "  •  ${ltr(c.ip)}" else "",
            color = Muted, fontSize = 11.sp
        )
        if (c.url != null) Text(ltr("URL: ${c.url}"), color = Color(0xFFB45F00), fontSize = 11.sp, maxLines = 2)
        Text(
            "دریافت ${fmt(c.down)}   ارسال ${fmt(c.up)}" + if (c.rate > 1024) "   ⚡ ${fmt(c.rate)}/s" else "",
            color = Muted, fontSize = 11.sp
        )
    }
}
