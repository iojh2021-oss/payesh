package app.payesh

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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

private const val DL_MIN = 1_048_576L // 1 MB total download counts as "a download"

@Composable
fun Pill(text: String, selected: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Box(
        modifier.clip(RoundedCornerShape(16.dp)).background(if (selected) Accent else CardBg)
            .clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 11.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(text, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = if (selected) OnAccent else Color.White)
    }
}

@Composable
fun HistoryScreen(page: Int, onPage: (Int) -> Unit) {
    val ctx = LocalContext.current
    var mode by remember { mutableStateOf(0) } // 0 = last 24h, 1 = by day
    var day by remember { mutableStateOf<String?>(null) }
    var filter by remember { mutableStateOf(0) } // 0 all, 1 downloads, 2 background
    var tick by remember { mutableStateOf(0) }
    var retention by remember { mutableStateOf(History.retention(ctx)) }
    LaunchedEffect(Unit) { while (true) { delay(10_000); tick++ } }

    val selDay = day
    val apps by produceState<List<HApp>>(emptyList(), mode, selDay, tick) {
        value = withContext(Dispatchers.IO) {
            when {
                mode == 0 -> History.loadSince(ctx)
                selDay != null -> History.loadDay(ctx, selDay)
                else -> emptyList()
            }
        }
    }
    val days by produceState<List<HDay>>(emptyList(), mode, tick, retention) {
        value = withContext(Dispatchers.IO) { History.days(ctx) }
    }

    val shown = apps.filter {
        when (filter) {
            1 -> it.down >= DL_MIN
            2 -> it.bgUp + it.bgDown > 0
            else -> true
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 110.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Text(
                "تاریخچهٔ مصرف\nاینترنت", color = Color.White, fontSize = 34.sp,
                fontWeight = FontWeight.Bold, lineHeight = 40.sp, modifier = Modifier.padding(vertical = 6.dp)
            )
        }
        item { PageSwitch(page, onPage) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill("۲۴ ساعت گذشته", mode == 0, { mode = 0; day = null }, Modifier.weight(1f))
                Pill("به تفکیک روز", mode == 1, { mode = 1; day = null }, Modifier.weight(1f))
            }
        }
        item {
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg).padding(14.dp)) {
                Text("نگهداری اطلاعات", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Spacer(Modifier.height(8.dp))
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(listOf(1, 3, 7, 14, 30)) { n ->
                        Pill("$n روز", retention == n, { History.setRetention(ctx, n); retention = n })
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "اطلاعات قدیمی‌تر از $retention روز خودکار از دیتابیس حذف می‌شود.",
                    color = Muted, fontSize = 11.sp
                )
            }
        }

        if (mode == 1 && selDay == null) {
            if (days.isEmpty()) item { Text("هنوز داده‌ای ثبت نشده. رصد را روشن کن.", color = Muted, fontSize = 13.sp) }
            items(days, key = { it.day }) { d ->
                Row(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(CardBg)
                        .clickable { day = d.day; filter = 0 }.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(History.jalali(d.day), color = Color.White, fontWeight = FontWeight.Bold)
                        Text(ltr(d.day) + "  •  ${d.apps} برنامه", color = Muted, fontSize = 12.sp)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text(ltr("↓ ${fmt(d.down)}"), color = Accent, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        Text(ltr("↑ ${fmt(d.up)}"), color = Muted, fontSize = 12.sp)
                    }
                }
            }
        } else {
            if (mode == 1 && selDay != null) item {
                Row(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(18.dp)).background(CardBg)
                        .clickable { day = null }.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("‹ بازگشت", color = Accent, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Spacer(Modifier.width(12.dp))
                    Text(History.jalali(selDay), color = Color.White, fontWeight = FontWeight.Bold)
                }
            }
            item { HSummary(apps) }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Pill("همه", filter == 0, { filter = 0 })
                    Pill("دانلود (بالای ۱ مگ)", filter == 1, { filter = 1 })
                    Pill("پس‌زمینه", filter == 2, { filter = 2 })
                }
            }
            if (shown.isEmpty()) item {
                Text("در این بازه داده‌ای ثبت نشده.", color = Muted, fontSize = 13.sp)
            }
            items(shown, key = { it.uid }) { a -> HRow(a) }
        }
    }
}

@Composable
fun HSummary(apps: List<HApp>) {
    val dlApps = apps.count { it.down >= DL_MIN }
    val down = apps.sumOf { it.down }
    val bg = apps.sumOf { it.bgDown }
    val fg = apps.sumOf { it.fgDown }
    val un = apps.sumOf { it.unDown }
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp)) {
        Row {
            Column(Modifier.weight(1f)) {
                Text("برنامه‌های دارای مصرف اینترنت", color = Muted, fontSize = 11.sp)
                Text("${apps.size}", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 22.sp)
            }
            Column(Modifier.weight(1f)) {
                Text("برنامه‌های دانلودکننده", color = Muted, fontSize = 11.sp)
                Text("$dlApps", color = Accent, fontWeight = FontWeight.Bold, fontSize = 22.sp)
            }
        }
        Spacer(Modifier.height(12.dp))
        Text("کل دریافت: ${fmt(down)}", color = Color.White, fontWeight = FontWeight.Bold)
        Text(
            "پس‌زمینه ${fmt(bg)}  •  پیش‌زمینه ${fmt(fg)}" + if (un > 0) "  •  نامشخص ${fmt(un)}" else "",
            color = Muted, fontSize = 12.sp
        )
        if (un > 0) Text(
            "برای تفکیک پیش‌زمینه / پس‌زمینه، Usage access را فعال کن.",
            color = Orange, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp)
        )
    }
}

@Composable
fun HRow(a: HApp) {
    val ctx = LocalContext.current
    var open by remember { mutableStateOf(false) }
    val icon = remember(a.pkg) { History.icon(ctx, a.pkg) }
    val dl = a.down >= DL_MIN
    Column {
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(if (dl) Accent else CardBg)
                .clickable { open = !open }.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val fgc = if (dl) OnAccent else Color.White
            val sub = if (dl) OnAccent.copy(alpha = .7f) else Muted
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
                Text(
                    ltr("BG ↓${fmt(a.bgDown)} ↑${fmt(a.bgUp)}"), color = sub, fontSize = 11.sp
                )
                Text(
                    ltr("FG ↓${fmt(a.fgDown)} ↑${fmt(a.fgUp)}") +
                        if (a.unDown + a.unUp > 0) ltr("  ?  ↓${fmt(a.unDown)}") else "",
                    color = sub, fontSize = 11.sp
                )
                Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    if (dl) Badge("دانلود", OnAccent, OnAccent.copy(alpha = .12f))
                    if (a.bgDown + a.bgUp > 0) Badge("پس‌زمینه", if (dl) OnAccent else Violet)
                    if (a.fgDown + a.fgUp > 0) Badge("پیش‌زمینه", if (dl) OnAccent else Accent)
                    if (a.system) Badge("سیستمی", sub)
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(fmt(a.down), color = fgc, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(ltr("↑ ${fmt(a.up)}"), color = sub, fontSize = 11.sp)
            }
        }
        AnimatedVisibility(open && a.dests.isNotEmpty()) {
            Column(
                Modifier.fillMaxWidth().padding(top = 8.dp).clip(RoundedCornerShape(24.dp))
                    .background(Paper).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(ltr(a.pkg), color = Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace, maxLines = 1)
                a.dests.take(40).forEach { d ->
                    Column(Modifier.fillMaxWidth()) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                ltr(d.dest), color = Ink, fontSize = 13.sp, fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f),
                                maxLines = 1, overflow = TextOverflow.Ellipsis
                            )
                            Badge(d.proto, Ink, Ink.copy(alpha = .08f))
                        }
                        Text(
                            "پورت ${portName(d.port)}   دریافت ${fmt(d.down)}   ارسال ${fmt(d.up)}" +
                                if (d.bgDown > 0) "   (پس‌زمینه ${fmt(d.bgDown)})" else "",
                            color = Muted, fontSize = 11.sp
                        )
                    }
                }
            }
        }
    }
}
