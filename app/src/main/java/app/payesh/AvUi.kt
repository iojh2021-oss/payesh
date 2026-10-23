package app.payesh

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.app.NotificationManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private val Danger = Color(0xFFFF5A5F)

private fun scoreColor(s: Int): Color = when {
    s < 0 -> Muted
    s >= 80 -> Accent
    s >= 50 -> Orange
    else -> Danger
}

@Composable
fun Toggle(on: Boolean, onChange: (Boolean) -> Unit) {
    val x by animateDpAsState(if (on) 24.dp else 3.dp, label = "toggle")
    Box(
        Modifier.width(54.dp).height(30.dp).clip(RoundedCornerShape(15.dp))
            .background(if (on) Accent else Color(0xFF2A2F24)).clickable { onChange(!on) }
    ) {
        Box(
            Modifier.offset(x = x, y = 3.dp).size(24.dp).clip(CircleShape)
                .background(if (on) OnAccent else Muted)
        )
    }
}

@Composable
fun AvBtn(text: String, filled: Boolean, color: Color = Accent, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Box(
        modifier.clip(RoundedCornerShape(18.dp))
            .background(if (filled) color else Color.White.copy(alpha = .07f))
            .clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 13.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(text, color = if (filled) OnAccent else Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
    }
}

@Composable
fun AntivirusScreen(page: Int, onPage: (Int) -> Unit) {
    val ctx = LocalContext.current
    val status by AvState.status.collectAsState()
    val findings by AvState.findings.collectAsState()
    val posture by AvState.posture.collectAsState()
    val enabled by AvState.enabled.collectAsState()
    val counts by AvState.counts.collectAsState()
    val quar by AvState.quarantine.collectAsState()
    val score by AvState.score.collectAsState()
    val note by AvState.note.collectAsState()
    val nets by AvState.netThreats.collectAsState()

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 110.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Text(
                "آنتی‌ویروس\nمحافظ هوشمند", color = Color.White, fontSize = 34.sp,
                fontWeight = FontWeight.Bold, lineHeight = 40.sp, modifier = Modifier.padding(vertical = 6.dp)
            )
        }
        item { PageSwitch(page, onPage) }
        item {
            ShieldHero(
                status, score, enabled,
                onToggle = { AvState.setEnabled(ctx, it) },
                onScan = { AvState.scan(ctx, it) },
                onCancel = { AvState.cancelScan() }
            )
        }
        item { GuardCard(ctx) }
        item { AppLockCard(ctx) }
        item { DashboardCard(ctx) }
        item {
            val last = counts.lastScan
            val ago = if (last == 0L) "—" else {
                val m = (System.currentTimeMillis() - last) / 60_000
                if (m < 60) "$m دقیقه" else "${m / 60} ساعت"
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AvStat("برنامه", "${counts.apps}", Accent, Modifier.weight(1f))
                AvStat("فایل", "${counts.files}", Violet, Modifier.weight(1f))
                AvStat("تهدید", "${findings.size}", if (findings.isEmpty()) Accent else Danger, Modifier.weight(1f))
                AvStat("آخرین اسکن", ago, Orange, Modifier.weight(1f))
            }
        }
        if (note != null) item { Text(note ?: "", color = Orange, fontSize = 12.sp) }

        item {
            Text(
                "تهدیدها و موارد مشکوک (${findings.size})", color = Color.White, fontSize = 18.sp,
                fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 6.dp)
            )
        }
        if (counts.lastScan == 0L && status.state != 1) item {
            Text("هنوز اسکنی انجام نشده. «اسکن هوشمند» را بزن.", color = Muted, fontSize = 13.sp)
        } else if (findings.isEmpty() && status.state != 1) item {
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg).padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Rounded.Check, null, tint = Accent)
                Spacer(Modifier.width(10.dp))
                Text("تهدیدی پیدا نشد.", color = Color.White, fontWeight = FontWeight.Bold)
            }
        }
        items(findings, key = { it.id }) { f -> FindingCard(f, ctx) }

        if (nets.isNotEmpty()) {
            item {
                Text(
                    "ترافیک شبکهٔ مخرب (${nets.size})", color = Color.White, fontSize = 18.sp,
                    fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 6.dp)
                )
            }
            items(nets, key = { it.time.toString() + it.domain + it.uid }) { n -> NetRow(n) }
        }

        if (quar.isNotEmpty()) {
            item {
                Text(
                    "قرنطینه (${quar.size})", color = Color.White, fontSize = 18.sp,
                    fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 6.dp)
                )
            }
            items(quar, key = { it.id }) { q -> QuarRow(q, ctx) }
        }

        item {
            Text(
                "وضعیت امنیتی دستگاه", color = Color.White, fontSize = 18.sp,
                fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 6.dp)
            )
        }
        items(posture, key = { it.title }) { p -> PostureRow(p) }

        item { DbCard(ctx) }
        item { SigCard(ctx) }
        item {
            Text(
                "روش‌های به‌کاررفته: تحلیل رفتاری و ترکیب دسترسی‌ها (الگوی تروجان بانکی، استاکرویر، Dropper)، بررسی منبع نصب و گواهی امضا، " +
                    "یافتن Payload تعبیه‌شده در APK، تشخیص فایل اجرایی پنهان‌شده با پسوند جعلی، پایگاه تهدیدهای بروزرسانی‌شونده از گیت‌هاب (هش، پکیج، گواهی، دامنهٔ مخرب)، " +
                    "و پایش لحظه‌ای نصب برنامه‌ها. این ابزار جایگزین آنتی‌ویروس‌های تجاری با موتور و پایگاه داده اختصاصی نیست؛ " +
                    "یک لایهٔ تکمیلی است. نتیجهٔ «مشکوک» لزوماً بدافزار بودن را ثابت نمی‌کند.",
                color = Muted, fontSize = 11.sp
            )
        }
    }
}

@Composable
fun AvStat(title: String, value: String, color: Color, modifier: Modifier) {
    Column(
        modifier.clip(RoundedCornerShape(16.dp)).background(CardBg).padding(vertical = 12.dp, horizontal = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(value, color = color, fontWeight = FontWeight.Bold, fontSize = 15.sp, maxLines = 1)
        Text(title, color = Muted, fontSize = 10.sp, maxLines = 1)
    }
}

@Composable
fun ShieldHero(
    status: AvStatus, score: Int, enabled: Boolean,
    onToggle: (Boolean) -> Unit, onScan: (Int) -> Unit, onCancel: () -> Unit
) {
    val scanning = status.state == 1
    val inf = rememberInfiniteTransition(label = "av")
    val rot by inf.animateFloat(
        initialValue = 0f, targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(2200, easing = LinearEasing)), label = "rot"
    )
    val pulse by inf.animateFloat(
        initialValue = 0.55f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(900), RepeatMode.Reverse), label = "pulse"
    )
    val target = if (scanning) {
        if (status.total > 0) (status.done.toFloat() / status.total).coerceIn(0f, 1f) else 0.05f
    } else if (score >= 0) score / 100f else 0f
    val prog by animateFloatAsState(target, tween(700), label = "prog")
    val ring = if (scanning) Accent else scoreColor(score)

    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(28.dp)).background(CardBg).padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(Modifier.size(210.dp), contentAlignment = Alignment.Center) {
            Canvas(Modifier.size(210.dp)) {
                val sw = 18.dp.toPx()
                val inset = sw / 2 + 10.dp.toPx()
                val sz = Size(size.width - inset * 2, size.height - inset * 2)
                drawArc(Color.White.copy(alpha = .07f), 0f, 360f, false, Offset(inset, inset), sz, style = Stroke(sw))
                drawArc(
                    ring.copy(alpha = if (scanning) pulse else 1f), -90f, 360f * prog, false,
                    Offset(inset, inset), sz, style = Stroke(sw, cap = StrokeCap.Round)
                )
                if (scanning) {
                    val o = 9.dp.toPx()
                    drawArc(
                        Accent.copy(alpha = .45f), rot, 55f, false, Offset(inset - o, inset - o),
                        Size(sz.width + o * 2, sz.height + o * 2), style = Stroke(3.dp.toPx(), cap = StrokeCap.Round)
                    )
                }
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                if (scanning) {
                    Text(
                        if (status.total > 0) "${(prog * 100).toInt()}٪" else "…",
                        color = Color.White, fontSize = 38.sp, fontWeight = FontWeight.Bold
                    )
                    Text("در حال اسکن", color = Accent, fontSize = 12.sp)
                } else {
                    Text(
                        if (score >= 0) "$score" else "؟", color = ring, fontSize = 52.sp, fontWeight = FontWeight.Bold
                    )
                    Text(
                        when {
                            score < 0 -> "هنوز اسکن نشده"
                            score >= 80 -> "دستگاه ایمن است"
                            score >= 50 -> "نیاز به توجه"
                            else -> "در خطر"
                        },
                        color = ring, fontSize = 12.sp, fontWeight = FontWeight.Bold
                    )
                }
            }
        }
        if (scanning) {
            Text(status.phase, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp, modifier = Modifier.padding(top = 4.dp))
            Text(
                ltr(status.note), color = Muted, fontSize = 10.sp, fontFamily = FontFamily.Monospace,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            if (status.total > 0) Text("${status.done} از ${status.total}", color = Muted, fontSize = 11.sp)
        }
        Spacer(Modifier.height(14.dp))
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(Color.White.copy(alpha = .05f)).padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text("محافظت لحظه‌ای", color = Color.White, fontWeight = FontWeight.Bold)
                Text(
                    if (enabled) "فعال: نصب برنامه‌ها، APK دانلودی و دسترسی‌های خطرناک پایش می‌شود"
                    else "خاموش است",
                    color = if (enabled) Accent else Muted, fontSize = 11.sp
                )
            }
            Toggle(enabled, onToggle)
        }
        Spacer(Modifier.height(12.dp))
        if (scanning) {
            AvBtn("لغو اسکن", true, Orange, Modifier.fillMaxWidth(), onCancel)
        } else {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AvBtn("اسکن هوشمند", true, Accent, Modifier.weight(1f)) { onScan(0) }
                AvBtn("اسکن کامل", false, Accent, Modifier.weight(1f)) { onScan(1) }
            }
        }
    }
}

@Composable
fun FindingCard(f: Finding, ctx: Context) {
    var open by remember { mutableStateOf(false) }
    val col = if (f.level == 2) Danger else Orange
    val icon = remember(f.pkg) { f.pkg?.let { History.icon(ctx, it) } }
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg)
            .border(1.dp, col.copy(alpha = .45f), RoundedCornerShape(24.dp))
    ) {
        Row(
            Modifier.fillMaxWidth().clickable { open = !open }.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (icon != null) {
                Image(icon, null, Modifier.size(46.dp).clip(RoundedCornerShape(14.dp)))
            } else {
                Box(
                    Modifier.size(46.dp).clip(RoundedCornerShape(14.dp)).background(col.copy(alpha = .18f)),
                    contentAlignment = Alignment.Center
                ) { Icon(Icons.Rounded.Warning, null, tint = col) }
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(f.title, color = Color.White, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    ltr(f.sub), color = Muted, fontSize = 10.sp, fontFamily = FontFamily.Monospace,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                Row(Modifier.padding(top = 4.dp)) { Badge(if (f.level == 2) "خطرناک" else "مشکوک", col) }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("${f.score}", color = col, fontWeight = FontWeight.Bold, fontSize = 22.sp)
                Text("ریسک", color = Muted, fontSize = 10.sp)
            }
        }
        AnimatedVisibility(open) {
            Column(Modifier.padding(start = 14.dp, end = 14.dp, bottom = 14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                f.reasons.forEach { Text("• $it", color = Color.White, fontSize = 12.sp) }
                Spacer(Modifier.height(4.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (f.kind == 0 && f.pkg != null) {
                        AvBtn("حذف برنامه", true, Danger, Modifier.weight(1f)) {
                            ctx.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.pkg}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                        }
                        AvBtn("اطلاعات", false, Accent, Modifier.weight(1f)) {
                            ctx.startActivity(
                                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${f.pkg}"))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    } else {
                        AvBtn("قرنطینه", true, Orange, Modifier.weight(1f)) { AvState.quarantineFile(ctx, f) }
                        AvBtn("حذف", true, Danger, Modifier.weight(1f)) { AvState.deleteFile(f) }
                    }
                    AvBtn("اعتماد", false, Accent, Modifier.weight(1f)) { AvState.trust(ctx, f.id) }
                }
            }
        }
    }
}

@Composable
fun QuarRow(q: QItem, ctx: Context) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg).padding(14.dp)) {
        Text(q.name, color = Color.White, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(ltr(q.orig), color = Muted, fontSize = 10.sp, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AvBtn("بازگردانی", false, Accent, Modifier.weight(1f)) { AvState.restore(ctx, q) }
            AvBtn("حذف همیشگی", true, Danger, Modifier.weight(1f)) { AvState.deleteQuarantined(ctx, q) }
        }
    }
}

@Composable
fun PostureRow(p: Posture) {
    val col = if (p.ok) Accent else if (p.severity >= 2) Danger else Orange
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg).padding(14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier.size(30.dp).clip(CircleShape).background(col.copy(alpha = .18f)),
            contentAlignment = Alignment.Center
        ) { Icon(if (p.ok) Icons.Rounded.Check else Icons.Rounded.Warning, null, tint = col, modifier = Modifier.size(18.dp)) }
        Spacer(Modifier.width(12.dp))
        Column {
            Text(p.title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text(p.detail, color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
fun SigCard(ctx: Context) {
    var count by remember { mutableStateOf(AvPrefs.sigCount(ctx)) }
    var msg by remember { mutableStateOf<String?>(null) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            val n = AvPrefs.importSignatures(ctx, uri)
            count = AvPrefs.sigCount(ctx)
            msg = "$n امضای جدید اضافه شد"
        }
    }
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp)) {
        Text("پایگاه امضای محلی: $count مورد", color = Color.White, fontWeight = FontWeight.Bold)
        Text(
            "یک فایل متنی با هش SHA-256 بدافزارها اضافه کن (هر خط یک هش، اختیاری با نام بعد از آن). " +
                "برای آزمایش، فایل استاندارد EICAR را از eicar.org دانلود کن؛ باید به‌عنوان تهدید پیدا شود.",
            color = Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp)
        )
        Spacer(Modifier.height(10.dp))
        AvBtn("افزودن فهرست هش", false, Accent, Modifier.fillMaxWidth()) { picker.launch(arrayOf("*/*")) }
        if (msg != null) Text(msg ?: "", color = Accent, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
    }
}


@Composable
fun NetRow(n: NetThreat) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp)).background(CardBg)
            .border(1.dp, Danger.copy(alpha = .45f), RoundedCornerShape(20.dp)).padding(14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier.size(36.dp).clip(CircleShape).background(Danger.copy(alpha = .18f)),
            contentAlignment = Alignment.Center
        ) { Icon(Icons.Rounded.Warning, null, tint = Danger, modifier = Modifier.size(20.dp)) }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(n.label, color = Color.White, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(ltr(n.domain), color = Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Badge(n.family, Danger)
    }
}

@Composable
fun DbCard(ctx: Context) {
    val info by AvDbStore.info.collectAsState()
    val busy by AvDbStore.busy.collectAsState()
    val msg by AvDbStore.message.collectAsState()
    var auto by remember { mutableStateOf(AvDbStore.auto(ctx)) }
    var url by remember { mutableStateOf(AvDbStore.url(ctx)) }
    LaunchedEffect(Unit) { withContext(Dispatchers.IO) { AvDbStore.load(ctx) } }
    val last = info.lastCheck
    val ago = if (last == 0L) "هنوز بررسی نشده" else {
        val m = (System.currentTimeMillis() - last) / 60_000
        if (m < 60) "$m دقیقه پیش" else "${m / 60} ساعت پیش"
    }
    val sigCol = if (info.signed) Accent else if (info.signing) Orange else Muted
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("پایگاه تهدیدها (بروزرسانی از گیت‌هاب)", color = Color.White, fontWeight = FontWeight.Bold)
                Text(
                    "نسخهٔ ${info.version}" + (if (info.updated.isNotEmpty()) " • ${info.updated}" else "") + " • آخرین بررسی: $ago",
                    color = Muted, fontSize = 11.sp
                )
                Text(
                    "${info.hashes} هش • ${info.pkgs} پکیج • ${info.certs} گواهی • ${info.domains} دامنه • ${info.rules} قانون رفتاری",
                    color = Accent, fontSize = 11.sp
                )
                Text(
                    if (info.signed) "امضای دیجیتال: معتبر ✓"
                    else if (info.signing) "امضای دیجیتال: هنوز بروزرسانی امضاشده‌ای دریافت نشده"
                    else "امضای دیجیتال: غیرفعال (کلید عمومی در برنامه نیست؛ فقط هش‌ها بررسی می‌شوند)",
                    color = sigCol, fontSize = 11.sp
                )
                if (info.sources.isNotEmpty()) Text("منابع: ${info.sources}", color = Muted, fontSize = 10.sp)
            }
            Toggle(auto) { auto = it; AvDbStore.setAuto(ctx, it) }
        }
        Text(
            if (auto) "هر ۶ ساعت یک‌بار خودکار بروزرسانی می‌شود. هر بروزرسانی قبل از استفاده بررسی می‌شود: امضا، نسخه (ضد بازگشت به قدیم)، هش فایل، و تعداد رکوردها."
            else "بروزرسانی خودکار خاموش است.",
            color = Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp)
        )
        Spacer(Modifier.height(10.dp))
        AvBtn(if (busy) "در حال بروزرسانی…" else "بروزرسانی الان", true, Accent, Modifier.fillMaxWidth()) {
            AvDbStore.updateAsync(ctx)
        }
        if (msg != null) Text(msg ?: "", color = Orange, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(
            value = url, onValueChange = { url = it; AvDbStore.setUrl(ctx, it) }, singleLine = true,
            label = { Text("آدرس پایهٔ پایگاه (https)", color = Muted) },
            shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun CheckRow(ok: Boolean, text: String, onFix: (() -> Unit)?) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp))
            .then(if (!ok && onFix != null) Modifier.clickable { onFix() } else Modifier).padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(if (ok) Icons.Rounded.Check else Icons.Rounded.Warning, null, tint = if (ok) Accent else Orange, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, color = if (ok) Color.White else Orange, fontSize = 12.sp)
    }
}

/** Real-time protection: what is being watched, prerequisites, and the "ask before scan" switch. */
@Composable
fun GuardCard(ctx: Context) {
    val enabled by AvState.enabled.collectAsState()
    val watched by AvGuardState.watched.collectAsState()
    val last by AvGuardState.last.collectAsState()
    val alive by AvGuardState.running.collectAsState()
    val events by AvGuardState.events.collectAsState()
    val lastNote by AvGuardState.note.collectAsState()
    var ask by remember { mutableStateOf(AvPrefs.askBeforeScan(ctx)) }
    var tick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) { while (true) { delay(2000); tick++ } }
    val files = remember(tick) { Dedup.hasAccess(ctx) }
    val usage = remember(tick) { Fg.granted(ctx) }
    val notif = remember(tick) { try { ctx.getSystemService(NotificationManager::class.java).areNotificationsEnabled() } catch (_: Exception) { true } }

    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp)) {
        Text("محافظت لحظه‌ای: وضعیت و پیش‌نیازها", color = Color.White, fontWeight = FontWeight.Bold)
        Text(
            if (enabled) "فعال: هر نصبِ غیر Google Play اعلان می‌دهد، APK دانلودی فوراً شناسایی می‌شود، و هنگام باز شدن نصب‌کننده یادآوری می‌کند."
            else "خاموش است؛ کلید «محافظت لحظه‌ای» بالا را روشن کن.",
            color = if (enabled) Accent else Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp, bottom = 8.dp)
        )
        CheckRow(alive || !enabled, if (alive) "سرویس محافظ: در حال اجرا ✓" else if (enabled) "سرویس محافظ فعال نیست (احتمالاً سیستم بسته)؛ اینجا بزن تا دوباره راه بیفتد" else "سرویس محافظ: خاموش") {
            AvState.startGuard(ctx)
        }
        CheckRow(notif, if (notif) "اعلان‌ها مجازند" else "اعلان‌ها خاموش‌اند؛ اینجا بزن و روشن کن") {
            ctx.startActivity(
                Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
        CheckRow(files, if (files) "دسترسی همهٔ فایل‌ها: فعال ($watched پوشه تحت نظر)" else "برای شناسایی فوری دانلودها، دسترسی «همهٔ فایل‌ها» لازم است؛ اینجا بزن") {
            if (Build.VERSION.SDK_INT >= 30) ctx.startActivity(
                Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${ctx.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
        CheckRow(usage, if (usage) "Usage access: فعال (تشخیص باز شدن نصب‌کننده)" else "برای تشخیص باز شدن صفحهٔ نصب، Usage access لازم است؛ اینجا بزن") {
            ctx.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
        Spacer(Modifier.height(6.dp))
        Text("آخرین مورد بررسی‌شده: $last • رویدادهای فایل: $events", color = Muted, fontSize = 11.sp)
        Text(lastNote, color = Muted, fontSize = 11.sp)
        Spacer(Modifier.height(6.dp))
        AvBtn("ارسال اعلان آزمایشی", false, Accent, Modifier.fillMaxWidth()) {
            AvNotify.post(ctx, 4, "آزمایش اعلان", "اگر این پیام را می‌بینی، اعلان‌های آنتی‌ویروس درست کار می‌کنند.", true)
        }
        Spacer(Modifier.height(8.dp))
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Color.White.copy(alpha = .05f)).padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text("پرسیدن قبل از اسکن APK دانلودی", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Text(
                    if (ask) "بعد از دانلود اعلانی با «اسکن الان» می‌آید و فقط با اجازهٔ تو اسکن می‌شود."
                    else "هر APK دانلودی بدون پرسش اسکن و نتیجه اعلام می‌شود.",
                    color = Muted, fontSize = 11.sp
                )
            }
            Toggle(ask) { ask = it; AvPrefs.setAskBeforeScan(ctx, it) }
        }
    }
}
