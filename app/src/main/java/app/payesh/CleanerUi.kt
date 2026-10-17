package app.payesh

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
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
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.InsertDriveFile
import androidx.compose.material.icons.rounded.MusicNote
import androidx.compose.material.icons.rounded.Videocam
import androidx.compose.material.icons.rounded.Image as ImageIcon
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TYPE_LABELS = listOf("همه", "تصویر", "ویدیو", "صوت", "سند", "فشرده / برنامه", "سایر")

private fun typeColor(t: Int): Color = when (t) {
    1 -> Accent; 2 -> Violet; 3 -> Orange; 4 -> Color(0xFF7DD3FC); 5 -> Color(0xFFF0ABFC); else -> Muted
}

private fun typeIcon(t: Int): ImageVector = when (t) {
    1 -> Icons.Rounded.ImageIcon; 2 -> Icons.Rounded.Videocam; 3 -> Icons.Rounded.MusicNote
    4 -> Icons.Rounded.Description; 5 -> Icons.Rounded.Archive; else -> Icons.Rounded.InsertDriveFile
}

@Composable
fun CleanerScreen(page: Int, onPage: (Int) -> Unit) {
    val ctx = LocalContext.current
    val st by CleanerState.status.collectAsState()
    val all by CleanerState.groups.collectAsState()
    val msg by CleanerState.message.collectAsState()
    var access by remember { mutableStateOf(Dedup.hasAccess(ctx)) }
    var filter by remember { mutableStateOf(0) }
    var confirm by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { while (true) { access = Dedup.hasAccess(ctx); delay(1500) } }

    val legacy = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        access = Dedup.hasAccess(ctx)
    }
    fun askAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            ctx.startActivity(
                Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${ctx.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        } else legacy.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
    }

    val shown = all.filter { filter == 0 || it.type == (if (filter == 6) 0 else filter) }
    val delCount = shown.sumOf { it.toDelete().size }
    val delBytes = shown.sumOf { g -> g.toDelete().size * g.size }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 110.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Text(
                "پاکسازی\nفایل‌های تکراری", color = Color.White, fontSize = 34.sp,
                fontWeight = FontWeight.Bold, lineHeight = 40.sp, modifier = Modifier.padding(vertical = 6.dp)
            )
        }
        item { PageSwitch(page, onPage) }
        if (!access) item {
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(20.dp))
                    .border(1.dp, Accent.copy(alpha = .6f), RoundedCornerShape(20.dp))
                    .clickable { askAccess() }.padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Rounded.Warning, null, tint = Accent)
                Spacer(Modifier.width(10.dp))
                Text(
                    "برای اسکن و حذف نسخه‌های اضافه، دسترسی «همهٔ فایل‌ها» لازم است. اینجا بزن و برای «پایش» فعالش کن.",
                    color = Color.White, fontSize = 12.sp
                )
            }
        }
        item {
            Hero(
                st = st, count = delCount, bytes = delBytes, groupsCount = shown.size,
                hasResults = all.isNotEmpty(), msg = msg,
                onStart = { if (access) CleanerState.start(ctx) else askAccess() },
                onCancel = { CleanerState.cancelScan() },
                onDelete = { confirm = true }
            )
        }
        item {
            Text(
                "فقط حافظهٔ مشترک گوشی و SD اسکن می‌شود؛ پوشهٔ داخلی برنامه‌ها (Android/data) را خود اندروید قفل کرده و قابل دسترسی نیست. " +
                    "فایل‌های کوچک‌تر از ۴ کیلوبایت و پوشه‌های مخفی نادیده گرفته می‌شوند. تکراری بودن با مقایسهٔ کامل محتوا (SHA-256) تشخیص داده می‌شود، نه با اسم.",
                color = Muted, fontSize = 11.sp
            )
        }
        if (all.isNotEmpty()) {
            item {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(TYPE_LABELS.indices.toList()) { i -> Pill(TYPE_LABELS[i], filter == i, { filter = i }) }
                }
            }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Pill("انتخاب پیش‌فرض", false, { shown.forEach { it.skip.clear() } })
                    Pill("هیچ‌کدام", false, { shown.forEach { g -> g.files.forEach { f -> if (f.path !in g.skip) g.skip.add(f.path) } } })
                }
            }
            items(shown, key = { g -> g.files[0].path + g.size }) { g -> GroupCard(g) }
        }
    }

    if (confirm) AlertDialog(
        onDismissRequest = { confirm = false },
        containerColor = CardBg,
        title = { Text("حذف نسخه‌های اضافه؟", color = Color.White, fontWeight = FontWeight.Bold) },
        text = {
            Text(
                "$delCount فایل (${fmt(delBytes)}) حذف می‌شود. از هر گروه یک فایل اصلی باقی می‌ماند. این کار برگشت‌پذیر نیست.",
                color = Muted
            )
        },
        confirmButton = {
            Text(
                "حذف", color = Orange, fontWeight = FontWeight.Bold,
                modifier = Modifier.clickable { confirm = false; CleanerState.delete(ctx, shown) }.padding(12.dp)
            )
        },
        dismissButton = {
            Text("انصراف", color = Color.White, modifier = Modifier.clickable { confirm = false }.padding(12.dp))
        }
    )
}

@Composable
fun HeroBtn(text: String, filled: Boolean, enabled: Boolean = true, onClick: () -> Unit) {
    Box(
        Modifier.clip(RoundedCornerShape(18.dp))
            .background(if (filled) OnAccent.copy(alpha = if (enabled) 1f else .35f) else OnAccent.copy(alpha = .10f))
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 18.dp, vertical = 13.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(text, color = if (filled) Accent else OnAccent, fontWeight = FontWeight.Bold, fontSize = 13.sp)
    }
}

@Composable
fun Hero(
    st: CStatus, count: Int, bytes: Long, groupsCount: Int, hasResults: Boolean, msg: String?,
    onStart: () -> Unit, onCancel: () -> Unit, onDelete: () -> Unit
) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(28.dp)).background(Accent).padding(20.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(40.dp).clip(CircleShape).background(OnAccent.copy(alpha = .12f)),
                contentAlignment = Alignment.Center
            ) { Icon(Icons.Rounded.ContentCopy, null, tint = OnAccent) }
            Spacer(Modifier.width(12.dp))
            Text("یافتن نسخه‌های کپیِ یک فایل", color = OnAccent, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        }
        Spacer(Modifier.height(14.dp))
        when (st.state) {
            1 -> {
                Text(st.phase, color = OnAccent, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                Spacer(Modifier.height(8.dp))
                if (st.total > 0) {
                    val f = (st.done.toFloat() / st.total.toFloat()).coerceIn(0f, 1f)
                    Box(Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)).background(OnAccent.copy(alpha = .15f))) {
                        Box(Modifier.fillMaxWidth(f).fillMaxHeight().background(OnAccent))
                    }
                    Text("${st.done} از ${st.total} فایل", color = OnAccent, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
                } else {
                    Text("${st.done} فایل دیده شد", color = OnAccent, fontSize = 12.sp)
                }
                Text(
                    ltr(st.note), color = OnAccent.copy(alpha = .7f), fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 4.dp)
                )
                Spacer(Modifier.height(14.dp))
                HeroBtn("لغو", false, true, onCancel)
            }
            3 -> Text("در حال حذف نسخه‌های اضافه… لطفاً صبر کن", color = OnAccent, fontWeight = FontWeight.Bold)
            2 -> if (hasResults) {
                Text(fmt(bytes), color = OnAccent, fontWeight = FontWeight.Bold, fontSize = 40.sp)
                Text(
                    "قابل آزادسازی • $count نسخهٔ اضافه در $groupsCount گروه",
                    color = OnAccent.copy(alpha = .8f), fontSize = 12.sp
                )
                if (msg != null) Text(msg, color = OnAccent, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 6.dp))
                Spacer(Modifier.height(14.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    HeroBtn("حذف انتخاب‌شده‌ها", true, count > 0, onDelete)
                    HeroBtn("اسکن دوباره", false, true, onStart)
                }
            } else {
                Text(msg ?: "فایل تکراری پیدا نشد.", color = OnAccent, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(14.dp))
                HeroBtn("اسکن دوباره", false, true, onStart)
            }
            else -> {
                Text(
                    "همهٔ نسخه‌های کپیِ یک فایل را پیدا می‌کنم و فقط نسخه‌های اضافه را حذف می‌کنم؛ از هر گروه یک فایل اصلی می‌ماند.",
                    color = OnAccent, fontSize = 13.sp
                )
                Spacer(Modifier.height(14.dp))
                HeroBtn("شروع اسکن", true, true, onStart)
            }
        }
    }
}

@Composable
fun GroupCard(g: DGroup) {
    var open by remember { mutableStateOf(false) }
    val keepFile = g.files.first { it.path == g.keep }
    val del = g.toDelete()
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg)) {
        Row(
            Modifier.fillMaxWidth().clickable { open = !open }.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                Modifier.size(46.dp).clip(RoundedCornerShape(14.dp)).background(typeColor(g.type).copy(alpha = .18f)),
                contentAlignment = Alignment.Center
            ) { Icon(typeIcon(g.type), null, tint = typeColor(g.type)) }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    File(keepFile.path).name, color = Color.White, fontWeight = FontWeight.Bold,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                Text("${g.files.size} نسخه • هر کدام ${fmt(g.size)}", color = Muted, fontSize = 11.sp)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    "−${fmt(g.size * del.size)}", fontWeight = FontWeight.Bold, fontSize = 15.sp,
                    color = if (del.isEmpty()) Muted else Accent
                )
                Text("${del.size} حذف", color = Muted, fontSize = 11.sp)
            }
        }
        AnimatedVisibility(open) {
            Column(
                Modifier.padding(start = 14.dp, end = 14.dp, bottom = 14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) { g.files.forEach { CopyRow(g, it) } }
        }
    }
}

@Composable
fun CopyRow(g: DGroup, f: DFile) {
    val isKeep = g.keep == f.path
    val willDelete = !isKeep && f.path !in g.skip
    val fi = File(f.path)
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Color.White.copy(alpha = .05f))
            .clickable(enabled = !isKeep) { if (willDelete) g.skip.add(f.path) else g.skip.remove(f.path) }
            .padding(10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier.size(24.dp).clip(CircleShape)
                .background(if (isKeep) Accent else if (willDelete) Orange else Color.Transparent)
                .then(if (!isKeep && !willDelete) Modifier.border(1.5.dp, Muted, CircleShape) else Modifier),
            contentAlignment = Alignment.Center
        ) {
            if (isKeep) Icon(Icons.Rounded.Check, null, tint = OnAccent, modifier = Modifier.size(16.dp))
            else if (willDelete) Icon(Icons.Rounded.Delete, null, tint = Color.Black, modifier = Modifier.size(14.dp))
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(fi.name, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(ltr(fi.parent ?: ""), color = Muted, fontSize = 10.sp, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(ltr(SimpleDateFormat("yyyy/MM/dd HH:mm", Locale.US).format(Date(f.modified))), color = Muted, fontSize = 10.sp)
        }
        if (isKeep) Badge("نگه داشته می‌شود", Accent)
        else Text(
            "اصلی کن", color = Accent, fontSize = 11.sp, fontWeight = FontWeight.Bold,
            modifier = Modifier.clip(RoundedCornerShape(10.dp))
                .clickable { g.keep = f.path; g.skip.remove(f.path) }.padding(8.dp)
        )
    }
}
