package app.payesh

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.util.Base64
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * App-level lock (not the Android system lock screen). Accepts ANY characters: letters, digits, symbols, spaces.
 * The password is never stored: only a salted PBKDF2-SHA256 hash. Wrong attempts are rate-limited.
 */
object AppLock {
    const val MIN_LEN = 6
    private const val ITER = 120_000
    private const val GRACE_MS = 30_000L
    val locked = MutableStateFlow(false)
    @Volatile private var leftAt = 0L

    private fun p(ctx: Context) = ctx.applicationContext.getSharedPreferences("payesh_lock", Context.MODE_PRIVATE)
    fun enabled(ctx: Context) = p(ctx).contains("hash")

    fun init(ctx: Context) { locked.value = enabled(ctx) }

    /** Called when the app leaves the screen; relocks on return if it was away longer than the grace period. */
    fun onLeave() { leftAt = android.os.SystemClock.elapsedRealtime() }
    fun onReturn(ctx: Context) {
        if (enabled(ctx) && leftAt != 0L && android.os.SystemClock.elapsedRealtime() - leftAt > GRACE_MS) locked.value = true
    }

    private fun derive(pw: String, salt: ByteArray, iter: Int): ByteArray {
        val spec = PBEKeySpec(pw.toCharArray(), salt, iter, 256)
        return try { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded } finally { spec.clearPassword() }
    }

    fun set(ctx: Context, pw: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val h = derive(pw, salt, ITER)
        p(ctx).edit().putString("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString("hash", Base64.encodeToString(h, Base64.NO_WRAP))
            .putInt("iter", ITER).putInt("fails", 0).putLong("until", 0).apply()
    }

    /** Opens Android's own "set screen lock" screen (the real system lock; apps cannot set it themselves). */
    fun openSystemLockSettings(ctx: Context) {
        try {
            ctx.startActivity(Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: Exception) {
            try {
                ctx.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            } catch (_: Exception) {
            }
        }
    }

    fun clear(ctx: Context) { p(ctx).edit().clear().apply(); locked.value = false }

    /** Seconds the user must still wait because of earlier wrong attempts (0 = may try now). */
    fun waitSeconds(ctx: Context): Int {
        val d = p(ctx).getLong("until", 0) - System.currentTimeMillis()
        return if (d <= 0) 0 else ((d + 999) / 1000).toInt()
    }

    /** true = correct. Counts failures and applies growing delays after the 5th wrong attempt. */
    fun verify(ctx: Context, pw: String): Boolean {
        val sp = p(ctx)
        val salt = Base64.decode(sp.getString("salt", "") ?: return false, Base64.NO_WRAP)
        val want = Base64.decode(sp.getString("hash", "") ?: return false, Base64.NO_WRAP)
        val ok = MessageDigest.isEqual(derive(pw, salt, sp.getInt("iter", ITER)), want)
        if (ok) { sp.edit().putInt("fails", 0).putLong("until", 0).apply(); return true }
        val f = sp.getInt("fails", 0) + 1
        val delay = if (f >= 5) minOf(30L shl (f - 5).coerceAtMost(5), 900L) * 1000 else 0L
        sp.edit().putInt("fails", f).putLong("until", System.currentTimeMillis() + delay).apply()
        return false
    }
}

@Composable
fun LockScreen(ctx: Context) {
    var pw by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    fun submit() {
        if (busy || pw.isEmpty()) return
        val w = AppLock.waitSeconds(ctx)
        if (w > 0) { msg = "تلاش‌های زیاد. $w ثانیه صبر کن."; return }
        busy = true
        scope.launch {
            val ok = withContext(Dispatchers.Default) { AppLock.verify(ctx, pw) }
            busy = false
            if (ok) { pw = ""; msg = ""; AppLock.locked.value = false }
            else { pw = ""; val w2 = AppLock.waitSeconds(ctx); msg = if (w2 > 0) "رمز اشتباه است. $w2 ثانیه صبر کن." else "رمز اشتباه است." }
        }
    }
    Column(
        Modifier.fillMaxSize().background(Bg).padding(24.dp),
        verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("پایش قفل است", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 22.sp)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            pw, { pw = it }, label = { Text("رمز عبور") }, singleLine = true,
            visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = { submit() }),
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        AvBtn(if (show) "پنهان کردن رمز" else "نمایش رمز", false, Accent, Modifier.fillMaxWidth()) { show = !show }
        Spacer(Modifier.height(8.dp))
        AvBtn("باز کردن", true, Accent, Modifier.fillMaxWidth()) { submit() }
        if (msg.isNotEmpty()) Text(msg, color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
    }
}

@Composable
fun AppLockCard(ctx: Context) {
    var on by remember { mutableStateOf(AppLock.enabled(ctx)) }
    var cur by remember { mutableStateOf("") }
    var n1 by remember { mutableStateOf("") }
    var n2 by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(CardBg).padding(16.dp)) {
        Text("قفل برنامه با رمز", color = Color.White, fontWeight = FontWeight.Bold)
        Text(
            "رمز می‌تواند حروف، عدد و نمادها (مثل * & £ # ! + × %) باشد، حداقل ${AppLock.MIN_LEN} نویسه. " +
                "این قفل فقط ورود به خود برنامه است، نه قفل صفحهٔ اندروید. رمز فراموش‌شده بازیابی نمی‌شود (فقط با پاک کردن داده‌های برنامه).",
            color = Muted, fontSize = 11.sp
        )
        if (on) PwField(cur, "رمز فعلی", show) { cur = it }
        PwField(n1, if (on) "رمز جدید (برای تغییر)" else "رمز", show) { n1 = it }
        PwField(n2, "تکرار رمز", show) { n2 = it }
        Spacer(Modifier.height(8.dp))
        AvBtn(if (show) "پنهان کردن" else "نمایش رمزها", false, Accent, Modifier.fillMaxWidth()) { show = !show }
        Spacer(Modifier.height(6.dp))
        AvBtn(if (on) "تغییر رمز" else "فعال‌سازی قفل", true, Accent, Modifier.fillMaxWidth()) {
            if (n1.length < AppLock.MIN_LEN) { msg = "رمز باید حداقل ${AppLock.MIN_LEN} نویسه باشد"; return@AvBtn }
            if (n1 != n2) { msg = "تکرار رمز یکسان نیست"; return@AvBtn }
            scope.launch {
                if (on && !withContext(Dispatchers.Default) { AppLock.verify(ctx, cur) }) { msg = "رمز فعلی اشتباه است"; return@launch }
                withContext(Dispatchers.Default) { AppLock.set(ctx, n1) }
                on = true; cur = ""; n1 = ""; n2 = ""; msg = "رمز ذخیره شد ✓"
            }
        }
        if (on) {
            Spacer(Modifier.height(6.dp))
            AvBtn("خاموش کردن قفل", false, Accent, Modifier.fillMaxWidth()) {
                scope.launch {
                    if (!withContext(Dispatchers.Default) { AppLock.verify(ctx, cur) }) { msg = "رمز فعلی اشتباه است"; return@launch }
                    AppLock.clear(ctx); on = false; cur = ""; n1 = ""; n2 = ""; msg = "قفل خاموش شد"
                }
            }
        }
        Spacer(Modifier.height(10.dp))
        Text(
            "قفل صفحهٔ خود اندروید را فقط خود سیستم تنظیم می‌کند. این دکمه صفحهٔ رسمی آن را باز می‌کند؛ " +
                "در آنجا نوع قفل را «رمز عبور» بگذار تا حروف و نمادها قبول شوند.",
            color = Muted, fontSize = 11.sp
        )
        Spacer(Modifier.height(6.dp))
        AvBtn("تنظیم قفل صفحهٔ اندروید", false, Accent, Modifier.fillMaxWidth()) { AppLock.openSystemLockSettings(ctx) }
        if (msg.isNotEmpty()) Text(msg, color = Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
    }
}

@Composable
private fun PwField(v: String, label: String, show: Boolean, onChange: (String) -> Unit) {
    OutlinedTextField(
        v, onChange, label = { Text(label) }, singleLine = true,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth().padding(top = 6.dp)
    )
}
