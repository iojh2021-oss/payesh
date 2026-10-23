package app.payesh

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.view.WindowManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection

class MainActivity : ComponentActivity() {
    private val vm: MainVM by viewModels()
    private var askedBattery = false

    private val vpnLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
            if (r.resultCode == RESULT_OK) startVpn()
        }

    private val notifLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Plog.init(this)
        AvState.init(this)
        AppLock.init(this)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)

        setContent {
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                MaterialTheme(colorScheme = darkColorScheme(primary = Accent, background = Bg, surface = CardBg)) {
                    val locked by AppLock.locked.collectAsState()
                    if (locked) LockScreen(this@MainActivity) else PayeshApp(vm, ::toggle, ::openUsage, ::openVpnSettings)
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        AppLock.onReturn(this)
        // With the lock on, hide the app from screenshots and the recent-apps preview.
        if (AppLock.enabled(this)) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun onStop() {
        AppLock.onLeave()
        super.onStop()
    }

    private fun toggle() {
        if (Tracker.running.value) {
            startService(Intent(this, PayeshVpnService::class.java).setAction(PayeshVpnService.ACTION_STOP))
        } else {
            val i = VpnService.prepare(this)
            if (i != null) vpnLauncher.launch(i) else startVpn()
        }
    }

    private fun startVpn() {
        startService(Intent(this, PayeshVpnService::class.java))
        // Ask once to exempt the app from battery optimization so the system never kills the monitor.
        val pm = getSystemService(PowerManager::class.java)
        if (!askedBattery && !pm.isIgnoringBatteryOptimizations(packageName)) {
            askedBattery = true
            try {
                startActivity(
                    Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName"))
                )
            } catch (_: Exception) {
            }
        }
    }

    private fun openUsage() { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }

    private fun openVpnSettings() { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
}
