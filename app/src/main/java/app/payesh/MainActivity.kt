package app.payesh

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection

class MainActivity : ComponentActivity() {
    private val vm: MainVM by viewModels()

    private val vpnLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
            if (r.resultCode == RESULT_OK) startVpn()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                MaterialTheme(colorScheme = darkColorScheme(primary = Accent, background = Bg, surface = CardBg)) {
                    PayeshApp(vm, ::toggle, ::openUsage)
                }
            }
        }
    }

    private fun toggle() {
        if (Tracker.running.value) {
            startService(Intent(this, PayeshVpnService::class.java).setAction(PayeshVpnService.ACTION_STOP))
        } else {
            val i = VpnService.prepare(this)
            if (i != null) vpnLauncher.launch(i) else startVpn()
        }
    }

    private fun startVpn() { startService(Intent(this, PayeshVpnService::class.java)) }

    private fun openUsage() { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }
}
