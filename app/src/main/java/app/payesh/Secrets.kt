package app.payesh

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secrets stored on the phone (dashboard token, VirusTotal key) are sealed with AES-256-GCM using a key that lives in the
 * Android Keystore (hardware-backed where the phone has it) and never leaves it. A symmetric 256-bit key is the quantum-safe
 * choice for data at rest: the best known quantum attack (Grover) only halves its strength, and NIST and CNSA 2.0 both accept AES-256.
 * No post-quantum public-key algorithm is needed here, because nothing is being exchanged with anyone.
 * The name of the setting is bound in as authenticated data, so a sealed value cannot be moved to another setting.
 * Old plain values are sealed automatically the first time they are read.
 */
object Secrets {
    private const val ALIAS = "payesh_secrets_v1"
    private const val PREFIX = "enc1:"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }

    /** null = the Keystore is not usable (very rare); the caller then keeps the value as it is. */
    fun seal(name: String, plain: String): String? = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        c.updateAAD(name.toByteArray())
        val iv = c.iv
        val ct = c.doFinal(plain.toByteArray(Charsets.UTF_8))
        PREFIX + Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    } catch (e: Exception) {
        Plog.w("secrets: seal failed: " + e.javaClass.simpleName)
        null
    }

    fun open(name: String, stored: String): String? = try {
        val raw = Base64.decode(stored.removePrefix(PREFIX), Base64.NO_WRAP)
        val iv = raw.copyOfRange(0, 12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        c.updateAAD(name.toByteArray())
        String(c.doFinal(raw, 12, raw.size - 12), Charsets.UTF_8)
    } catch (e: Exception) {
        Plog.w("secrets: open failed: " + e.javaClass.simpleName)
        null
    }

    /** Reads a secret from [sp]; an old plain value is returned and sealed in place for next time. */
    fun read(sp: SharedPreferences, name: String): String {
        val stored = sp.getString(name, "") ?: ""
        if (stored.isEmpty()) return ""
        if (!stored.startsWith(PREFIX)) {
            seal(name, stored)?.let { sp.edit().putString(name, it).apply() }
            return stored
        }
        // a value that cannot be opened (key lost after a reset) is treated as empty so the user simply enters it again
        return open(name, stored) ?: ""
    }

    fun write(ed: SharedPreferences.Editor, name: String, value: String): SharedPreferences.Editor {
        if (value.isEmpty()) return ed.putString(name, "")
        return ed.putString(name, seal(name, value) ?: value)
    }
}
