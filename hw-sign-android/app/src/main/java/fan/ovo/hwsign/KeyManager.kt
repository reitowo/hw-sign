package fan.ovo.hwsign

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import android.util.Log
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Manages cryptographic keys for hardware-backed authentication
 */
class KeyManager(private val context: Context) {

    // Constants
    private val keyAlias = "hw_sign_hardware_key"
    private val keyAccelId = "accel_key_id"
    
    // Cache for acceleration keys
    private var accelerationKeyPair: KeyPair? = null
    
    private val keystore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    private val sharedPreferences by lazy {
        EncryptedSharedPreferences.create(
            context,
            "auth_prefs",
            MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * Check the security level of the hardware key
     */
    @SuppressLint("SwitchIntDef")
    fun getKeySecurityLevel(): String {
        return try {
            val privateKey = keystore.getKey(keyAlias, null) as PrivateKey
            val keyFactory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo

            // Acceptable value: StrongBox, TEE, SecureHardware.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "UnknownSecure"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software"
                    KeyProperties.SECURITY_LEVEL_UNKNOWN -> "Unknown"
                    else -> "Unknown"
                }
            } else {
                if (keyInfo.isInsideSecureHardware) {
                    "SecureHardware"
                } else {
                    "Insecure"
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            "Unknown"
        }
    }

    /**
     * Generate a hardware-backed key pair using AndroidKeyStore
     * Attempts to use StrongBox if available, falls back to TEE
     */
    suspend fun generateHardwareKey(): KeyPair = withContext(Dispatchers.IO) {
        // Delete any existing key
        if (keystore.containsAlias(keyAlias)) {
            keystore.deleteEntry(keyAlias)
        }

        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )

        val builder = KeyGenParameterSpec.Builder(
            keyAlias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).apply {
            setDigests(KeyProperties.DIGEST_SHA256)
            setUserAuthenticationRequired(false)
            setUnlockedDeviceRequired(true)
        }

        var keyPair: KeyPair
        // First try StrongBox if available (API 28+)
        try {
            builder.setIsStrongBoxBacked(true)
            keyPairGenerator.initialize(builder.build())
            keyPair = keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            // Initialize with TEE fallback
            builder.setIsStrongBoxBacked(false)
            keyPairGenerator.initialize(builder.build())
            keyPair = keyPairGenerator.generateKeyPair()
        }

        val keyLevel = getKeySecurityLevel()
        Log.i(null, "successfully generated key pair in $keyLevel")
        keyPair
    }

    /**
     * Retrieve the existing hardware key pair from the Android KeyStore
     */
    private fun getHardwareKeyPair(): KeyPair? = try {
        if (keystore.containsAlias(keyAlias)) {
            val privateKey = keystore.getKey(keyAlias, null) as PrivateKey
            val publicKey = keystore.getCertificate(keyAlias).publicKey
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    } catch (e: Exception) {
        e.printStackTrace()
        null
    }

    /**
     * Store and retrieve acceleration key ID
     */
    fun storeAccelKeyId(keyId: String) {
        sharedPreferences.edit { putString(keyAccelId, keyId) }
    }

    fun getAccelKeyId(): String? = 
        sharedPreferences.getString(keyAccelId, null)

    fun clearAccelKeyId() {
        sharedPreferences.edit { remove(keyAccelId) }
    }

    /**
     * Sign data using the hardware key
     */
    suspend fun signWithHardwareKey(data: String): String = withContext(Dispatchers.IO) {
        val keyPair = getHardwareKeyPair() ?: throw SecurityException("Hardware key not found")
        
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(keyPair.private)
            update(data.toByteArray())
        }
        
        Base64.getEncoder().encodeToString(signature.sign())
    }

    /**
     * Generate an acceleration key pair in memory
     */
    fun generateAccelerationKey(): KeyPair {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        
        accelerationKeyPair = keyPair
        return keyPair
    }

    /**
     * Get the cached acceleration key pair or generate a new one
     */
    fun getOrCreateAccelerationKey(): KeyPair {
        return accelerationKeyPair ?: generateAccelerationKey()
    }

    /**
     * Sign data with a specific key pair
     */
    fun signWithKey(keyPair: KeyPair, data: String): String {
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(keyPair.private)
            update(data.toByteArray())
        }
        return Base64.getEncoder().encodeToString(signature.sign())
    }

    /**
     * Clear stored keys and identifiers
     */
    fun clearKeys() {
        accelerationKeyPair = null
        clearAccelKeyId()
        
        try {
            if (keystore.containsAlias(keyAlias)) {
                keystore.deleteEntry(keyAlias)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
