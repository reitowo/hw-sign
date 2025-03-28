package fan.ovo.hwsign

import android.content.Context
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

class AuthService(private val context: Context) {
    // Constants
    private val baseUrl = "https://dbcs-api.ovo.fan"
    private val jsonContentType = "application/json; charset=utf-8".toMediaType()
    private val keyAuthToken = "auth_token"
    
    // Key management
    public val keyManager = KeyManager(context)
    
    // Lazy initialization for network client
    private val client by lazy {
        OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
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
     * Store and retrieve auth token from encrypted preferences
     */
    private fun storeAuthToken(token: String) = 
        sharedPreferences.edit { putString(keyAuthToken, token) }

    private fun getAuthToken(): String? = 
        sharedPreferences.getString(keyAuthToken, null)

    /**
     * Register a new user
     */
    suspend fun register(username: String, password: String): Boolean = 
        withContext(Dispatchers.IO) {
            try {
                val json = JSONObject().apply {
                    put("username", username)
                    put("password", password)
                }

                val requestBody = json.toString().toRequestBody(jsonContentType)
                val request = Request.Builder()
                    .url("$baseUrl/register")
                    .post(requestBody)
                    .build()

                val response = client.newCall(request).await()
                
                if (response.isSuccessful) {
                    response.body?.string()?.let { body ->
                        val jsonResponse = JSONObject(body)
                        return@withContext jsonResponse.optString("message", "").isNotEmpty()
                    }
                }
                false
            } catch (e: Exception) {
                e.printStackTrace()
                false
            }
        }

    /**
     * Login using username/password and register hardware key
     */
    suspend fun login(username: String, password: String): Boolean = 
        withContext(Dispatchers.IO) {
            try {
                // Generate new hardware key
                val keyPair = keyManager.generateHardwareKey()
                val publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded)

                val json = JSONObject().apply {
                    put("username", username)
                    put("password", password)
                }

                val requestBody = json.toString().toRequestBody(jsonContentType)
                val request = Request.Builder()
                    .url("$baseUrl/login")
                    .header("x-rpc-sec-dbcs-hw-pub", publicKey)
                    .header("x-rpc-sec-dbcs-hw-pub-type", "ecdsa")
                    .post(requestBody)
                    .build()

                val response = client.newCall(request).await()
                
                if (response.isSuccessful) {
                    response.body?.string()?.let { body ->
                        val jsonResponse = JSONObject(body)
                        val token = jsonResponse.optString("token", "")
                        if (token.isNotEmpty()) {
                            storeAuthToken(token)
                            // Clear any existing acceleration resources
                            keyManager.clearAccelKeyId()
                            return@withContext true
                        }
                    }
                }
                false
            } catch (e: Exception) {
                e.printStackTrace()
                false
            }
        }

    /**
     * Check authentication status and manage acceleration keys
     */
    suspend fun checkAuthentication(): Boolean = withContext(Dispatchers.IO) {
        val token = getAuthToken() ?: return@withContext false
        val timestamp = System.currentTimeMillis().toString()

        try {
            val accelKeyId = keyManager.getAccelKeyId()
            val requestBuilder = Request.Builder()
                .url("$baseUrl/authenticated")
                .header("Authorization", "Bearer $token")
                .header("x-rpc-sec-dbcs-data", timestamp)

            if (accelKeyId != null) {
                // Use existing acceleration key
                val keyPair = keyManager.getOrCreateAccelerationKey()
                val signature = keyManager.signWithKey(keyPair, timestamp)
                
                requestBuilder
                    .header("x-rpc-sec-dbcs-data-sig", signature)
                    .header("x-rpc-sec-dbcs-accel-pub-id", accelKeyId)
            } else {
                // Generate a new acceleration key
                val keyPair = keyManager.generateAccelerationKey()
                
                val accelPubKey = Base64.getEncoder().encodeToString(keyPair.public.encoded)
                val accelPubKeySig = keyManager.signWithHardwareKey(accelPubKey)
                val signature = keyManager.signWithKey(keyPair, timestamp)

                requestBuilder
                    .header("x-rpc-sec-dbcs-accel-pub", accelPubKey)
                    .header("x-rpc-sec-dbcs-accel-pub-type", "ecdsa")
                    .header("x-rpc-sec-dbcs-accel-pub-sig", accelPubKeySig)
                    .header("x-rpc-sec-dbcs-data-sig", signature)
            }

            val request = requestBuilder.get().build()
            val response = client.newCall(request).await()

            if (response.isSuccessful) {
                // Save acceleration key ID if this was a new key registration
                response.header("x-rpc-sec-dbcs-accel-pub-id")?.let { newId ->
                    keyManager.storeAccelKeyId(newId)
                }
                return@withContext true
            }
            false
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Clear all stored credentials and keys
     */
    fun logout() {
        sharedPreferences.edit { 
            remove(keyAuthToken)
        }
        keyManager.clearKeys()
    }

    /**
     * Extension function to simplify OkHttp async calls
     */
    private suspend fun Call.await(): Response = suspendCoroutine { continuation ->
        this.enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) {
                continuation.resume(response)
            }
            
            override fun onFailure(call: Call, e: IOException) {
                continuation.resumeWithException(e)
            }
        })
    }
}
