package com.codingwithpuneet.securityapp

import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object SecurityUtils {

    // Symmetric Key Encryption
    @RequiresApi(Build.VERSION_CODES.O)
    fun encryptString(secretKey: SecretKeySpec, plainText: String): String {
        // Create Cipher Instance with AES Algorithm, ECB Mode, PKCS5Padding Padding
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        Log.d("ENCRYPT_DECRYPT", "Original Message: $plainText")
        // Initialize Cipher with Encrypt Mode and Secret Key
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        // Do the Encryption using Cipher.doFinal
        val encryptedBytes = cipher.doFinal(plainText.toByteArray())
        Log.d("ENCRYPT_DECRYPT", "Encrypted Message: ${encryptedBytes.toString()}")
        // Convert encrypted bytes to Base64 so that bytes can be converted to ASCII and can be easily transmitted or stored
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    // Symmetric Key Decryption
    @RequiresApi(Build.VERSION_CODES.O)
    fun decryptString(secretKey: SecretKeySpec, encryptedText: String): String {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val decodedBytes = Base64.getDecoder().decode(encryptedText)
        val decryptedBytes = cipher.doFinal(decodedBytes)
        Log.d("ENCRYPT_DECRYPT", "Decrypted Message: ${String(decryptedBytes)}")
        return String(decryptedBytes)
    }

    // Symmetric Key Generator
    fun generateKey(): SecretKeySpec{
        val key = ByteArray(16) // 128-bit key
        SecureRandom().nextBytes(key)
        return SecretKeySpec(key, "AES")
    }


    // -------

    // Asymmetric key Encryption
    @RequiresApi(Build.VERSION_CODES.O)
    fun encryptStringAsymmetric(publicKey: PublicKey, plainText: String): String {
        Log.d("ENCRYPT_DECRYPT", "Original Message: $plainText")
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(plainText.toByteArray())
        Log.d("ENCRYPT_DECRYPT", "Encrypted Message: ${encryptedBytes.toString()}")
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    // Asymmetric key Decryption
    @RequiresApi(Build.VERSION_CODES.O)
    fun decryptStringAsymmetric(privateKey: PrivateKey, encryptedText: String): String {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decodedBytes = Base64.getDecoder().decode(encryptedText)
        val decryptedBytes = cipher.doFinal(decodedBytes)
        Log.d("ENCRYPT_DECRYPT", "Decrypted Message: ${String(decryptedBytes)}")
        return String(decryptedBytes)
    }

    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        return keyPairGenerator.genKeyPair()
    }
}