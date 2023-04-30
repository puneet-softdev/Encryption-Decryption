package com.codingwithpuneet.securityapp

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.*
import java.util.*
import javax.crypto.Cipher

class MainActivity : AppCompatActivity() {
    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        encryptDecryptSymmetric()
        encryptDecryptAsymmetric()
    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun encryptDecryptSymmetric(){
        Log.d("ENCRYPT_DECRYPT", "----- Using Symmetric Key Encryption Decryption -----")
        val message = "CodingWithPuneet"
        val secretKey = SecurityUtils.generateKey()
        val encryptedMessage = SecurityUtils.encryptString(secretKey= secretKey, plainText = message)
        SecurityUtils.decryptString(secretKey= secretKey, encryptedText=encryptedMessage)
    }

    // Calling Asymmetric Key
    @RequiresApi(Build.VERSION_CODES.O)
    fun encryptDecryptAsymmetric(){
        Log.d("ENCRYPT_DECRYPT", "----- Using Asymmetric Key Encryption Decryption -----")
        val keyPair = SecurityUtils.generateKeyPair()
        val publicKey = keyPair.public
        val privateKey = keyPair.private

        val plainText = "CodingWithPuneet Asymmetric"
        val encryptedText = SecurityUtils.encryptStringAsymmetric(publicKey, plainText)
        SecurityUtils.decryptStringAsymmetric(privateKey, encryptedText)
    }
}