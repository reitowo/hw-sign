package com.example.hwsign;

import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.security.KeyPairGenerator;
import java.security.KeyStore;

public class MainActivity extends AppCompatActivity {
    private TextView messageTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        messageTextView = findViewById(R.id.messageTextView);
        Button generateKeyButton = findViewById(R.id.generateKeyButton);

        generateKeyButton.setOnClickListener(v -> generateKeyPair());
    }

    private void generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

            keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(
                    "hw_sign_key",
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setKeySize(2048)
                    .build());

            keyPairGenerator.generateKeyPair();
            messageTextView.setText("Key pair generated successfully!");
        } catch (Exception e) {
            messageTextView.setText("Error generating key pair: " + e.getMessage());
        }
    }
}