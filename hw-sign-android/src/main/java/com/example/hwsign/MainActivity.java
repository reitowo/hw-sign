package com.example.hwsign;

import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import okhttp3.*;

public class MainActivity extends AppCompatActivity {
    private TextView messageTextView;
    private EditText usernameEditText;
    private EditText passwordEditText;
    private final OkHttpClient client = new OkHttpClient();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        messageTextView = findViewById(R.id.messageTextView);
        usernameEditText = findViewById(R.id.usernameEditText);
        passwordEditText = findViewById(R.id.passwordEditText);
        Button generateKeyButton = findViewById(R.id.generateKeyButton);
        Button registerButton = findViewById(R.id.registerButton);
        Button loginButton = findViewById(R.id.loginButton);
        Button checkAuthButton = findViewById(R.id.checkAuthButton);

        generateKeyButton.setOnClickListener(v -> generateKeyPair());
        registerButton.setOnClickListener(v -> registerUser());
        loginButton.setOnClickListener(v -> loginUser());
        checkAuthButton.setOnClickListener(v -> checkAuthentication());
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

    private void registerUser() {
        String username = usernameEditText.getText().toString();
        String password = passwordEditText.getText().toString();
        sendRequest("/register", "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}");
    }

    private void loginUser() {
        String username = usernameEditText.getText().toString();
        String password = passwordEditText.getText().toString();
        sendRequest("/login", "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}");
    }

    private void checkAuthentication() {
        Request request = new Request.Builder()
                .url("https://dbcs-api.reito.fun/authenticated")
                .get()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                runOnUiThread(() -> messageTextView.setText("Request failed: " + e.getMessage()));
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (!response.isSuccessful()) {
                    runOnUiThread(() -> messageTextView.setText("Request failed with code: " + response.code()));
                    return;
                }

                final String responseData = response.body().string();
                runOnUiThread(() -> messageTextView.setText("Authentication status: " + responseData));
            }
        });
    }

    private void sendRequest(String endpoint, String jsonPayload) {
        RequestBody body = RequestBody.create(jsonPayload, MediaType.get("application/json; charset=utf-8"));
        Request request = new Request.Builder()
                .url("https://dbcs-api.reito.fun" + endpoint)
                .post(body)
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                runOnUiThread(() -> messageTextView.setText("Request failed: " + e.getMessage()));
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (!response.isSuccessful()) {
                    runOnUiThread(() -> messageTextView.setText("Request failed with code: " + response.code()));
                    return;
                }

                final String responseData = response.body().string();
                runOnUiThread(() -> messageTextView.setText("Response: " + responseData));
            }
        });
    }
}