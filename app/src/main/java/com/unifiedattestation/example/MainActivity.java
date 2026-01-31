package com.unifiedattestation.example;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.unifiedattestation.sdk.UnifiedAttestationClient;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private TextView statusText;
    private UnifiedAttestationClient client;

    private final String serverBaseUrl = "http://192.168.90.77:4000";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        statusText = findViewById(R.id.statusText);
        Button runButton = findViewById(R.id.runButton);

        client = new UnifiedAttestationClient(this);
        runButton.setOnClickListener(v -> runAttestationFlow());
    }

    @Override
    protected void onStart() {
        super.onStart();
        client.connect();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        client.disconnect();
        executor.shutdownNow();
    }

    private void runAttestationFlow() {
        String projectId = getPackageName();
        String canonicalRequest = canonicalRequestString();
        String requestHash = sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        status("RequestHash: " + requestHash);

        client.getProviderSet(projectId, new UnifiedAttestationClient.ProviderSetCallback() {
            @Override
            public void onSuccess(List<String> backends) {
                executor.submit(() -> {
                    try {
                        String backendId = selectBackend(projectId, canonicalRequest, backends);
                        status("Selected backend: " + backendId);
                        requestToken(backendId, projectId, requestHash, canonicalRequest);
                    } catch (Exception e) {
                        status("Server error: " + e.getMessage());
                    }
                });
            }

            @Override
            public void onError(int code, String message) {
                status("ProviderSet error: " + code + " " + message);
            }
        });
    }

    private void requestToken(
            String backendId,
            String projectId,
            String requestHash,
            String canonicalRequest
    ) {
        client.requestIntegrityToken(
                backendId,
                projectId,
                requestHash,
                new UnifiedAttestationClient.TokenCallback() {
                    @Override
                    public void onSuccess(String token) {
                        status("Token received, verifying...");
                        executor.submit(() -> {
                            try {
                                String verdict = verifyToken(projectId, canonicalRequest, token);
                                status("Verdict: " + verdict);
                            } catch (Exception e) {
                                status("Verify error: " + e.getMessage());
                            }
                        });
                    }

                    @Override
                    public void onError(int code, String message) {
                        status("Token error: " + code + " " + message);
                    }
                }
        );
    }

    private String selectBackend(String projectId, String canonicalRequest, List<String> backendIds)
            throws Exception {
        JSONObject body = new JSONObject();
        body.put("projectId", projectId);
        body.put("canonicalRequest", canonicalRequest);
        body.put("backendIds", backendIds);
        JSONObject response = postJson(serverBaseUrl + "/select-backend", body);
        return response.getString("backendId");
    }

    private String verifyToken(String projectId, String canonicalRequest, String token) throws Exception {
        JSONObject body = new JSONObject();
        body.put("projectId", projectId);
        body.put("canonicalRequest", canonicalRequest);
        body.put("token", token);
        JSONObject response = postJson(serverBaseUrl + "/verify", body);
        return response.getString("verdict");
    }

    private JSONObject postJson(String url, JSONObject body) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
        conn.setFixedLengthStreamingMode(bytes.length);
        conn.getOutputStream().write(bytes);
        int code = conn.getResponseCode();
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream()
        ));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        if (code < 200 || code >= 300) {
            throw new IllegalStateException("HTTP " + code + ": " + sb);
        }
        return new JSONObject(sb.toString());
    }

    private void status(String message) {
        runOnUiThread(() -> {
            String existing = statusText.getText() != null ? statusText.getText().toString() : "";
            if (existing.isEmpty()) {
                statusText.setText(message);
            } else {
                statusText.setText(existing + "\n" + message);
            }
        });
    }

    private String canonicalRequestString() {
        return "action=login&sessionId=123456&ts=1700000000";
    }

    private String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
