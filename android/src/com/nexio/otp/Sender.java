package com.nexio.otp;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.WifiManager;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts an OTP and sends it to the Mac receiver. Blocking — call off the main thread.
 * Paths are tried in order, stopping at the first success:
 *   1. LAN: direct TCP to the Mac (found via Bonjour), only when on Wi-Fi;
 *   2. each relay from the "relays" setting, in order (e.g. your VPS, then ntfy.sh).
 */
public final class Sender {
    static final String TAG = "Nexio";
    static final String PREFS = "nexio";
    static final String SERVICE_TYPE = "_nexio._tcp";
    static final int DEFAULT_PORT = 47800;
    static final String DEFAULT_RELAYS = "https://ntfy.sh";

    private Sender() {}

    public static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    /** Relay list, one per line: {@code URL [access-token]}. */
    public static String relays(SharedPreferences p) {
        return p.getString("relays", p.getString("relay", DEFAULT_RELAYS));
    }

    /** Sends the code over the first path that works. Returns null on success, else an error. */
    public static String send(Context ctx, String code, String sender) {
        SharedPreferences p = prefs(ctx);
        String pairing = p.getString("pairing", "");
        if (pairing.isEmpty()) return "No pairing code set";

        String frame;
        try {
            JSONObject json = new JSONObject();
            json.put("code", code);
            json.put("sender", sender == null ? "" : sender);
            json.put("ts", System.currentTimeMillis());
            frame = encrypt(pairing, json.toString());
        } catch (Exception e) {
            return "Encrypt failed: " + e;
        }

        List<String> errors = new ArrayList<>();

        if (onWifi(ctx)) {
            String err = sendLan(ctx, p, frame);
            if (err == null) return delivered(p, "Wi-Fi");
            errors.add("Wi-Fi: " + err);
        }

        String topic = relayTopic(pairing);
        for (String line : relays(p).split("\\n")) {
            String[] parts = line.trim().split("\\s+");
            if (parts[0].isEmpty() || parts[0].startsWith("#")) continue;
            String host = Uri.parse(parts[0]).getHost();
            String err = postRelay(parts[0], parts.length > 1 ? parts[1] : null, topic, frame);
            if (err == null) return delivered(p, host);
            errors.add(host + ": " + err);
        }
        return errors.isEmpty() ? "no path available" : TextUtils.join("; ", errors);
    }

    private static String delivered(SharedPreferences p, String via) {
        p.edit().putString("lastPath", via).apply();
        return null;
    }

    /** Which path delivered the last successful send (for the status line). */
    public static String lastPath(Context ctx) {
        return prefs(ctx).getString("lastPath", "");
    }

    @SuppressWarnings("deprecation")
    private static boolean onWifi(Context ctx) {
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities nc = cm.getNetworkCapabilities(n);
            if (nc != null && (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    || nc.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))) return true;
        }
        return false;
    }

    private static String sendLan(Context ctx, SharedPreferences p, String frame) {
        String host = p.getString("host", "");
        int port = p.getInt("port", DEFAULT_PORT);
        if (!host.isEmpty() && deliver(host, port, frame, 1500) == null) return null;

        // IP changed or different network: look for the Mac via Bonjour.
        String[] found = discover(ctx, 3000);
        if (found == null) return "Mac not on this network";
        p.edit().putString("host", found[0]).putInt("port", Integer.parseInt(found[1])).apply();
        return deliver(found[0], Integer.parseInt(found[1]), frame, 3000);
    }

    private static String postRelay(String base, String token, String topic, String frame) {
        HttpURLConnection c = null;
        try {
            while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
            c = (HttpURLConnection) new URL(base + "/" + topic).openConnection();
            c.setConnectTimeout(5000);
            c.setReadTimeout(5000);
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "text/plain");
            c.setRequestProperty("Cache", "yes");
            c.setRequestProperty("Firebase", "no");
            if (token != null) c.setRequestProperty("Authorization", "Bearer " + token);
            try (OutputStream out = c.getOutputStream()) {
                out.write(frame.getBytes(StandardCharsets.US_ASCII));
            }
            int code = c.getResponseCode();
            if (code == 401 || code == 403) return "access denied (token?)";
            return code / 100 == 2 ? null : "HTTP " + code;
        } catch (Exception e) {
            return describe(e);
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /** Short, human-readable reason for a network failure. */
    static String describe(Exception e) {
        if (e instanceof java.net.SocketTimeoutException) return "timed out";
        if (e instanceof java.net.UnknownHostException) return "DNS lookup failed";
        if (e instanceof java.net.ConnectException) return "connection refused";
        if (e instanceof javax.net.ssl.SSLException) return "TLS error";
        return e.getClass().getSimpleName();
    }

    static String normalize(String pairing) {
        StringBuilder norm = new StringBuilder();
        for (char c : pairing.toUpperCase(Locale.ROOT).toCharArray()) {
            if (c < 128 && Character.isLetterOrDigit(c)) norm.append(c);
        }
        return norm.toString();
    }

    static String relayTopic(String pairing) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256")
                    .digest(("nexio-topic:" + normalize(pairing)).getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder("nexio-");
            for (int i = 0; i < 16; i++) b.append(String.format("%02x", h[i]));
            return b.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String ping(String host, int port) {
        return deliver(host, port, "PING", 3000);
    }

    private static String deliver(String host, int port, String frame, int connectTimeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            s.setSoTimeout(3000);
            OutputStream out = s.getOutputStream();
            out.write((frame + "\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            String reply = new BufferedReader(new InputStreamReader(s.getInputStream())).readLine();
            if ("OK".equals(reply)) return null;
            return "Mac rejected message (wrong pairing code?)";
        } catch (Exception e) {
            return describe(e);
        }
    }

    static String encrypt(String pairing, String plaintext) throws Exception {
        byte[] key = MessageDigest.getInstance("SHA-256").digest(normalize(pairing).getBytes(StandardCharsets.UTF_8));
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)); // ciphertext || tag
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.encodeToString(out, Base64.NO_WRAP);
    }

    /** Finds the Mac via Bonjour. Returns {host, port} or null. Blocking. */
    @SuppressWarnings("deprecation")
    public static String[] discover(Context ctx, long timeoutMs) {
        NsdManager nsd = (NsdManager) ctx.getSystemService(Context.NSD_SERVICE);
        WifiManager wifi = (WifiManager) ctx.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        WifiManager.MulticastLock lock = wifi.createMulticastLock("nexio");
        lock.setReferenceCounted(false);
        lock.acquire();

        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<String[]> result = new AtomicReference<>();

        NsdManager.DiscoveryListener listener = new NsdManager.DiscoveryListener() {
            boolean resolving = false;
            @Override public void onServiceFound(NsdServiceInfo info) {
                if (resolving) return;
                resolving = true;
                nsd.resolveService(info, new NsdManager.ResolveListener() {
                    @Override public void onServiceResolved(NsdServiceInfo r) {
                        if (r.getHost() != null) {
                            result.set(new String[]{r.getHost().getHostAddress(), String.valueOf(r.getPort())});
                        }
                        done.countDown();
                    }
                    @Override public void onResolveFailed(NsdServiceInfo r, int code) { resolving = false; }
                });
            }
            @Override public void onStartDiscoveryFailed(String t, int code) { done.countDown(); }
            @Override public void onStopDiscoveryFailed(String t, int code) {}
            @Override public void onDiscoveryStarted(String t) {}
            @Override public void onDiscoveryStopped(String t) {}
            @Override public void onServiceLost(NsdServiceInfo info) {}
        };

        try {
            nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener);
            done.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            Log.w(TAG, "discovery error", e);
        } finally {
            try { nsd.stopServiceDiscovery(listener); } catch (Exception ignored) {}
            lock.release();
        }
        return result.get();
    }
}
