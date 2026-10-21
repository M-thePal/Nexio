package com.nexio.otp;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.text.InputType;
import android.view.ViewGroup;
import android.view.Gravity;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

public class MainActivity extends Activity {
    private EditText pairing, host, relay;
    private TextView status;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        prefs = Sender.prefs(this);
        applyIntentExtras(getIntent());
        buildUi();
        if (checkSelfPermission(Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.RECEIVE_SMS}, 1);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        applyIntentExtras(intent);
        pairing.setText(prefs.getString("pairing", ""));
        host.setText(prefs.getString("host", ""));
        relay.setText(prefs.getString("relay", Sender.DEFAULT_RELAY));
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus(null);
    }

    /** Allows pairing over adb: am start -n com.nexio.otp/.MainActivity --es pair CODE --es host IP */
    private void applyIntentExtras(Intent i) {
        if (i == null) return;
        SharedPreferences.Editor e = prefs.edit();
        if (i.hasExtra("pair")) e.putString("pairing", i.getStringExtra("pair").trim());
        if (i.hasExtra("host")) e.putString("host", i.getStringExtra("host").trim());
        if (i.hasExtra("relay")) e.putString("relay", i.getStringExtra("relay").trim());
        e.apply();
    }

    private void buildUi() {
        int pad = dp(20);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(pad, pad * 2, pad, pad);

        ImageView icon = new ImageView(this);
        icon.setImageDrawable(getApplicationInfo().loadIcon(getPackageManager()));
        LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(dp(72), dp(72));
        iconLp.gravity = Gravity.CENTER_HORIZONTAL;
        iconLp.bottomMargin = dp(12);
        col.addView(icon, iconLp);

        TextView title = new TextView(this);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        title.setText("Nexio — OTP to Mac");
        title.setTextSize(24);
        col.addView(title);

        status = new TextView(this);
        status.setPadding(0, dp(12), 0, dp(12));
        col.addView(status);

        Switch enabled = new Switch(this);
        enabled.setText("Forward OTP codes");
        enabled.setChecked(prefs.getBoolean("enabled", true));
        enabled.setOnCheckedChangeListener((b, on) -> prefs.edit().putBoolean("enabled", on).apply());
        col.addView(enabled);

        col.addView(label("Pairing code (run: nexio-mac pair)"));
        pairing = new EditText(this);
        pairing.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);
        pairing.setText(prefs.getString("pairing", ""));
        col.addView(pairing);

        col.addView(label("Mac address (optional — found automatically)"));
        host = new EditText(this);
        host.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        host.setText(prefs.getString("host", ""));
        col.addView(host);

        col.addView(label("Relay server (used when not on the same network)"));
        relay = new EditText(this);
        relay.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        relay.setText(prefs.getString("relay", Sender.DEFAULT_RELAY));
        col.addView(relay);

        col.addView(button("Save", () -> { save(); refreshStatus("Saved"); }));
        col.addView(button("Find Mac on network", this::findMac));
        col.addView(button("Send test code", this::sendTest));
        col.addView(button("Disable battery optimization", this::askBattery));

        ScrollView scroll = new ScrollView(this);
        scroll.addView(col);
        setContentView(scroll);
    }

    private void save() {
        prefs.edit()
                .putString("pairing", pairing.getText().toString().trim())
                .putString("host", host.getText().toString().trim())
                .putString("relay", relay.getText().toString().trim().isEmpty()
                        ? Sender.DEFAULT_RELAY : relay.getText().toString().trim())
                .apply();
    }

    private void findMac() {
        save();
        refreshStatus("Searching…");
        new Thread(() -> {
            String[] found = Sender.discover(this, 6000);
            runOnUiThread(() -> {
                if (found == null) { refreshStatus("Mac not found. Same Wi-Fi? Is nexio-mac running?"); return; }
                prefs.edit().putString("host", found[0]).putInt("port", Integer.parseInt(found[1])).apply();
                host.setText(found[0]);
                refreshStatus("Found Mac at " + found[0]);
            });
        }).start();
    }

    private void sendTest() {
        save();
        refreshStatus("Sending…");
        new Thread(() -> {
            String err = Sender.send(this, "123456", "Nexio test");
            runOnUiThread(() -> refreshStatus(err == null
                    ? "Test code sent via " + Sender.lastPath(this) + " ✓" : "Failed: " + err));
        }).start();
    }

    private void askBattery() {
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm.isIgnoringBatteryOptimizations(getPackageName())) { refreshStatus("Already unrestricted"); return; }
        startActivity(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:" + getPackageName())));
    }

    private void refreshStatus(String msg) {
        boolean sms = checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED;
        StringBuilder b = new StringBuilder();
        b.append("SMS permission: ").append(sms ? "granted" : "MISSING").append('\n');
        b.append("Pairing code: ").append(prefs.getString("pairing", "").isEmpty() ? "not set" : "set").append('\n');
        b.append("Mac: ").append(prefs.getString("host", "auto")).append('\n');
        b.append("Last: ").append(prefs.getString("last", "—"));
        if (msg != null) b.append("\n\n").append(msg);
        status.setText(b.toString());
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        refreshStatus(null);
    }

    private TextView label(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setPadding(0, dp(16), 0, 0);
        return t;
    }

    private Button button(String text, Runnable r) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setOnClickListener(v -> r.run());
        b.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return b;
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
