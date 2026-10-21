package com.nexio.otp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;
import android.util.Log;

import java.util.LinkedHashMap;
import java.util.Map;

public class SmsReceiver extends BroadcastReceiver {
    private static final long RETRY_WINDOW_MS = 35_000;
    private static final long RETRY_DELAY_MS = 4_000;

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;
        if (!Sender.prefs(context).getBoolean("enabled", true)) return;

        // Multipart messages arrive as several PDUs; join them per sender.
        Map<String, StringBuilder> bySender = new LinkedHashMap<>();
        for (SmsMessage m : Telephony.Sms.Intents.getMessagesFromIntent(intent)) {
            String from = m.getDisplayOriginatingAddress();
            bySender.computeIfAbsent(from == null ? "" : from, k -> new StringBuilder())
                    .append(m.getDisplayMessageBody());
        }

        final PendingResult pending = goAsync();
        new Thread(() -> {
            try {
                for (Map.Entry<String, StringBuilder> e : bySender.entrySet()) {
                    String code = OtpParser.extract(e.getValue().toString());
                    if (code == null) continue;
                    // Retry while the network may be switching (Wi-Fi ↔ mobile, VPN reconnecting).
                    // The Mac rejects codes older than 2 minutes, so give up well before that.
                    long deadline = System.currentTimeMillis() + RETRY_WINDOW_MS;
                    String err = Sender.send(context, code, e.getKey());
                    while (err != null && System.currentTimeMillis() + RETRY_DELAY_MS < deadline) {
                        try { Thread.sleep(RETRY_DELAY_MS); } catch (InterruptedException ie) { break; }
                        err = Sender.send(context, code, e.getKey());
                    }
                    Sender.prefs(context).edit()
                            .putString("last", (err == null ? "Sent via " + Sender.lastPath(context) + " — " : "Failed: " + err + " — ")
                                    + "code from " + e.getKey())
                            .apply();
                    if (err != null) Log.w(Sender.TAG, "send failed: " + err);
                }
            } finally {
                pending.finish();
            }
        }).start();
    }
}
