package com.nexio.otp;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Detects whether an SMS is an OTP message and extracts the code. */
public final class OtpParser {
    private OtpParser() {}

    private static final String[] KEYWORDS = {
        "رمز پویا", "رمز دوم", "رمز یکبار", "رمز", "کد تایید", "کد تأیید", "کد فعالسازی", "کد ورود", "کد",
        "پویا", "یکبار مصرف", "تایید", "تأیید",
        "otp", "code", "passcode", "password", "pin", "verification", "verify", "one-time", "one time",
    };

    // 4–8 digits that aren't part of a longer number, amount (1,000), date/time, card or masked digits.
    private static final Pattern CANDIDATE =
        Pattern.compile("(?<![\\d*])(?<!\\d[,./:\\-])(\\d{4,8})(?![,./:\\-]\\d|\\d|\\*)");

    /** Returns the code, or null if this doesn't look like an OTP. */
    public static String extract(String body) {
        if (body == null) return null;
        String text = normalizeDigits(body);
        String lower = text.toLowerCase(Locale.ROOT);

        int[] keywordPositions = new int[64];
        int nk = 0;
        for (String k : KEYWORDS) {
            int i = lower.indexOf(k);
            while (i >= 0 && nk < keywordPositions.length) {
                keywordPositions[nk++] = i + k.length();
                i = lower.indexOf(k, i + 1);
            }
        }
        if (nk == 0) return null;

        String best = null;
        int bestScore = Integer.MAX_VALUE;
        Matcher m = CANDIDATE.matcher(text);
        while (m.find()) {
            int score = Integer.MAX_VALUE;
            for (int j = 0; j < nk; j++) {
                int d = m.start() - keywordPositions[j];
                // Prefer numbers that follow the keyword; penalize ones before it.
                int s = d >= 0 ? d : (-d) * 3;
                if (s < score) score = s;
            }
            if (score < bestScore) {
                bestScore = score;
                best = m.group(1);
            }
        }
        return best;
    }

    /** Converts Persian (۰-۹) and Arabic-Indic (٠-٩) digits to ASCII. */
    static String normalizeDigits(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '۰' && c <= '۹') c = (char) ('0' + (c - '۰'));
            else if (c >= '٠' && c <= '٩') c = (char) ('0' + (c - '٠'));
            b.append(c);
        }
        return b.toString();
    }
}
