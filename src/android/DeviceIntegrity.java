
package cordova_plugin_security_checks;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.os.Debug;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

public final class DeviceIntegrity {

    private DeviceIntegrity() {}

    // -------- Root Detection --------
    public static boolean isDeviceRooted(Context ctx) {
        return hasTestKeys() ||
               hasSuBinary() ||
               hasRootAppsInstalled(ctx) ||
               canExecuteSu() ||
               hasDangerousProps() ||
               isSystemPartitionWritable();
    }

    private static boolean hasTestKeys() {
        String tags = Build.TAGS;
        return tags != null && tags.contains("test-keys");
    }

    private static boolean hasSuBinary() {
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su"
        };
        for (String path : paths) {
            File f = new File(path);
            if (f.exists()) return true;
        }
        return false;
    }

    private static boolean hasRootAppsInstalled(Context ctx) {
        String[] pkgs = {
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.topjohnwu.magisk"
        };
        PackageManager pm = ctx.getPackageManager();
        for (String pkg : pkgs) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {}
        }
        return false;
    }

    private static boolean canExecuteSu() {
        return commandExists("which", "su") || runCmdReturns("su", "-c", "id");
    }

    private static boolean commandExists(String... cmd) {
        return runCmdReturns(cmd);
    }

    private static boolean runCmdReturns(String... cmd) {
        Process p = null;
        BufferedReader r = null;
        try {
            p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = r.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (r != null) r.close(); } catch (IOException ignored) {}
            if (p != null) p.destroy();
        }
        return false;
    }

    private static boolean hasDangerousProps() {
        String roSecure = getProp("ro.secure");
        String roDebuggable = getProp("ro.debuggable");
        return "0".equals(roSecure) || "1".equals(roDebuggable);
    }

    private static String getProp(String key) {
        Process p = null;
        BufferedReader r = null;
        try {
            p = new ProcessBuilder("getprop", key).redirectErrorStream(true).start();
            r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = r.readLine();
            return val != null ? val.trim() : "";
        } catch (Throwable ignored) {
            return "";
        } finally {
            try { if (r != null) r.close(); } catch (IOException ignored) {}
            if (p != null) p.destroy();
        }
    }

    private static boolean isSystemPartitionWritable() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/mounts"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains(" /system ")) {
                    String[] parts = line.split(" ");
                    if (parts.length >= 4) {
                        String opts = parts[3];
                        if (opts.contains("rw")) return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (br != null) br.close(); } catch (IOException ignored) {}
        }
        return false;
    }

    // -------- Debugger Detection --------
    public static boolean isDebuggerAttached() {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger() || tracerPid() > 0;
    }

    private static int tracerPid() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String val = line.split("\s+")[1].trim();
                    return Integer.parseInt(val);
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (br != null) br.close(); } catch (IOException ignored) {}
        }
        return 0;
    }

    // -------- USB Debugging --------
    public static boolean isUsbDebuggingEnabled(Context ctx) {
        try {
            int adb = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1)
                    ? Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.ADB_ENABLED, 0)
                    : Settings.Secure.getInt(ctx.getContentResolver(), Settings.Secure.ADB_ENABLED, 0);
            return adb == 1;
        } catch (Throwable ignored) {
            return false;
        }
    }

    // -------- Developer Options --------
    public static boolean isDeveloperOptionsEnabled(Context ctx) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                return Settings.Global.getInt(ctx.getContentResolver(),
                        Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1;
            } else {
                return Settings.Secure.getInt(ctx.getContentResolver(),
                        "development_settings_enabled", 0) == 1;
            }
        } catch (Throwable ignored) {
            return false;
        }
    }

    // -------- Frida / Runtime Instrumentation --------
    public static boolean isFridaDetected(Context ctx) {
        return hasSuspiciousLibrariesInMaps() || hasXposed() || fridaPortsOpen();
    }

    private static boolean hasSuspiciousLibrariesInMaps() {
        List<String> keywords = Arrays.asList(
            "frida", "gum-js-loop", "libfrida", "frida-gadget",
            "re.frida.server", "frida-agent", "substrate", "xposed", "edxp"
        );

        BufferedReader br = null;
        try {
            String path = "/proc/" + android.os.Process.myPid() + "/maps";
            br = new BufferedReader(new FileReader(path));
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                for (String k : keywords) {
                    if (lower.contains(k)) return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try { if (br != null) br.close(); } catch (IOException ignored) {}
        }
        return false;
    }

    private static boolean hasXposed() {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean fridaPortsOpen() {
        int[] ports = {27042, 27043};
        for (int port : ports) {
            Socket s = null;
            try {
                s = new Socket();
                s.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return true;
            } catch (Throwable ignored) {
            } finally {
                try { if (s != null) s.close(); } catch (IOException ignored) {}
            }
        }
        return false;
    }

    // -------- App Debuggable Flag --------
    public static boolean isAppDebuggable(Context ctx) {
        try {
            ApplicationInfo ai = ctx.getApplicationInfo();
            return (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }
}
