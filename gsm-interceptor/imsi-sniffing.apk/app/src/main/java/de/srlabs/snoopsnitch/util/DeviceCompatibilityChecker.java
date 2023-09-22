package de.srlabs.snoopsnitch.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.HashSet;

import android.content.Context;

import de.srlabs.snoopsnitch.R;

public class DeviceCompatibilityChecker {
    private static String su_binary = null;

    private static int suFailReason = 0;
    private static final int SU_ROOT_DENIED = 1;
    private static final int SU_NOT_PRESENT = 2;
    private static final int SU_NOT_WORKING = 3;

    /**
     * Check whether the phone is compatible with the App. Please note that this
     * test already requests root privileges to test whether the su binary is
     * actually working. Unfortunately, many non-rooted phones still have a su
     * binary which is not installed setuid-root. This also applies to some
     * rooted phones which have a non-working /system/bin/su but a working
     * /system/xbin/su. Since there is no standard Android/Java API to retrieve
     * the POSIX filesystem permissions for a file, it will instead run 'su -c
     * "id"' and check whether the id command reports UID 0 (root).
     * <p>
     * New logic; three cases :
     * <p>
     * 1.     No diag device   +   no MSM Qualcomm chip -> for sure not compatible, and never will be
     * 2.     No diag device   +   is MSM Qualcomm chip -> not compatible for now, relate to firmware changes
     * 3.     Diag device      +   no baseband messages -> check again on next boot
     *
     * @return Returns null if everything is OK or a textual description of the
     * Error if the phone is not compatible.
     */
    public static String checkDeviceCompatibility(Context context) {
        boolean deviceIncompatibleDetected = MsdConfig.getDeviceIncompatible(context);
        boolean deviceCompatibleDetected = MsdConfig.getDeviceCompatibleDetected(context);
        String lastFirmwareInfo = MsdConfig.getLastFirmwareInformation(context);
        String currentFirmwareInfo = Utils.getFirmwareInformation();
        String suBinary;
        File diagDevice = new File("/dev/diag");

        if (deviceCompatibleDetected) {
            if (lastFirmwareInfo != null && lastFirmwareInfo.equals(currentFirmwareInfo)) {
                // we know, that device was working and there was no firmware update
                return null;
            }
        }

        if (!diagDevice.exists() && Utils.getDiagDeviceNodeMajor() == null) {
            if (!Utils.isDeviceMSM()) {
                //case 1: no /dev/diag + no MSM chip -> will never be compatible
                MsdConfig.setDeviceIncompatible(context, true);
                return context.getResources().getString(R.string.device_never_compatible);
            } else {
                // case 2: no /dev/diag + MSM chip -> not compatible for now, check again after firmware changed
                MsdConfig.setLastFirmwareInformation(context, currentFirmwareInfo);
                return context.getResources().getString(R.string.device_not_compatible_now_no_diag);
            }
        } else {
            if (deviceIncompatibleDetected) {
                //case 3: diag device + no baseband messages, check if firmware changed to be optimistic
                if (lastFirmwareInfo != null && !lastFirmwareInfo.equals(currentFirmwareInfo)) {
                    // firmware change detected, be optimistic and give it a try
                    MsdConfig.setLastFirmwareInformation(context, currentFirmwareInfo);
                }
                else {
                    return context.getResources().getString(R.string.compat_no_baseband_messages_in_active_test);
                }
            }
        }

        MsdConfig.setLastFirmwareInformation(context, currentFirmwareInfo);

        suBinary = getSuBinary();
        if (suBinary == null) {
            switch (suFailReason) {
                case SU_ROOT_DENIED:
                    return context.getResources().getString(R.string.compat_root_denied);
                case SU_NOT_PRESENT:
                    return context.getResources().getString(R.string.compat_su_not_present);
                case SU_NOT_WORKING:
                    return context.getResources().getString(R.string.compat_su_not_working);
                default:
                    return context.getResources().getString(R.string.compat_no_root);
            }
        }

        String createDiagError = Utils.createDiagDevice();
        if (createDiagError != null) {
            return "Failed to create diag device: " + createDiagError;
        }
        if (!testRunOK(context, suBinary)) {
            return context.getResources().getString(R.string.compat_broken_diag);
        }

        // Everything OK
        return null;
    }

    private static boolean testRunOK(Context context, String suBinary) {

        Process helper;

        String libdir = context.getApplicationInfo().nativeLibraryDir;
        String diag_helper = libdir + "/libdiag-helper.so";
        String cmd[] = {suBinary, "-c", "exec " + diag_helper + " test"};

        try {
            helper = Runtime.getRuntime().exec(cmd);
        } catch (IOException e) {
            return false;
        }

        boolean terminated = false;
        do {
            try {
                helper.waitFor();
                terminated = true;
            } catch (InterruptedException e) {
                // Do nothing
            }
        } while (!terminated);

        return helper.exitValue() == 0;
    }

    public static String getSuBinary() {
        if (su_binary == null)
            su_binary = findSuBinary();
        return su_binary;
    }

    private static String findSuBinary() {

        // Iterate over all PATH entries to find su binary
        String path = System.getenv("PATH");
        HashSet<String> pathDirs = new HashSet<String>();

        // Always consider the default paths /system/bin/ and /system/xbin/ in case $PATH is incomplete
        pathDirs.add("/system/bin/");
        pathDirs.add("/system/xbin/");
        Collections.addAll(pathDirs, path.split(":"));

        int suBinariesTried = 0;

        for (String pathDir : pathDirs) {
            File f = new File(pathDir + "/su");
            if (!f.exists())
                continue;
            suBinariesTried++;
            String cmd[] = {pathDir + "/su", "-c", "id"};
            Process p;
            try {
                p = Runtime.getRuntime().exec(cmd, null, null);
                BufferedReader su_stdout = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String id_line = su_stdout.readLine();
                su_stdout.close();
                p.waitFor();
                // We don't receive anything if root was denied
                if (id_line == null) {
                    suFailReason = SU_ROOT_DENIED;
                    return null;
                }
                // Check whether the id command reports UID zero (root) to make sure that the su binary actually works
                if (id_line.startsWith("uid=0")) {
                    return pathDir + "/su";
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if (suBinariesTried > 0) {
            //  Found and su binary, but it didn't work
            suFailReason = SU_NOT_WORKING;
            return null;
        } else {
            //  No su binary found.
            suFailReason = SU_NOT_PRESENT;
            return null;
        }
    }
}
