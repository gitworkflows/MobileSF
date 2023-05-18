package de.srlabs.snoopsnitch;

import de.srlabs.snoopsnitch.qdmon.MsdService;
import de.srlabs.snoopsnitch.util.Constants;
import de.srlabs.snoopsnitch.util.MsdConfig;
import de.srlabs.snoopsnitch.util.Utils;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

public class BootCompletedIntentReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!MsdConfig.getFirstRun(context) && MsdConfig.getStartOnBoot(context)) {

            //do not start background service, if device is incompatible and firmware did not change
            String currentFirmware = Utils.getFirmwareInformation();
            String lastFirmware = MsdConfig.getLastFirmwareInformation(context);
            if (lastFirmware != null) {
                if (lastFirmware.equals(currentFirmware) && MsdConfig.getDeviceIncompatible(context)) {
                    //do not start service
                    return;
                }
            } else {
                //not able to tell if there was a firmware update or not
                if (MsdConfig.getDeviceIncompatible(context)) {
                    //do not start service
                    return;
                }
            }


            //start service
            Intent i = new Intent(context, MsdService.class);
            if (Build.VERSION.SDK_INT >= 26) {
                Log.d("SnoopSnitch","starting service in foreground...working");
                context.startForegroundService(i);
            } else {
                context.startService(i);
            }
        }
    }
}
