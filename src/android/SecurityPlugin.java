
package cordova_plugin_security_checks;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import android.content.Context;

public class SecurityPlugin extends CordovaPlugin {
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if ("isSecure".equals(action)) {
            Context ctx = this.cordova.getActivity().getApplicationContext();
            JSONObject result = new JSONObject();

            boolean rooted = DeviceIntegrity.isDeviceRooted(ctx);
            boolean debugger = DeviceIntegrity.isDebuggerAttached();
            boolean usbDebug = DeviceIntegrity.isUsbDebuggingEnabled(ctx);
            boolean devOpts = DeviceIntegrity.isDeveloperOptionsEnabled(ctx);
            boolean frida = DeviceIntegrity.isFridaDetected(ctx);
            boolean appDebuggable = DeviceIntegrity.isAppDebuggable(ctx);

            boolean secure = !(rooted || debugger || usbDebug || devOpts || frida || appDebuggable);

            result.put("rooted", rooted);
            result.put("debugger", debugger);
            result.put("usbDebug", usbDebug);
            result.put("developerOptions", devOpts);
            result.put("frida", frida);
            result.put("appDebuggable", appDebuggable);
            result.put("isSecure", secure);

            callbackContext.success(result);
            return true;
        }
        return false;
    }
}
