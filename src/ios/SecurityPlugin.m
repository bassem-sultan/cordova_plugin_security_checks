
#import <Cordova/CDV.h>
#import "SecurityChecks.h"

@interface SecurityPlugin : CDVPlugin
- (void)isSecure:(CDVInvokedUrlCommand*)command;
@end

@implementation SecurityPlugin

- (void)isSecure:(CDVInvokedUrlCommand*)command {
    BOOL jailbroken = [SecurityChecks isDeviceJailbroken];
    BOOL debugger = [SecurityChecks isDebuggerAttached];
    BOOL frida = [SecurityChecks isFridaDetected];
    BOOL appDebuggable = [SecurityChecks isAppDebuggable];

    BOOL secure = !(jailbroken || debugger || frida || appDebuggable);

    NSDictionary *result = @{
        @"jailbroken": @(jailbroken),
        @"debugger": @(debugger),
        @"frida": @(frida),
        @"appDebuggable": @(appDebuggable),
        @"isSecure": @(secure)
    };

    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end
