
#import <Foundation/Foundation.h>

@interface SecurityChecks : NSObject
+ (BOOL)isDeviceJailbroken;
+ (BOOL)isDebuggerAttached;
+ (BOOL)isFridaDetected;
+ (BOOL)isAppDebuggable;
+ (void)denyDebuggerIfPossible;
@end
