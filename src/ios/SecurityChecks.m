
#import "SecurityChecks.h"
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <Security/SecTask.h>
#import <Security/SecCode.h>
#import <sys/stat.h>
#import <unistd.h>
#import <fcntl.h>
#import <sys/ptrace.h>
#import <UIKit/UIKit.h>

@implementation SecurityChecks

#pragma mark - Jailbreak Detection

+ (BOOL)isDeviceJailbroken {
#if TARGET_OS_SIMULATOR
    return YES;
#endif

    NSArray<NSString *> *paths = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/private/var/lib/apt/",
        @"/private/var/lib/cydia/",
        @"/usr/bin/ssh"
    ];
    NSFileManager *fm = NSFileManager.defaultManager;
    for (NSString *p in paths) {
        if ([fm fileExistsAtPath:p]) return YES;
    }

    NSURL *cydiaURL = [NSURL URLWithString:@"cydia://package/com.example"];
    if ([[UIApplication sharedApplication] canOpenURL:cydiaURL]) {
        return YES;
    }

    NSString *testPath = @"/private/jb_test.txt";
    @try {
        [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        if ([fm fileExistsAtPath:testPath]) {
            [fm removeItemAtPath:testPath error:nil];
            return YES;
        }
    } @catch (NSException *exception) { }

    if ([self hasSuspiciousDylibs]) return YES;

    return NO;
}

+ (BOOL)hasSuspiciousDylibs {
    NSArray<NSString *> *keywords = @[
        @"MobileSubstrate", @"Substrate", @"CydiaSubstrate",
        @"cycript", @"frida", @"FridaGadget", @"libhooker", @"substrate"
    ];
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *lib = [NSString stringWithUTF8String:name].lowercaseString;
        for (NSString *k in keywords) {
            if ([lib containsString:k.lowercaseString]) {
                return YES;
            }
        }
    }
    return NO;
}

#pragma mark - Debugger Detection

+ (BOOL)isDebuggerAttached {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    int ret = sysctl(mib, 4, &info, &size, NULL, 0);
    if (ret == 0) {
        return ((info.kp_proc.p_flag & P_TRACED) != 0);
    }
    return NO;
}

+ (void)denyDebuggerIfPossible {
#if !TARGET_OS_SIMULATOR
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
#endif
}

#pragma mark - Frida / Runtime Instrumentation

+ (BOOL)isFridaDetected {
    if ([self hasSuspiciousDylibs]) return YES;

    char *env = getenv("DYLD_INSERT_LIBRARIES");
    if (env && strlen(env) > 0) return YES;

    int ports[] = {27042, 27043};
    for (int i = 0; i < 2; i++) {
        if ([self isLocalPortOpen:ports[i]]) return YES;
    }
    return NO;
}

+ (BOOL)isLocalPortOpen:(int)port {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return NO;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 100 * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int res = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    close(sockfd);
    return (res == 0);
}

#pragma mark - App Debuggable (Development Build Entitlement)

+ (BOOL)isAppDebuggable {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) return NO;
    CFTypeRef val = SecTaskCopyValueForEntitlement(task, CFSTR("get-task-allow"), NULL);
    CFRelease(task);
    if (!val) return NO;
    BOOL allowed = CFBooleanGetValue((CFBooleanRef)val);
    CFRelease(val);
    return allowed;
}

@end
