#import "Libsodium.h"
#import <React/RCTBridge+Private.h>
#import <React/RCTLog.h>
#import "react-native-libsodium.h"

@implementation Libsodium

@synthesize bridge=_bridge;

- (BOOL)install
{
  RCTLogInfo(@"installing libsodium");
  RCTCxxBridge *cxxBridge = (RCTCxxBridge *)self.bridge;
  if (!cxxBridge.runtime) {
    RCTLogInfo(@"libsodium install failure: no cxx bridge runtime");
    return NO;
  }

  RCTLogInfo(@"calling installLibsodium with cxx bridge runtime");
  ReactNativeLibsodium::installLibsodium(*(facebook::jsi::Runtime *)cxxBridge.runtime);
  return YES;
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeLibsodiumSpecJSI>(params);
}

+ (NSString *)moduleName
{
  return @"Libsodium";
}

@end
