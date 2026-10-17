#import "Libsodium.h"
#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import <React/RCTLog.h>
#import "react-native-libsodium.h"

@interface RCTBridge (LibsodiumRuntime)
- (void *)runtime;
@end

@implementation Libsodium

@synthesize bridge=_bridge;

RCT_EXPORT_MODULE()

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install) {

  RCTLogInfo(@"installing libsodium");
  void *runtime = [self.bridge runtime];
  if (!runtime) {
    RCTLogInfo(@"libsodium install failure: no cxx bridge runtime");
    return nil;
  }

  RCTLogInfo(@"calling installLibsodium with cxx bridge runtime");
  ReactNativeLibsodium::installLibsodium(*(facebook::jsi::Runtime *)runtime);
  return nil;
}

@end
