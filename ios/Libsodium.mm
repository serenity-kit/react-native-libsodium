#import "Libsodium.h"
#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import <React/RCTLog.h>
#import "react-native-libsodium.h"

@implementation Libsodium

@synthesize bridge=_bridge;

RCT_EXPORT_MODULE()

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install) {

  RCTLogInfo(@"installing libsodium");
  RCTCxxBridge *cxxBridge = (RCTCxxBridge *)self.bridge;
  if (!cxxBridge.runtime) {
    RCTLogInfo(@"libsodium install failure: no cxx bridge runtime");
    return nil;
  }

  RCTLogInfo(@"calling installLibsodium with cxx bridge runtime");
  ReactNativeLibsodium::installLibsodium(*(facebook::jsi::Runtime *)cxxBridge.runtime);
  return nil;
}

@end
