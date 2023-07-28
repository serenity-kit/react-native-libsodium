#import "react-native-libsodium.h"
#import <React/RCTBridgeModule.h>
#import "sodium.h"

@interface Libsodium : NSObject <RCTBridgeModule>

@property(nonatomic, assign) BOOL setBridgeOnMainQueue;

@end