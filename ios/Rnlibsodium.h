#import "react-native-rnlibsodium.h"
#import <React/RCTBridgeModule.h>
#import "sodium.h"

@interface Rnlibsodium : NSObject <RCTBridgeModule>

@property (nonatomic, assign) BOOL setBridgeOnMainQueue;

@end
