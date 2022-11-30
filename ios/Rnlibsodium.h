#ifdef __cplusplus
#import "react-native-rnlibsodium.h"
#endif

#ifdef RCT_NEW_ARCH_ENABLED
#import "RNRnlibsodiumSpec.h"

@interface Rnlibsodium : NSObject <NativeRnlibsodiumSpec>
#else
#import <React/RCTBridgeModule.h>

@interface Rnlibsodium : NSObject <RCTBridgeModule>
#endif

@end
