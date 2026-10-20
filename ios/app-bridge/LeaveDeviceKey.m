#import <React/RCTBridgeModule.h>

// Registers the Swift LeaveDeviceKey module with React Native.
@interface RCT_EXTERN_MODULE(LeaveDeviceKey, NSObject)
RCT_EXTERN_METHOD(publicKey:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sign:(NSString *)message reason:(NSString *)reason resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(agreementPublicKey:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(reset:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
@end
