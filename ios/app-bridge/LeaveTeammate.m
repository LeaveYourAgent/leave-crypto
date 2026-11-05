#import <React/RCTBridgeModule.h>

// Registers the Swift LeaveTeammate module with React Native.
@interface RCT_EXTERN_MODULE(LeaveTeammate, NSObject)
RCT_EXTERN_METHOD(pinCached:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(pinAccept:(NSString *)recordJson mac:(NSString *)mac resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(pinMake:(NSString *)teammateAccountId spkiSha256:(NSString *)spkiSha256 compared:(BOOL)compared how:(NSString *)how resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(wrapDekToTeammate:(NSString *)type id:(NSString *)id spki:(NSString *)spki info:(NSString *)info resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(code:(NSString *)athleteAccountId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(checkCode:(NSString *)text teammateAccountId:(NSString *)teammateAccountId spki:(NSString *)spki resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sasStatus:(NSString *)athleteAccountId teammateAccountId:(NSString *)teammateAccountId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sasCommit:(NSString *)runId teammateAccountId:(NSString *)teammateAccountId spki:(NSString *)spki resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sasReveal:(NSString *)runId nT:(NSString *)nT resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sasDigits:(NSString *)runId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sasAnswer:(NSString *)runId athleteAccountId:(NSString *)athleteAccountId commitment:(NSString *)commitment resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sasCheck:(NSString *)runId nA:(NSString *)nA resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sasEnd:(NSString *)runId finished:(BOOL)finished resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
@end
