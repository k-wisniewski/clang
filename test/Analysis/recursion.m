// RUN: %clang_cc1 -analyze -analyzer-checker=core,osx.cocoa.RetainCount,alpha.core -analyzer-config ipa=none -analyzer-store=region -verify %s

typedef signed char BOOL;
@protocol NSObject  - (BOOL)isEqual:(id)object; @end
@interface NSObject <NSObject> {}
+(id)alloc;
-(id)init;
-(id)autorelease;
-(id)copy;
-(id)retain;
@end

@interface RecursionTestClass: NSObject
-(void) callWithArgument:(int)a;
@end

@implementation RecursionTestClass

-(void) callWithArgument:(int)a {
  [self callWithArgument: a]; // expected-warning {{Infinite recursion detected}}
}

@end