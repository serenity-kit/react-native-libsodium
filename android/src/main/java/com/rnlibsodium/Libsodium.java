package com.libsodium;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = Libsodium.NAME)
public class Libsodium extends ReactContextBaseJavaModule {
  public static final String NAME = "Libsodium";

  private native void installLibsodium(long jsContextNativePointer);

  public Libsodium(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }

  // static {
  //   System.loadLibrary("cpp");
  // }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public boolean install(ReactApplicationContext context) {
    try {
      System.loadLibrary("cpp");
      long jsContextPointer = context.getJavaScriptContextHolder().get();
      installLibsodium(jsContextPointer);
      return true;
    } catch (Exception exception) {
      return false;
    }
  }

  // private static native double nativeMultiply(double a, double b);

  // // Example method
  // // See https://reactnative.dev/docs/native-modules-android
  // @ReactMethod
  // public void multiply(double a, double b, Promise promise) {
  //   promise.resolve(nativeMultiply(a, b));
  // }
}
