package com.libsodium;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

public class LibsodiumModule extends ReactContextBaseJavaModule {
  public static final String NAME = "Libsodium";
  private static native void initialize(long jsiPtr);

  public LibsodiumModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @NonNull
  @Override
  public String getName() {
    return NAME;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public boolean install() {
    try {
      System.loadLibrary("libsodium");

      ReactApplicationContext context = getReactApplicationContext();
      initialize(
        context.getJavaScriptContextHolder().get()
      );
      return true;
    } catch (Exception exception) {
      return false;
    }
  }
}