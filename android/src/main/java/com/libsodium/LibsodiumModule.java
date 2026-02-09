package com.libsodium;

import com.facebook.react.bridge.ReactApplicationContext;

public class LibsodiumModule extends NativeLibsodiumSpec {
  public static final String NAME = NativeLibsodiumSpec.NAME;
  private static native void initialize(long jsiPtr);

  public LibsodiumModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
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
