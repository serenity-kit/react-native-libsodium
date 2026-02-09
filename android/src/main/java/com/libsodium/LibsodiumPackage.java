package com.libsodium;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.BaseReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.module.model.ReactModuleInfoProvider;

import java.util.HashMap;
import java.util.Map;


public class LibsodiumPackage extends BaseReactPackage {
  @Override
  @Nullable
  public NativeModule getModule(String name, ReactApplicationContext reactContext) {
    if (name.equals(LibsodiumModule.NAME)) {
      return new LibsodiumModule(reactContext);
    }
    return null;
  }

  @NonNull
  @Override
  public ReactModuleInfoProvider getReactModuleInfoProvider() {
    return () -> {
      Map<String, ReactModuleInfo> moduleInfos = new HashMap<>();
      moduleInfos.put(
        LibsodiumModule.NAME,
        new ReactModuleInfo(
          LibsodiumModule.NAME,
          LibsodiumModule.NAME,
          false,  // canOverrideExistingModule
          false,  // needsEagerInit
          false,  // isCxxModule
          true // isTurboModule
        )
      );
      return moduleInfos;
    };
  }
}
