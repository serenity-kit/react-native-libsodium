require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-libsodium"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/serenity-kit/react-native-libsodium.git", :tag => "#{s.version}" }

  # Ensure vendored libsodium is unpacked even when npm/yarn postinstall scripts
  # are skipped (e.g. some CI/EAS builds).
  s.prepare_command = <<-CMD
    set -e
    if [ ! -d "libsodium/build/libsodium-apple/Clibsodium.xcframework" ]; then
      tar -xzf libsodium/build.tgz --directory libsodium
    fi
  CMD

  s.source_files = "ios/**/*.{h,m,mm}", "cpp/**/*.{h,cpp}"

  s.vendored_frameworks = "libsodium/build/libsodium-apple/Clibsodium.xcframework"

  install_modules_dependencies(s)

end
