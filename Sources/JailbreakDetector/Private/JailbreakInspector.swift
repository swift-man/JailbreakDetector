//
//  JailbreakInspector.swift
//  JailbreakDetector
//
//  Created by Gorani on 11/4/25.
//  Copyright © 2025 Gorani. All rights reserved.
//

#if canImport(MachO)
import MachO
#endif
import Foundation

enum JailbreakInspector {
  static func detect(options: JailbreakCheckOptions) throws {
    if options.contains(.filePathChecks) {
      try checkSuspiciousAppPaths()
      try checkSuspiciousSystemPaths()
      try checkJailbreakFilePaths()
    }

    if options.contains(.sandboxWrite) {
      try sandboxWriteTest(path: "/private/\(UUID().uuidString)")
    }

    if options.contains(.systemWrite) {
      try sandboxWriteTest(path: "/jb_sys_\(UUID().uuidString)")
    }

    if options.contains(.dyldScan) {
      try checkLoadedDynamicLibraries()
    }
  }

  // MARK: - Checks
  private static func checkSuspiciousAppPaths() throws {
    for path in suspiciousAppPaths {
      if FileManager.default.fileExists(atPath: path) {
        throw JailbreakDetectionError.suspiciousApplication(path: path)
      }
    }
  }

  private static func checkSuspiciousSystemPaths() throws {
    for path in suspiciousSystemPaths {
      if FileManager.default.fileExists(atPath: path) {
        throw JailbreakDetectionError.suspiciousSystemPath(path: path)
      }
    }
  }

  private static func checkJailbreakFilePaths() throws {
    for path in jailbreakFilePaths {
      if FileManager.default.fileExists(atPath: path) {
        throw JailbreakDetectionError.suspiciousFile(path: path)
      }
    }
  }

  private static func sandboxWriteTest(path: String) throws {
    do {
      try "jailbreak".write(toFile: path, atomically: true, encoding: .utf8)
    } catch {
      return
    }

    try? FileManager.default.removeItem(atPath: path)
    throw JailbreakDetectionError.sandboxWriteSucceeded(path: path)
  }

  // MARK: - Datasets

  private static let suspiciousAppPaths: Set<String> = [
    // Traditional jailbreaks
    "/Applications/Cydia.app",
    "/Applications/blackra1n.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",

    // Modern jailbreaks
    "/Applications/Palera1n.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/TrollStore.app",
    "/var/containers/Bundle/Application/TrollStore.app",

    // Checkra1n
    "/Applications/checkra1n.app",

    // Rootless jailbreak paths
    "/var/jb/Applications/Cydia.app",
    "/var/jb/Applications/Sileo.app",
    "/var/jb/Applications/Zebra.app"
  ]

  private static let suspiciousSystemPaths: Set<String> = [
    // Traditional paths
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/usr/bin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/bin/bash",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",

    // Modern jailbreak paths
    "/var/jb", // Rootless jailbreak root
    "/var/binpack", // Checkm8 jailbreak
    "/var/containers/Bundle/tweaksupport",
    "/var/mobile/Library/palera1n",
    "/var/mobile/Library/xyz.willy.Zebra",
    "/var/lib/undecimus",

    // Palera1n specific
    "/var/jb/basebin",
    "/var/jb/usr",
    "/var/jb/etc",
    "/var/jb/Library",
    "/var/jb/.installed_palera1n",
    "/var/binpack/Applications",
    "/var/binpack/usr",

    // TrollStore
    "/var/containers/Bundle/Application/trollstorehelper",
    "/var/containers/Bundle/trollstore",

    // Bootstrap files
    "/var/jb/preboot",
    "/var/jb/var"
  ]

  private static let jailbreakFilePaths: Set<String> = [
    "/bin/sh",
    "/etc/ssh/sshd_config",
    "/usr/sbin/frida-server",
    "/var/cache/apt",
    "/var/jb/bin/bash",
    "/var/jb/bin/sh",
    "/var/tmp/cydia.log"
  ]

  private static let suspiciousDynamicLibraryNames: Set<String> = [
    "systemhook.dylib",
    "roothideinit.dylib",
    "SubstrateLoader.dylib",
    "SSLKillSwitch2.dylib",
    "SSLKillSwitch.dylib",
    "MobileSubstrate.dylib",
    "TweakInject.dylib",
    "CydiaSubstrate",
    "SubstrateInserter.dylib",
    "SubstrateBootstrap.dylib",
    "ABypass.dylib",
    "FlyJB.dylib",
    "Substitute.dylib",
    "Cephei.dylib",
    "Electra.dylib",
    "AppSyncUnified-FrontBoard.dylib",
    "FridaGadget.dylib",
    "libcycript.dylib",
    "libhooker.dylib",
    "ellekit.dylib",
    "tweaksupport.dylib"
  ]

  private static func checkLoadedDynamicLibraries() throws {
    #if canImport(MachO)
    for index in 0..<_dyld_image_count() {
      let imageName = String(cString: _dyld_get_image_name(index))

      for libraryName in suspiciousDynamicLibraryNames
      where imageName.localizedCaseInsensitiveContains(libraryName) {
        throw JailbreakDetectionError.suspiciousDynamicLibrary(name: libraryName)
      }
    }
    #endif
  }
}
