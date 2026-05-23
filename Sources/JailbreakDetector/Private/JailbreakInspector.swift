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
  struct Environment: Sendable {
    let fileExists: @Sendable (String) -> Bool
    let symbolicLinkDestination: @Sendable (String) -> String?
    let environmentVariables: @Sendable () -> [String: String]
    let writeString: @Sendable (String, URL) throws -> Void
    let removeItem: @Sendable (URL) throws -> Void
    let loadedImageNames: @Sendable () -> [String]

    static let live = Environment(
      fileExists: { path in
        FileManager.default.fileExists(atPath: path)
      },
      symbolicLinkDestination: { path in
        try? FileManager.default.destinationOfSymbolicLink(atPath: path)
      },
      environmentVariables: {
        ProcessInfo.processInfo.environment
      },
      writeString: { string, url in
        try string.write(to: url, atomically: true, encoding: .utf8)
      },
      removeItem: { url in
        try FileManager.default.removeItem(at: url)
      },
      loadedImageNames: {
        JailbreakInspector.loadedDynamicLibraryImageNames()
      }
    )
  }

  static func detect(options: JailbreakCheckOptions, environment: Environment = .live) throws {
    if options.contains(.filePathChecks) {
      try checkSuspiciousAppPaths(environment: environment)
      try checkSuspiciousSymbolicLinks(environment: environment)
      try checkSuspiciousSystemPaths(environment: environment)
      try checkJailbreakFilePaths(environment: environment)
    }

    if options.contains(.sandboxWrite) {
      try sandboxWriteTest(path: "/private/\(UUID().uuidString)", environment: environment)
    }

    if options.contains(.systemWrite) {
      try sandboxWriteTest(path: "/jb_sys_\(UUID().uuidString)", environment: environment)
    }

    if options.contains(.dyldScan) {
      try checkLoadedDynamicLibraries(environment: environment)
    }

    if options.contains(.environmentVariableChecks) {
      try checkSuspiciousEnvironmentVariables(environment: environment)
    }
  }

  // MARK: - Checks
  private static func checkSuspiciousAppPaths(environment: Environment) throws {
    for path in suspiciousAppPaths {
      if environment.fileExists(path) {
        throw JailbreakDetectionError.suspiciousApplication(path: path)
      }
    }
  }

  private static func checkSuspiciousSystemPaths(environment: Environment) throws {
    for path in suspiciousSystemPaths {
      if environment.fileExists(path) {
        throw JailbreakDetectionError.suspiciousSystemPath(path: path)
      }
    }
  }

  private static func checkJailbreakFilePaths(environment: Environment) throws {
    for path in jailbreakFilePaths {
      if environment.fileExists(path) {
        throw JailbreakDetectionError.suspiciousFile(path: path)
      }
    }
  }

  private static func checkSuspiciousSymbolicLinks(environment: Environment) throws {
    for path in suspiciousSymbolicLinkPaths {
      if environment.symbolicLinkDestination(path) != nil {
        throw JailbreakDetectionError.suspiciousSymbolicLink(path: path)
      }
    }
  }

  private static func sandboxWriteTest(path: String, environment: Environment) throws {
    let url = URL(fileURLWithPath: path)

    do {
      try environment.writeString("jailbreak", url)
    } catch {
      return
    }

    try? environment.removeItem(url)
    throw JailbreakDetectionError.sandboxWriteSucceeded(path: path)
  }

  private static func checkSuspiciousEnvironmentVariables(environment: Environment) throws {
    let environmentVariables = environment.environmentVariables()

    for variableName in suspiciousEnvironmentVariableNames {
      if environmentVariables[variableName] != nil {
        throw JailbreakDetectionError.suspiciousEnvironmentVariable(name: variableName)
      }
    }
  }

  // MARK: - Datasets

  private static let suspiciousAppPaths: [String] = [
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

    // Checkra1n
    "/Applications/checkra1n.app",

    // Rootless jailbreak paths
    "/var/jb/Applications/Cydia.app",
    "/var/jb/Applications/Sileo.app",
    "/var/jb/Applications/Zebra.app"
  ]

  private static let suspiciousSystemPaths: [String] = [
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
    "/private/etc/apt",
    "/private/var/root/Library/PreferenceLoader/Preferences",
    "/usr/bin/sshd",
    "/usr/bin/ssh",
    "/usr/libexec/cydia",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
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
    "/var/lib/apt",
    "/var/lib/cydia",

    // Bootstrap files
    "/var/jb/preboot",
    "/var/jb/var"
  ]

  private static let jailbreakFilePaths: [String] = [
    "/etc/ssh/sshd_config",
    "/usr/bin/cycript",
    "/usr/lib/libcycript.dylib",
    "/usr/local/bin/cycript",
    "/usr/sbin/frida-server",
    "/var/cache/apt",
    "/var/jb/bin/bash",
    "/var/jb/bin/sh",
    "/var/tmp/cydia.log"
  ]

  private static let suspiciousDynamicLibraryNames: [String] = [
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

  private static let suspiciousSymbolicLinkPaths: [String] = [
    "/var/jb"
  ]

  private static let suspiciousEnvironmentVariableNames: [String] = [
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_LIBRARY_PATH"
  ]

  private static let suspiciousDynamicLibraryNameLookup: [String: String] = Dictionary(
    suspiciousDynamicLibraryNames.map { libraryName in
      (libraryName.lowercased(), libraryName)
    },
    uniquingKeysWith: { first, _ in first }
  )

  private static func checkLoadedDynamicLibraries(environment: Environment) throws {
    for imageName in environment.loadedImageNames() {
      if let libraryName = suspiciousDynamicLibraryName(in: imageName) {
        throw JailbreakDetectionError.suspiciousDynamicLibrary(name: libraryName)
      }
    }
  }

  private static func suspiciousDynamicLibraryName(in imageName: String) -> String? {
    let lastPathComponent = URL(fileURLWithPath: imageName).lastPathComponent.lowercased()
    return suspiciousDynamicLibraryNameLookup[lastPathComponent]
  }

  private static func loadedDynamicLibraryImageNames() -> [String] {
    #if canImport(MachO)
    let imageCount = _dyld_image_count()
    var imageNames: [String] = []
    imageNames.reserveCapacity(Int(imageCount))

    for index in 0..<imageCount {
      guard let cString = _dyld_get_image_name(index) else {
        continue
      }

      imageNames.append(String(cString: cString))
    }

    return imageNames
    #else
    return []
    #endif
  }
}
