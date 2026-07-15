//
//  JailbreakInspector.swift
//  JailbreakDetector
//
//  Created by Gorani on 11/4/25.
//  Copyright © 2025 Gorani. Licensed under the MIT License.
//

import Foundation

enum JailbreakInspector {
  typealias CancellationCheck = @Sendable () throws -> Void

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

  static func detect(
    options: JailbreakCheckOptions,
    environment: Environment = .live,
    cancellationCheck: CancellationCheck = {}
  ) throws {
    try cancellationCheck()

    if options.contains(.filePathChecks) {
      try cancellationCheck()
      try checkSuspiciousSymbolicLinks(environment: environment,
                                       cancellationCheck: cancellationCheck)
      try checkSuspiciousAppPaths(environment: environment,
                                  cancellationCheck: cancellationCheck)
      try checkSuspiciousSystemPaths(environment: environment,
                                     cancellationCheck: cancellationCheck)
      try checkJailbreakFilePaths(environment: environment,
                                  cancellationCheck: cancellationCheck)
    }

    if options.contains(.sandboxWrite) {
      try cancellationCheck()
      try sandboxWriteTest(path: "/private/\(UUID().uuidString)",
                           environment: environment,
                           cancellationCheck: cancellationCheck)
    }

    if options.contains(.systemWrite) {
      try cancellationCheck()
      try sandboxWriteTest(path: "/jb_sys_\(UUID().uuidString)",
                           environment: environment,
                           cancellationCheck: cancellationCheck)
    }

    if options.contains(.dyldScan) {
      try cancellationCheck()
      try checkLoadedDynamicLibraries(environment: environment,
                                      cancellationCheck: cancellationCheck)
    }

    if options.contains(.environmentVariableChecks) {
      try cancellationCheck()
      try checkSuspiciousEnvironmentVariables(environment: environment,
                                               cancellationCheck: cancellationCheck)
    }
  }

  // MARK: - Checks
  private static func checkSuspiciousAppPaths(
    environment: Environment,
    cancellationCheck: CancellationCheck
  ) throws {
    for path in suspiciousAppPaths {
      try cancellationCheck()
      if environment.fileExists(path) {
        throw JailbreakDetectionError.suspiciousApplication(path: path)
      }
    }
  }

  private static func checkSuspiciousSystemPaths(
    environment: Environment,
    cancellationCheck: CancellationCheck
  ) throws {
    for path in suspiciousSystemPaths {
      try cancellationCheck()
      if environment.fileExists(path) {
        throw JailbreakDetectionError.suspiciousSystemPath(path: path)
      }
    }
  }

  private static func checkJailbreakFilePaths(
    environment: Environment,
    cancellationCheck: CancellationCheck
  ) throws {
    for path in jailbreakFilePaths {
      try cancellationCheck()
      if environment.fileExists(path) {
        throw JailbreakDetectionError.suspiciousFile(path: path)
      }
    }
  }

  private static func checkSuspiciousSymbolicLinks(
    environment: Environment,
    cancellationCheck: CancellationCheck
  ) throws {
    for path in suspiciousSymbolicLinkPaths {
      try cancellationCheck()
      if environment.symbolicLinkDestination(path) != nil {
        throw JailbreakDetectionError.suspiciousSymbolicLink(path: path)
      }
    }
  }

  private static func sandboxWriteTest(
    path: String,
    environment: Environment,
    cancellationCheck: CancellationCheck
  ) throws {
    try cancellationCheck()
    let url = URL(fileURLWithPath: path, isDirectory: false)

    do {
      try environment.writeString("jailbreak", url)
    } catch {
      return
    }

    defer { try? environment.removeItem(url) }
    try cancellationCheck()
    throw JailbreakDetectionError.sandboxWriteSucceeded(path: path)
  }

  private static func checkSuspiciousEnvironmentVariables(
    environment: Environment,
    cancellationCheck: CancellationCheck
  ) throws {
    try cancellationCheck()
    let environmentVariables = environment.environmentVariables()

    for variableName in suspiciousEnvironmentVariableNames {
      try cancellationCheck()
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
    "CydiaSubstrate.dylib",
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

  private static func checkLoadedDynamicLibraries(
    environment: Environment,
    cancellationCheck: CancellationCheck
  ) throws {
    try cancellationCheck()
    for imageName in environment.loadedImageNames() {
      try cancellationCheck()
      if let libraryName = suspiciousDynamicLibraryName(in: imageName) {
        throw JailbreakDetectionError.suspiciousDynamicLibrary(name: libraryName)
      }
    }
  }

  private static func suspiciousDynamicLibraryName(in imageName: String) -> String? {
    let lastPathComponent = (imageName as NSString).lastPathComponent.lowercased()
    return suspiciousDynamicLibraryNameLookup[lastPathComponent]
  }

  private static func loadedDynamicLibraryImageNames() -> [String] {
    #if canImport(MachO)
    return DynamicLibraryImageRegistry.shared.currentImageNames()
    #else
    return []
    #endif
  }
}
