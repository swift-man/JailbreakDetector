//
//  JailbreakDetector.swift
//  JailbreakDetector
//
//  Created by Gorani on 11/4/25.
//  Copyright © 2025 Gorani. All rights reserved.
//

import Foundation

public struct JailbreakDetector: JailbreakDetecting, Sendable {
  public init() {}

  public func detect(options: JailbreakCheckOptions = .default) throws {
    #if targetEnvironment(simulator)
    return
    #else
    try JailbreakInspector.detect(options: Self.effectiveOptions(options))
    #endif
  }

  static func effectiveOptions(
    _ options: JailbreakCheckOptions,
    isDebugBuild: Bool = Self.isDebugBuild,
    isSandboxReceipt: Bool = Self.isSandboxReceipt
  ) -> JailbreakCheckOptions {
    var effectiveOptions = options
    if isDebugBuild || isSandboxReceipt {
      // Xcode and TestFlight can expose DYLD_* variables for legitimate tooling.
      effectiveOptions.remove(.environmentVariableChecks)
    }
    return effectiveOptions
  }

  private static var isDebugBuild: Bool {
    #if DEBUG
    return true
    #else
    return false
    #endif
  }

  private static var isSandboxReceipt: Bool {
    Bundle.main.appStoreReceiptURL?.lastPathComponent == "sandboxReceipt"
  }
}
