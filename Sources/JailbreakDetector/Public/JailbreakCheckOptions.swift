//
//  JailbreakCheckOptions.swift
//  JailbreakDetector
//
//  Created by Gorani on 11/4/25.
//  Copyright © 2025 Gorani. All rights reserved.
//

public struct JailbreakCheckOptions: OptionSet, Sendable {
  public let rawValue: Int
  public init(rawValue: Int) { self.rawValue = rawValue }

  // Suspicious application and system paths.
  public static let filePathChecks   = JailbreakCheckOptions(rawValue: 1 << 0)

  // Write checks under /private.
  public static let sandboxWrite     = JailbreakCheckOptions(rawValue: 1 << 1)

  // More aggressive system-level write checks.
  public static let systemWrite      = JailbreakCheckOptions(rawValue: 1 << 2)

  // Loaded dylib scan.
  public static let dyldScan         = JailbreakCheckOptions(rawValue: 1 << 3)

  // Suspicious runtime environment variables.
  public static let environmentVariableChecks = JailbreakCheckOptions(rawValue: 1 << 4)

  public static let `default`: JailbreakCheckOptions = [
    .filePathChecks,
    .sandboxWrite,
    .dyldScan
  ]

  // Higher-sensitivity preset for apps that accept more false-positive risk.
  public static let strict: JailbreakCheckOptions = [
    .filePathChecks,
    .sandboxWrite,
    .dyldScan,
    .environmentVariableChecks
  ]

  public static let all: JailbreakCheckOptions = [
    .strict,
    .systemWrite
  ]
}
