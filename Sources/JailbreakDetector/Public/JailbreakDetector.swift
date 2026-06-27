//
//  JailbreakDetector.swift
//  JailbreakDetector
//
//  Created by Gorani on 11/4/25.
//  Copyright © 2025 Gorani. Licensed under the MIT License.
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
    isDebugBuild: Bool = Self.isDebugBuild
  ) -> JailbreakCheckOptions {
    var effectiveOptions = options
    if isDebugBuild {
      // DEBUG is evaluated for the package target; SwiftPM normally propagates
      // the consuming app's build configuration to package dependencies.
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
}
