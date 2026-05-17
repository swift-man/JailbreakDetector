//
//  JailbreakDetector.swift
//  JailbreakDetector
//
//  Created by Gorani on 11/4/25.
//  Copyright © 2025 Gorani. All rights reserved.
//

public struct JailbreakDetector: JailbreakDetecting, Sendable {
  public static let live = Self()

  public init() {}

  public func detect(options: JailbreakCheckOptions = .default) throws {
    #if targetEnvironment(simulator)
    return
    #else
    try JailbreakInspector.detect(options: options)
    #endif
  }
}
