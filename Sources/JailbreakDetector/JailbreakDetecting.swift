//
//  JailbreakDetecting.swift
//  JailbreakDetector
//
//  Created by Gorani on 11/4/25.
//  Copyright © 2025 Gorani. All rights reserved.
//

public protocol JailbreakDetecting: Sendable {
  func detect(options: JailbreakCheckOptions) throws
}

public extension JailbreakDetecting {
  func detect() throws {
    try detect(options: .default)
  }
}
