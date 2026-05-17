//
//  JailbreakDetectingError.swift
//  JailbreakDetector
//
//  Created by Gorani on 12/8/25.
//  Copyright © 2025 Gorani. All rights reserved.
//

import Foundation

public struct JailbreakDetectingError: Error, Equatable, LocalizedError, Sendable {
  public let code: String
  public let message: String

  public init(code: String, message: String) {
    self.code = code
    self.message = message
  }

  public var errorDescription: String? {
    message
  }
}
