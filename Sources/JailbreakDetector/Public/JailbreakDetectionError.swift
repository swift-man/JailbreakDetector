//
//  JailbreakDetectionError.swift
//  JailbreakDetector
//
//  Created by Gorani on 12/8/25.
//  Copyright © 2025 Gorani. All rights reserved.
//

import Foundation

public enum JailbreakDetectionError: Error, Equatable, LocalizedError, Sendable {
  case suspiciousApplication(path: String)
  case suspiciousSystemPath(path: String)
  case sandboxWriteSucceeded(path: String)
  case suspiciousFile(path: String)
  case suspiciousDynamicLibrary(name: String)

  public var code: String {
    switch self {
    case .suspiciousApplication:
      return "01"
    case .suspiciousSystemPath:
      return "02"
    case .sandboxWriteSucceeded:
      return "04"
    case .suspiciousFile:
      return "05"
    case .suspiciousDynamicLibrary:
      return "06"
    }
  }

  public var message: String {
    switch self {
    case .suspiciousApplication(let path):
      return "Suspicious application path exists: \(path)"
    case .suspiciousSystemPath(let path):
      return "Suspicious system path exists: \(path)"
    case .suspiciousFile(let path):
      return "Suspicious jailbreak file exists: \(path)"
    case .sandboxWriteSucceeded(let path):
      return "Sandbox write check succeeded: \(path)"
    case .suspiciousDynamicLibrary(let name):
      return "Suspicious dynamic library loaded: \(name)"
    }
  }

  public var errorDescription: String? {
    message
  }
}
