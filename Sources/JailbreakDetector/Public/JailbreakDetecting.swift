//
//  JailbreakDetecting.swift
//  JailbreakDetector
//
//  Created by Gorani on 11/4/25.
//  Copyright © 2025 Gorani. Licensed under the MIT License.
//

public protocol JailbreakDetecting: Sendable {
  /// Runs the selected jailbreak checks synchronously on the current thread.
  func detect(options: JailbreakCheckOptions) throws

  /// Runs the selected jailbreak checks without blocking the caller's executor.
  @available(macOS 10.15, *)
  func detect(options: JailbreakCheckOptions) async throws
}

@available(macOS 10.15, *)
enum JailbreakAsyncDetectionRunner {
  /// Runs synchronous detection outside the caller's executor and forwards task cancellation.
  static func run(_ operation: @escaping @Sendable () throws -> Void) async throws {
    try Task.checkCancellation()

    let task = Task.detached(priority: Task.currentPriority) {
      try Task.checkCancellation()
      try operation()
    }

    try await withTaskCancellationHandler {
      try await task.value
      try Task.checkCancellation()
    } onCancel: {
      task.cancel()
    }
  }
}

public extension JailbreakDetecting {
  /// Runs the default jailbreak checks synchronously on the current thread.
  func detect() throws {
    try detect(options: .default)
  }

  /// Runs the default jailbreak checks without blocking the caller's executor.
  @available(macOS 10.15, *)
  func detect() async throws {
    try await detect(options: .default)
  }

  /// Runs the selected jailbreak checks on a detached task using the caller's priority.
  ///
  /// Existing conformers only need to implement the synchronous requirement. This
  /// default implementation preserves their source compatibility while providing
  /// an async entry point suitable for app launch and other main-actor flows.
  ///
  /// - Parameter options: The checks to perform.
  @available(macOS 10.15, *)
  func detect(options: JailbreakCheckOptions) async throws {
    let detector = self
    try await JailbreakAsyncDetectionRunner.run {
      try detector.detect(options: options)
    }
  }
}
