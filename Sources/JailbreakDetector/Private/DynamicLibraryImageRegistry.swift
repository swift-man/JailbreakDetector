//
//  DynamicLibraryImageRegistry.swift
//  JailbreakDetector
//
//  Created by Gorani on 2026/07/15.
//  Copyright © 2026 Gorani. Licensed under the MIT License.
//

#if canImport(MachO)
import Darwin
import Foundation
import MachO

/// Maintains a thread-safe snapshot of images reported by dyld callbacks.
final class DynamicLibraryImageRegistry: @unchecked Sendable {
  static let shared = DynamicLibraryImageRegistry()

  private static let installCallbacks: Void = {
    _dyld_register_func_for_add_image { header, _ in
      guard let header,
            let imageName = imageName(for: header) else { return }
      shared.insert(imageName)
    }

    _dyld_register_func_for_remove_image { header, _ in
      guard let header,
            let imageName = imageName(for: header) else { return }
      shared.remove(imageName)
    }
  }()

  private let lock = NSLock()
  private var imageNames: Set<String> = []

  private init() {}

  func currentImageNames() -> [String] {
    _ = Self.installCallbacks

    lock.lock()
    defer { lock.unlock() }
    return Array(imageNames)
  }

  private func insert(_ imageName: String) {
    lock.lock()
    defer { lock.unlock() }
    imageNames.insert(imageName)
  }

  private func remove(_ imageName: String) {
    lock.lock()
    defer { lock.unlock() }
    imageNames.remove(imageName)
  }

  private static func imageName(for header: UnsafePointer<mach_header>) -> String? {
    var information = Dl_info()
    guard dladdr(UnsafeRawPointer(header), &information) != 0,
          let path = information.dli_fname else { return nil }
    return String(validatingUTF8: path)
  }
}
#endif
