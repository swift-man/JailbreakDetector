import Foundation
import Testing
@testable import JailbreakDetector

private struct TestWriteError: Error {}

private final class SandboxWriteRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var _writtenString: String?
  private var _writtenPath: String?
  private var _removedPath: String?

  var writtenString: String? {
    lock.lock()
    defer { lock.unlock() }
    return _writtenString
  }

  var writtenPath: String? {
    lock.lock()
    defer { lock.unlock() }
    return _writtenPath
  }

  var removedPath: String? {
    lock.lock()
    defer { lock.unlock() }
    return _removedPath
  }

  func recordWrite(_ string: String, url: URL) {
    lock.lock()
    defer { lock.unlock() }
    _writtenString = string
    _writtenPath = url.path
  }

  func recordRemoval(url: URL) {
    lock.lock()
    defer { lock.unlock() }
    _removedPath = url.path
  }
}

@Test
func defaultOptionsIncludeExpectedChecks() {
  #expect(JailbreakCheckOptions.default.contains(.filePathChecks))
  #expect(JailbreakCheckOptions.default.contains(.sandboxWrite))
  #expect(JailbreakCheckOptions.default.contains(.dyldScan))
  #expect(JailbreakCheckOptions.default.contains(.environmentVariableChecks))
  #expect(!JailbreakCheckOptions.default.contains(.systemWrite))
}

@Test
func allOptionsIncludeSystemWrite() {
  #expect(JailbreakCheckOptions.all.contains(.filePathChecks))
  #expect(JailbreakCheckOptions.all.contains(.sandboxWrite))
  #expect(JailbreakCheckOptions.all.contains(.systemWrite))
  #expect(JailbreakCheckOptions.all.contains(.dyldScan))
  #expect(JailbreakCheckOptions.all.contains(.environmentVariableChecks))
}

@Test
func detectorEffectiveOptionsExcludeEnvironmentVariablesForDebugBuilds() {
  let options = JailbreakDetector.effectiveOptions(.default,
                                                  isDebugBuild: true,
                                                  isSandboxReceipt: false)

  #expect(!options.contains(.environmentVariableChecks))
  #expect(options.contains(.filePathChecks))
  #expect(options.contains(.sandboxWrite))
  #expect(options.contains(.dyldScan))
}

@Test
func detectorEffectiveOptionsExcludeEnvironmentVariablesForSandboxReceipts() {
  let options = JailbreakDetector.effectiveOptions(.default,
                                                  isDebugBuild: false,
                                                  isSandboxReceipt: true)

  #expect(!options.contains(.environmentVariableChecks))
  #expect(options.contains(.filePathChecks))
  #expect(options.contains(.sandboxWrite))
  #expect(options.contains(.dyldScan))
}

@Test
func detectorEffectiveOptionsKeepEnvironmentVariablesForAppStoreBuilds() {
  let options = JailbreakDetector.effectiveOptions(.default,
                                                  isDebugBuild: false,
                                                  isSandboxReceipt: false)

  #expect(options.contains(.environmentVariableChecks))
}

@Test
func jailbreakDetectionErrorDescriptionUsesMessage() {
  let error = JailbreakDetectionError.suspiciousApplication(path: "/Applications/Cydia.app")

  #expect(error.code == "01")
  #expect(error.message == "Suspicious application path exists: /Applications/Cydia.app")
  #expect(error.errorDescription == "Suspicious application path exists: /Applications/Cydia.app")
}

@Test
func jailbreakDetectionErrorDescribesEnvironmentVariable() {
  let error = JailbreakDetectionError.suspiciousEnvironmentVariable(name: "DYLD_INSERT_LIBRARIES")

  #expect(error.code == "07")
  #expect(error.message == "Suspicious environment variable exists: DYLD_INSERT_LIBRARIES")
  #expect(error.errorDescription == "Suspicious environment variable exists: DYLD_INSERT_LIBRARIES")
}

@Test
func jailbreakDetectionErrorDescribesSymbolicLink() {
  let error = JailbreakDetectionError.suspiciousSymbolicLink(path: "/var/jb")

  #expect(error.code == "08")
  #expect(error.message == "Suspicious symbolic link exists: /var/jb")
  #expect(error.errorDescription == "Suspicious symbolic link exists: /var/jb")
}

@Test
func filePathChecksDetectSuspiciousApplicationPath() {
  let environment = makeEnvironment(fileExists: { path in
    path == "/Applications/Cydia.app"
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .filePathChecks, environment: environment)
  }

  #expect(error == .suspiciousApplication(path: "/Applications/Cydia.app"))
}

@Test
func filePathChecksDetectSuspiciousSystemPath() {
  let environment = makeEnvironment(fileExists: { path in
    path == "/var/jb"
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .filePathChecks, environment: environment)
  }

  #expect(error == .suspiciousSystemPath(path: "/var/jb"))
}

@Test
func filePathChecksDetectJailbreakFilePath() {
  let environment = makeEnvironment(fileExists: { path in
    path == "/usr/sbin/frida-server"
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .filePathChecks, environment: environment)
  }

  #expect(error == .suspiciousFile(path: "/usr/sbin/frida-server"))
}

@Test
func filePathChecksDetectAdditionalJailbreakToolPath() {
  let environment = makeEnvironment(fileExists: { path in
    path == "/usr/bin/cycript"
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .filePathChecks, environment: environment)
  }

  #expect(error == .suspiciousFile(path: "/usr/bin/cycript"))
}

@Test
func filePathChecksIgnoreGenericSystemShellPath() {
  let environment = makeEnvironment(fileExists: { path in
    path == "/bin/sh"
  })

  #expect(runsSuccessfully {
    try JailbreakInspector.detect(options: .filePathChecks, environment: environment)
  })
}

@Test
func filePathChecksDetectRootlessJailbreakSymbolicLink() {
  let environment = makeEnvironment(symbolicLinkDestination: { path in
    path == "/var/jb" ? "/private/preboot/example/procursus" : nil
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .filePathChecks, environment: environment)
  }

  #expect(error == .suspiciousSymbolicLink(path: "/var/jb"))
}

@Test
func filePathChecksPreferSymbolicLinkErrorWhenRootlessPathExists() {
  let environment = makeEnvironment(
    fileExists: { path in
      path == "/var/jb"
    },
    symbolicLinkDestination: { path in
      path == "/var/jb" ? "/private/preboot/example/procursus" : nil
    }
  )

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .filePathChecks, environment: environment)
  }

  #expect(error == .suspiciousSymbolicLink(path: "/var/jb"))
}

@Test
func sandboxWriteThrowsWhenWriteSucceeds() {
  let recorder = SandboxWriteRecorder()
  let environment = makeEnvironment(
    writeString: { string, url in
      recorder.recordWrite(string, url: url)
    },
    removeItem: { url in
      recorder.recordRemoval(url: url)
    }
  )

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .sandboxWrite, environment: environment)
  }

  guard case .sandboxWriteSucceeded(let path) = error else {
    Issue.record("Expected sandboxWriteSucceeded, got \(String(describing: error))")
    return
  }

  #expect(path.hasPrefix("/private/"))
  #expect(recorder.writtenString == "jailbreak")
  #expect(recorder.writtenPath == path)
  #expect(recorder.removedPath == path)
}

@Test
func sandboxWritePassesWhenWriteFails() {
  let recorder = SandboxWriteRecorder()
  let environment = makeEnvironment(
    writeString: { _, _ in
      throw TestWriteError()
    },
    removeItem: { url in
      recorder.recordRemoval(url: url)
    }
  )

  #expect(runsSuccessfully {
    try JailbreakInspector.detect(options: .sandboxWrite, environment: environment)
  })
  #expect(recorder.removedPath == nil)
}

@Test
func dyldScanDetectsSuspiciousLibraryByLastPathComponent() {
  let environment = makeEnvironment(loadedImageNames: {
    ["/usr/lib/fridagadget.dylib"]
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .dyldScan, environment: environment)
  }

  #expect(error == .suspiciousDynamicLibrary(name: "FridaGadget.dylib"))
}

@Test
func dyldScanPassesWhenLoadedLibrariesAreClean() {
  let environment = makeEnvironment(loadedImageNames: {
    [
      "/System/Library/Frameworks/Foundation.framework/Foundation",
      "/usr/lib/libswiftCore.dylib"
    ]
  })

  #expect(runsSuccessfully {
    try JailbreakInspector.detect(options: .dyldScan, environment: environment)
  })
}

@Test
func environmentVariableChecksDetectDyldInjectionVariable() {
  let environment = makeEnvironment(environmentVariables: {
    ["DYLD_INSERT_LIBRARIES": "/usr/lib/FridaGadget.dylib"]
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .environmentVariableChecks, environment: environment)
  }

  #expect(error == .suspiciousEnvironmentVariable(name: "DYLD_INSERT_LIBRARIES"))
}

@Test
func environmentVariableChecksPassWithoutSuspiciousVariables() {
  let environment = makeEnvironment(environmentVariables: {
    ["PATH": "/usr/bin"]
  })

  #expect(runsSuccessfully {
    try JailbreakInspector.detect(options: .environmentVariableChecks, environment: environment)
  })
}

private func makeEnvironment(
  fileExists: @escaping @Sendable (String) -> Bool = { _ in false },
  symbolicLinkDestination: @escaping @Sendable (String) -> String? = { _ in nil },
  environmentVariables: @escaping @Sendable () -> [String: String] = { [:] },
  writeString: @escaping @Sendable (String, URL) throws -> Void = { _, _ in throw TestWriteError() },
  removeItem: @escaping @Sendable (URL) throws -> Void = { _ in },
  loadedImageNames: @escaping @Sendable () -> [String] = { [] }
) -> JailbreakInspector.Environment {
  JailbreakInspector.Environment(
    fileExists: fileExists,
    symbolicLinkDestination: symbolicLinkDestination,
    environmentVariables: environmentVariables,
    writeString: writeString,
    removeItem: removeItem,
    loadedImageNames: loadedImageNames
  )
}

private func captureDetectionError(_ operation: () throws -> Void) -> JailbreakDetectionError? {
  do {
    try operation()
    return nil
  } catch let error as JailbreakDetectionError {
    return error
  } catch {
    Issue.record("Expected JailbreakDetectionError, got \(error)")
    return nil
  }
}

private func runsSuccessfully(_ operation: () throws -> Void) -> Bool {
  do {
    try operation()
    return true
  } catch {
    return false
  }
}
