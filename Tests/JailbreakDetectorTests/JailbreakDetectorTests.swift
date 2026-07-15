import Foundation
import Testing
@testable import JailbreakDetector

private struct TestWriteError: Error {}

private enum AsyncDetectionTestError: Error {
  case expected
}

private final class AsyncDetectionRecorder: JailbreakDetecting, @unchecked Sendable {
  private let lock = NSLock()
  private var _options: JailbreakCheckOptions?
  private var _didRunOnMainThread: Bool?

  var options: JailbreakCheckOptions? {
    lock.lock()
    defer { lock.unlock() }
    return _options
  }

  var didRunOnMainThread: Bool? {
    lock.lock()
    defer { lock.unlock() }
    return _didRunOnMainThread
  }

  func detect(options: JailbreakCheckOptions) throws {
    lock.lock()
    defer { lock.unlock() }
    _options = options
    _didRunOnMainThread = Thread.isMainThread
  }
}

private struct FailingAsyncDetector: JailbreakDetecting {
  func detect(options: JailbreakCheckOptions) throws {
    throw AsyncDetectionTestError.expected
  }
}

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

private final class CancellationProbe: @unchecked Sendable {
  private let lock = NSLock()
  private var _fileExistsCallCount = 0
  private var isCancellationRequested = false

  var fileExistsCallCount: Int {
    lock.lock()
    defer { lock.unlock() }
    return _fileExistsCallCount
  }

  func checkCancellation() throws {
    lock.lock()
    let shouldCancel = isCancellationRequested
    lock.unlock()

    if shouldCancel {
      throw CancellationError()
    }
  }

  func requestCancellation() {
    lock.lock()
    defer { lock.unlock() }
    isCancellationRequested = true
  }

  func fileExists(at path: String) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    _fileExistsCallCount += 1
    isCancellationRequested = true
    return false
  }
}

private final class BlockingOperationProbe: @unchecked Sendable {
  private let condition = NSCondition()
  private var didStart = false
  private var canFinish = false

  func runIgnoringCancellation() {
    condition.lock()
    didStart = true
    condition.broadcast()

    while !canFinish {
      condition.wait()
    }
    condition.unlock()
  }

  func waitUntilStarted() async {
    while true {
      if hasStarted() { return }
      await Task.yield()
    }
  }

  func finish() {
    condition.lock()
    canFinish = true
    condition.broadcast()
    condition.unlock()
  }

  private func hasStarted() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    return didStart
  }
}

@Test
func defaultOptionsIncludeExpectedChecks() {
  #expect(JailbreakCheckOptions.default.contains(.filePathChecks))
  #expect(JailbreakCheckOptions.default.contains(.sandboxWrite))
  #expect(JailbreakCheckOptions.default.contains(.dyldScan))
  #expect(!JailbreakCheckOptions.default.contains(.environmentVariableChecks))
  #expect(!JailbreakCheckOptions.default.contains(.systemWrite))
}

@Test
func strictOptionsIncludeEnvironmentVariableChecks() {
  #expect(JailbreakCheckOptions.strict.contains(.filePathChecks))
  #expect(JailbreakCheckOptions.strict.contains(.sandboxWrite))
  #expect(JailbreakCheckOptions.strict.contains(.dyldScan))
  #expect(JailbreakCheckOptions.strict.contains(.environmentVariableChecks))
  #expect(!JailbreakCheckOptions.strict.contains(.systemWrite))
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
  let options = JailbreakDetector.effectiveOptions(.strict,
                                                  isDebugBuild: true)

  #expect(!options.contains(.environmentVariableChecks))
  #expect(options.contains(.filePathChecks))
  #expect(options.contains(.sandboxWrite))
  #expect(options.contains(.dyldScan))
}

@Test
func detectorEffectiveOptionsKeepEnvironmentVariablesForReleaseBuilds() {
  let options = JailbreakDetector.effectiveOptions(.strict,
                                                  isDebugBuild: false)

  #expect(options.contains(.environmentVariableChecks))
}

@Test
func detectorDetectAcceptsEmptyCustomOptions() {
  #expect(throws: Never.self) {
    try JailbreakDetector().detect(options: [])
  }
}

@Test
@MainActor
func asynchronousDetectionRunsOffTheMainThreadAndForwardsOptions() async throws {
  let detector = AsyncDetectionRecorder()

  try await detector.detect(options: .strict)

  #expect(detector.options == .strict)
  #expect(detector.didRunOnMainThread == false)
}

@Test
@MainActor
func asynchronousDetectionUsesDefaultOptions() async throws {
  let detector = AsyncDetectionRecorder()

  try await detector.detect()

  #expect(detector.options == .default)
  #expect(detector.didRunOnMainThread == false)
}

@Test
func asynchronousDetectionPropagatesErrors() async {
  let detector = FailingAsyncDetector()

  await #expect(throws: AsyncDetectionTestError.self) {
    try await detector.detect(options: .default)
  }
}

@Test
func asynchronousDetectionHonorsExistingCancellation() async {
  let detector = AsyncDetectionRecorder()

  let task = Task {
    withUnsafeCurrentTask { task in
      task?.cancel()
    }
    try await detector.detect(options: .default)
  }

  await #expect(throws: CancellationError.self) {
    try await task.value
  }
  #expect(detector.options == nil)
}

@Test
func asynchronousDetectionChecksCancellationAfterOperationFinishes() async {
  let probe = BlockingOperationProbe()
  let task = Task {
    try await JailbreakAsyncDetectionRunner.run {
      probe.runIgnoringCancellation()
    }
  }

  await probe.waitUntilStarted()
  task.cancel()
  probe.finish()

  await #expect(throws: CancellationError.self) {
    try await task.value
  }
}

@Test
func inspectorStopsFilePathScanAfterCancellation() {
  let probe = CancellationProbe()
  let environment = makeEnvironment(fileExists: { path in
    probe.fileExists(at: path)
  })

  #expect(throws: CancellationError.self) {
    try JailbreakInspector.detect(options: .filePathChecks,
                                  environment: environment,
                                  cancellationCheck: { try probe.checkCancellation() })
  }

  #expect(probe.fileExistsCallCount == 1)
}

@Test
func inspectorRemovesSuccessfulProbeFileWhenCancellationArrives() {
  let probe = CancellationProbe()
  let recorder = SandboxWriteRecorder()
  let environment = makeEnvironment(
    writeString: { string, url in
      recorder.recordWrite(string, url: url)
      probe.requestCancellation()
    },
    removeItem: { url in
      recorder.recordRemoval(url: url)
    }
  )

  #expect(throws: CancellationError.self) {
    try JailbreakInspector.detect(options: .sandboxWrite,
                                  environment: environment,
                                  cancellationCheck: { try probe.checkCancellation() })
  }

  #expect(recorder.writtenPath != nil)
  #expect(recorder.removedPath == recorder.writtenPath)
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

  #expect(throws: Never.self) {
    try JailbreakInspector.detect(options: .filePathChecks, environment: environment)
  }
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
func filePathChecksPreferSymbolicLinkErrorWhenRootlessAppPathExists() {
  let environment = makeEnvironment(
    fileExists: { path in
      path == "/var/jb/Applications/Cydia.app"
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

  #expect(throws: Never.self) {
    try JailbreakInspector.detect(options: .sandboxWrite, environment: environment)
  }
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
func dyldScanDetectsSuspiciousLibraryWithTrailingSlash() {
  let environment = makeEnvironment(loadedImageNames: {
    ["/usr/lib/fridagadget.dylib/"]
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .dyldScan, environment: environment)
  }

  #expect(error == .suspiciousDynamicLibrary(name: "FridaGadget.dylib"))
}

@Test
func dyldScanDetectsCydiaSubstrateDylib() {
  let environment = makeEnvironment(loadedImageNames: {
    ["/Library/MobileSubstrate/DynamicLibraries/CydiaSubstrate.dylib"]
  })

  let error = captureDetectionError {
    try JailbreakInspector.detect(options: .dyldScan, environment: environment)
  }

  #expect(error == .suspiciousDynamicLibrary(name: "CydiaSubstrate.dylib"))
}

@Test
func dyldScanPassesWhenLoadedLibrariesAreClean() {
  let environment = makeEnvironment(loadedImageNames: {
    [
      "/System/Library/Frameworks/Foundation.framework/Foundation",
      "/usr/lib/libswiftCore.dylib"
    ]
  })

  #expect(throws: Never.self) {
    try JailbreakInspector.detect(options: .dyldScan, environment: environment)
  }
}

#if canImport(MachO)
@Test
func dynamicLibraryRegistryCapturesLoadedImages() {
  #expect(!DynamicLibraryImageRegistry.shared.currentImageNames().isEmpty)
}
#endif

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

  #expect(throws: Never.self) {
    try JailbreakInspector.detect(options: .environmentVariableChecks, environment: environment)
  }
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
