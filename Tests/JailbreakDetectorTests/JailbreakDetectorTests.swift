import Foundation
import Testing
@testable import JailbreakDetector

private struct TestWriteError: Error {}

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

  #expect(error == .suspiciousSystemPath(path: "/var/jb"))
}

@Test
func sandboxWriteThrowsWhenWriteSucceeds() {
  var writtenString: String?
  var writtenPath: String?
  var removedPath: String?
  let environment = makeEnvironment(
    writeString: { string, url in
      writtenString = string
      writtenPath = url.path
    },
    removeItem: { url in
      removedPath = url.path
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
  #expect(writtenString == "jailbreak")
  #expect(writtenPath == path)
  #expect(removedPath == path)
}

@Test
func sandboxWritePassesWhenWriteFails() {
  var didRemove = false
  let environment = makeEnvironment(
    writeString: { _, _ in
      throw TestWriteError()
    },
    removeItem: { _ in
      didRemove = true
    }
  )

  #expect(runsSuccessfully {
    try JailbreakInspector.detect(options: .sandboxWrite, environment: environment)
  })
  #expect(!didRemove)
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
  fileExists: @escaping (String) -> Bool = { _ in false },
  symbolicLinkDestination: @escaping (String) -> String? = { _ in nil },
  environmentVariables: @escaping () -> [String: String] = { [:] },
  writeString: @escaping (String, URL) throws -> Void = { _, _ in throw TestWriteError() },
  removeItem: @escaping (URL) throws -> Void = { _ in },
  loadedImageNames: @escaping () -> [String] = { [] }
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
