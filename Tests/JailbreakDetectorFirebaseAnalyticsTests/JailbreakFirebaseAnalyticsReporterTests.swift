import Foundation
@testable import JailbreakDetectorFirebaseAnalytics
import JailbreakDetector
import XCTest

final class JailbreakFirebaseAnalyticsReporterTests: XCTestCase {
  func testEventUsesStableFirebaseKeys() {
    let event = JailbreakLaunchAnalyticsEvent(
      error: .suspiciousSymbolicLink(path: "/var/jb"),
      appVersion: " 1.2.3 ",
      buildNumber: " 45 "
    )

    XCTAssertEqual(JailbreakLaunchAnalyticsEvent.name, "jailbreak_launch_blocked")
    XCTAssertEqual(event.parameters, [
      "reason_code": "08",
      "reason_message": "Suspicious symbolic link exists: /var/jb",
      "app_version": "1.2.3",
      "build_number": "45"
    ])
  }

  func testEventLimitsStringParametersForFirebaseAnalytics() {
    let longPath = "/" + String(repeating: "a", count: 200)
    let event = JailbreakLaunchAnalyticsEvent(
      error: .suspiciousFile(path: longPath),
      appVersion: String(repeating: "1", count: 200),
      buildNumber: String(repeating: "2", count: 200)
    )

    for value in event.parameters.values {
      XCTAssertLessThanOrEqual(
        value.count,
        JailbreakLaunchAnalyticsEvent.maximumParameterStringLength
      )
    }
  }

  func testEventUsesFallbackForEmptyBundleValues() {
    let event = JailbreakLaunchAnalyticsEvent(
      error: .suspiciousFile(path: "/var/jb"),
      appVersion: "",
      buildNumber: "  "
    )

    XCTAssertEqual(event.parameters["app_version"], "unknown")
    XCTAssertEqual(event.parameters["build_number"], "unknown")
  }

  func testEventNormalizesRandomSandboxProbePath() {
    let event = JailbreakLaunchAnalyticsEvent(
      error: .sandboxWriteSucceeded(path: "/private/123E4567-E89B-12D3-A456-426614174000"),
      appVersion: "1.2.3",
      buildNumber: "45"
    )

    XCTAssertEqual(
      event.parameters["reason_message"],
      "Sandbox write check succeeded"
    )
  }

  func testReporterDoesNotLogBeforeFirebaseIsConfigured() {
    let loggedEventCount = LockedBox(0)
    let reporter = JailbreakFirebaseAnalyticsReporter(
      isFirebaseConfigured: { false },
      logEvent: { _, _ in loggedEventCount.update { $0 += 1 } }
    )

    reporter.reportLaunchBlocked(.suspiciousSystemPath(path: "/private/preboot"))

    XCTAssertEqual(loggedEventCount.current, 0)
  }

  func testReporterLogsAfterFirebaseIsConfigured() {
    let loggedEvent = LockedBox<LoggedEvent?>(nil)
    let reporter = JailbreakFirebaseAnalyticsReporter(
      isFirebaseConfigured: { true },
      logEvent: { name, parameters in
        loggedEvent.update { $0 = LoggedEvent(name: name, parameters: parameters) }
      }
    )

    reporter.reportLaunchBlocked(.suspiciousEnvironmentVariable(name: "DYLD_INSERT_LIBRARIES"))

    XCTAssertEqual(loggedEvent.current?.name, "jailbreak_launch_blocked")
    XCTAssertEqual(loggedEvent.current?.parameters["reason_code"], "07")
    XCTAssertEqual(
      loggedEvent.current?.parameters["reason_message"],
      "Suspicious environment variable exists: DYLD_INSERT_LIBRARIES"
    )
  }

  func testReporterUsesInjectedBundleMetadata() {
    let loggedEvent = LockedBox<LoggedEvent?>(nil)
    let reporter = JailbreakFirebaseAnalyticsReporter(
      bundle: StubBundle(),
      isFirebaseConfigured: { true },
      logEvent: { name, parameters in
        loggedEvent.update { $0 = LoggedEvent(name: name, parameters: parameters) }
      }
    )

    reporter.reportLaunchBlocked(.suspiciousFile(path: "/var/jb"))

    XCTAssertEqual(loggedEvent.current?.parameters["app_version"], "9.9.9")
    XCTAssertEqual(loggedEvent.current?.parameters["build_number"], "777")
  }
}

private struct LoggedEvent {
  let name: String
  let parameters: [String: String]
}

private final class StubBundle: Bundle, @unchecked Sendable {
  override func object(forInfoDictionaryKey key: String) -> Any? {
    switch key {
    case "CFBundleShortVersionString":
      return "9.9.9"
    case "CFBundleVersion":
      return "777"
    default:
      return nil
    }
  }
}

private final class LockedBox<Value>: @unchecked Sendable {
  private let lock = NSLock()
  private var value: Value

  init(_ value: Value) {
    self.value = value
  }

  var current: Value {
    lock.lock()
    defer { lock.unlock() }
    return value
  }

  func update(_ body: (inout Value) -> Void) {
    lock.lock()
    defer { lock.unlock() }
    body(&value)
  }
}
