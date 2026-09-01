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
      appVersion: "",
      buildNumber: "  "
    )

    XCTAssertEqual(
      event.parameters["reason_message"]?.count,
      JailbreakLaunchAnalyticsEvent.maximumParameterStringLength
    )
    XCTAssertEqual(event.parameters["app_version"], "unknown")
    XCTAssertEqual(event.parameters["build_number"], "unknown")
  }

  func testReporterDoesNotLogBeforeFirebaseIsConfigured() {
    var loggedEventCount = 0
    let reporter = JailbreakFirebaseAnalyticsReporter(
      isFirebaseConfigured: { false },
      logEvent: { _, _ in loggedEventCount += 1 }
    )

    reporter.reportLaunchBlocked(.suspiciousSystemPath(path: "/private/preboot"))

    XCTAssertEqual(loggedEventCount, 0)
  }

  func testReporterLogsAfterFirebaseIsConfigured() {
    var loggedName: String?
    var loggedParameters: [String: String]?
    let reporter = JailbreakFirebaseAnalyticsReporter(
      isFirebaseConfigured: { true },
      logEvent: { name, parameters in
        loggedName = name
        loggedParameters = parameters
      }
    )

    reporter.reportLaunchBlocked(.suspiciousEnvironmentVariable(name: "DYLD_INSERT_LIBRARIES"))

    XCTAssertEqual(loggedName, "jailbreak_launch_blocked")
    XCTAssertEqual(loggedParameters?["reason_code"], "07")
    XCTAssertEqual(
      loggedParameters?["reason_message"],
      "Suspicious environment variable exists: DYLD_INSERT_LIBRARIES"
    )
  }
}
