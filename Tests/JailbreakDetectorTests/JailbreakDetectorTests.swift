import XCTest
@testable import JailbreakDetector

final class JailbreakDetectorTests: XCTestCase {
  func testDefaultOptionsIncludeExpectedChecks() {
    XCTAssertTrue(JailbreakCheckOptions.default.contains(.filePathChecks))
    XCTAssertTrue(JailbreakCheckOptions.default.contains(.sandboxWrite))
    XCTAssertTrue(JailbreakCheckOptions.default.contains(.dyldScan))
    XCTAssertFalse(JailbreakCheckOptions.default.contains(.systemWrite))
  }

  func testAllOptionsIncludeSystemWrite() {
    XCTAssertTrue(JailbreakCheckOptions.all.contains(.filePathChecks))
    XCTAssertTrue(JailbreakCheckOptions.all.contains(.sandboxWrite))
    XCTAssertTrue(JailbreakCheckOptions.all.contains(.systemWrite))
    XCTAssertTrue(JailbreakCheckOptions.all.contains(.dyldScan))
  }

  func testJailbreakDetectionErrorDescriptionUsesMessage() {
    let error = JailbreakDetectionError.suspiciousApplication(path: "/Applications/Cydia.app")

    XCTAssertEqual(error.code, "01")
    XCTAssertEqual(error.message, "Suspicious application path exists: /Applications/Cydia.app")
    XCTAssertEqual(error.errorDescription, "Suspicious application path exists: /Applications/Cydia.app")
  }
}
