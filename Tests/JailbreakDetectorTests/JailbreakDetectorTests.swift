import Testing
@testable import JailbreakDetector

@Test
func defaultOptionsIncludeExpectedChecks() {
  #expect(JailbreakCheckOptions.default.contains(.filePathChecks))
  #expect(JailbreakCheckOptions.default.contains(.sandboxWrite))
  #expect(JailbreakCheckOptions.default.contains(.dyldScan))
  #expect(!JailbreakCheckOptions.default.contains(.systemWrite))
}

@Test
func allOptionsIncludeSystemWrite() {
  #expect(JailbreakCheckOptions.all.contains(.filePathChecks))
  #expect(JailbreakCheckOptions.all.contains(.sandboxWrite))
  #expect(JailbreakCheckOptions.all.contains(.systemWrite))
  #expect(JailbreakCheckOptions.all.contains(.dyldScan))
}

@Test
func jailbreakDetectionErrorDescriptionUsesMessage() {
  let error = JailbreakDetectionError.suspiciousApplication(path: "/Applications/Cydia.app")

  #expect(error.code == "01")
  #expect(error.message == "Suspicious application path exists: /Applications/Cydia.app")
  #expect(error.errorDescription == "Suspicious application path exists: /Applications/Cydia.app")
}
