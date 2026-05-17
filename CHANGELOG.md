# Changelog

All notable changes to JailbreakDetector are documented here.

## 0.5.0 - 2026-05-17

Initial Swift Package release.

### Added

- SwiftPM package for `JailbreakDetector`.
- Public detection API through `JailbreakDetector`, `JailbreakDetecting`, `JailbreakCheckOptions`, and `JailbreakDetectionError`.
- iOS 15 minimum platform support.
- Default jailbreak checks for suspicious application paths, suspicious system paths, sandbox write behavior, and loaded dynamic libraries.
- Optional `.systemWrite` check through `JailbreakCheckOptions.all`.
- Simulator skip behavior for development builds.
- Swift Testing coverage for option configuration, error messages, file path checks, sandbox write behavior, and dynamic library matching.
- GitHub Actions CI for `swift test` and iOS package builds.
- DocC documentation generation and deployment workflow.

### Changed

- Replaced dependency injection framework usage with internal Swift-only environment injection for testable inspection logic.
- Kept the package dependency-free for easier SwiftPM adoption.
