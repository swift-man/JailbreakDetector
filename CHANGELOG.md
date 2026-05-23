# Changelog

All notable changes to JailbreakDetector are documented here.

## Unreleased

### Added

- Added suspicious `DYLD_*` environment variable checks to the default detection flow.
- Added additional low false-positive jailbreak tool paths for SSH, Cycript, Cydia internals, APT, and PreferenceLoader.
- Added `/var/jb` symbolic link detection for rootless jailbreak layouts.

### Notes

- Generic system shell paths such as `/bin/sh` remain excluded from the added path checks to keep false positives low.
- Sandbox write checks can create diagnostic or crash-reporting noise, so apps with strict telemetry should pass custom options if needed.
- URL scheme checks such as `cydia://`, `sileo://`, `zebra://`, and `filza://` remain excluded because they can produce false positives.

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
