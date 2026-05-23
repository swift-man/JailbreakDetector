# JailbreakDetector

A lightweight Swift Package for detecting common jailbreak indicators on iOS.

## Requirements

- iOS 15.0+
- Swift 5.9+

## Installation

Add this package in Xcode:

```text
https://github.com/swift-man/JailbreakDetector
```

Or add it to `Package.swift`:

```swift
.package(url: "https://github.com/swift-man/JailbreakDetector", .upToNextMinor(from: "0.5.0"))
```

Then add `JailbreakDetector` to your target dependencies:

```swift
.target(
  name: "YourApp",
  dependencies: ["JailbreakDetector"]
)
```

## Usage

```swift
import JailbreakDetector

let detector = JailbreakDetector()

do {
  try detector.detect()
} catch let error as JailbreakDetectionError {
  print("Jailbreak detected: \(error.code), \(error.message)")
} catch {
  print("Jailbreak detection failed: \(error)")
}
```

To customize checks:

```swift
try detector.detect(options: [.filePathChecks, .sandboxWrite, .dyldScan, .environmentVariableChecks])
```

Use `.all` only when your app should also run the more aggressive system write probe:

```swift
try detector.detect(options: .all)
```

The `.sandboxWrite` and `.systemWrite` checks intentionally attempt writes outside the app sandbox. Failed writes are expected on non-jailbroken devices, but they can create diagnostic or crash-reporting noise in some production telemetry. If that is a problem for your app, pass a custom option set that omits those checks.

JailbreakDetector does not use URL scheme checks such as `cydia://`, `sileo://`, `zebra://`, or `filza://` in the default detection flow because those schemes can produce false positives.

Rootless `/var/jb` symbolic link findings are reported as `suspiciousSymbolicLink` with error code `08`, so telemetry can distinguish symlink-based signals from regular suspicious system paths.

## Release

Current release: `0.5.0`

See [CHANGELOG.md](CHANGELOG.md) for release notes.
