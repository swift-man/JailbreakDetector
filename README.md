![Badge - Swift](https://img.shields.io/badge/Swift-5.9-F05138.svg?style=flat-square&logo=Swift&logoColor=white)
![Badge - Version](https://img.shields.io/badge/Version-0.5.3-1177AA?style=flat-square)
![Badge - Swift Package Manager](https://img.shields.io/badge/SPM-compatible-orange?style=flat-square)
![Badge - Platform](https://img.shields.io/badge/iOS-v15.0-yellow?style=flat-square)

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
.package(url: "https://github.com/swift-man/JailbreakDetector", .upToNextMinor(from: "0.5.3"))
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

Use `.strict` when your app should also treat suspicious `DYLD_*` environment variables as blocking signals:

```swift
try detector.detect(options: .strict)
```

Use `.all` only when your app should also run the more aggressive system write probe:

```swift
try detector.detect(options: .all)
```

The `.sandboxWrite` and `.systemWrite` checks intentionally attempt writes outside the app sandbox. Failed writes are expected on non-jailbroken devices, but they can create diagnostic or crash-reporting noise in some production telemetry. If that is a problem for your app, pass a custom option set that omits those checks.

The default option set avoids `.environmentVariableChecks` to keep normal app launches at a lower false-positive risk. In debug builds, `.environmentVariableChecks` is removed even when it is included in a custom option set. Release and TestFlight builds honor the option as passed.

JailbreakDetector does not use URL scheme checks such as `cydia://`, `sileo://`, `zebra://`, or `filza://` in the default detection flow because those schemes can produce false positives.

Rootless `/var/jb` symbolic link findings are reported as `suspiciousSymbolicLink` with error code `08`, so telemetry can distinguish symlink-based signals from regular suspicious system paths.

`DYLD_*` environment variable checks are opt-in through `.strict`, `.all`, or a custom option set. They are also skipped for debug builds to avoid flagging legitimate development tooling.

## Release

Current release: `0.5.3`

See [CHANGELOG.md](CHANGELOG.md) for release notes.
