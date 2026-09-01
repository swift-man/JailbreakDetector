![Badge - Swift](https://img.shields.io/badge/Swift-5.9-F05138.svg?style=flat-square&logo=Swift&logoColor=white)
![Badge - Version](https://img.shields.io/badge/Version-0.5.6-1177AA?style=flat-square)
![Badge - Swift Package Manager](https://img.shields.io/badge/SPM-compatible-orange?style=flat-square)
![Badge - Platform](https://img.shields.io/badge/iOS-v15.0-yellow?style=flat-square)
![Badge - License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

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
.package(url: "https://github.com/swift-man/JailbreakDetector", .upToNextMinor(from: "0.5.6"))
```

Then add `JailbreakDetector` to your target dependencies:

```swift
.target(
  name: "YourApp",
  dependencies: ["JailbreakDetector"]
)
```

Apps that use Firebase Analytics can also add the optional
`JailbreakDetectorFirebaseAnalytics` product. The core `JailbreakDetector`
target remains dependency-free and compatible with Swift 5.9. The Swift 5.9
fallback manifest does not resolve Firebase. Toolchains that use the default Swift
tools 6.1 manifest resolve Firebase at the package level even when an app links only
the core product.

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

Use the async overload from main-actor or app-launch flows to run file-system and runtime checks without blocking the caller's executor:

```swift
do {
  try await detector.detect()
} catch let error as JailbreakDetectionError {
  print("Jailbreak detected: \(error.code), \(error.message)")
}
```

The async overload runs the existing synchronous checks in a detached task while preserving the caller's priority and forwarding cancellation. The built-in `JailbreakDetector` cooperatively checks cancellation between detection stages and individual path or dynamic-library candidates. Existing `JailbreakDetecting` conformers remain source compatible because the protocol provides detached execution by default; custom synchronous implementations should check task cancellation internally when they perform long-running work.

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

## Firebase Analytics

The optional Firebase Analytics product standardizes launch-block telemetry across apps.
It requires Xcode 26.2 or later and Firebase iOS SDK 12.14.0 up to, but not including,
13.0.0. Add
`JailbreakDetectorFirebaseAnalytics` to the consuming app target, then add `-ObjC`
to that target's **Other Linker Flags** so Firebase Analytics Objective-C categories
are linked correctly.

Configure Firebase once in the consuming app before running launch checks:

```swift
import FirebaseCore

FirebaseApp.configure()
```

Report a detected jailbreak from the app-launch flow:

```swift
import JailbreakDetector
import JailbreakDetectorFirebaseAnalytics

do {
  try await JailbreakDetector().detect(options: .strict)
} catch let error as JailbreakDetectionError {
  JailbreakFirebaseAnalyticsReporter().reportLaunchBlocked(error)
  throw error
}
```

The reporter sends `jailbreak_launch_blocked` with these parameters:

- `reason_code`
- `reason_message`
- `app_version`
- `build_number`

The reporter does not configure Firebase and does not send anything before a default
`FirebaseApp` has been configured. This allows Firebase Remote Config, Analytics, and
other Firebase products in the host app to share one Firebase lifecycle.
Firebase queues events asynchronously, so present a launch-blocked UI instead of
terminating the process immediately after reporting.

To verify delivery in Firebase DebugView:

1. Add `-FIRDebugEnabled` to the app scheme's launch arguments.
2. Trigger a launch block and confirm `jailbreak_launch_blocked` includes
   `reason_code`, `reason_message`, `app_version`, and `build_number`.
3. Remove the debug argument after verification, or launch once with
   `-FIRDebugDisabled`.

The `.sandboxWrite` and `.systemWrite` checks intentionally attempt writes outside the app sandbox. Failed writes are expected on non-jailbroken devices, but they can create diagnostic or crash-reporting noise in some production telemetry. If that is a problem for your app, pass a custom option set that omits those checks.

The default option set avoids `.environmentVariableChecks` to keep normal app launches at a lower false-positive risk. In debug builds, `.environmentVariableChecks` is removed even when it is included in a custom option set. Release and TestFlight builds honor the option as passed.

JailbreakDetector does not use URL scheme checks such as `cydia://`, `sileo://`, `zebra://`, or `filza://` in the default detection flow because those schemes can produce false positives.

Rootless `/var/jb` symbolic link findings are reported as `suspiciousSymbolicLink` with error code `08`, so telemetry can distinguish symlink-based signals from regular suspicious system paths.

`DYLD_*` environment variable checks are opt-in through `.strict`, `.all`, or a custom option set. They are also skipped for debug builds to avoid flagging legitimate development tooling.

## Release

Current release: `0.5.6`

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

JailbreakDetector is released under the [MIT License](LICENSE).
