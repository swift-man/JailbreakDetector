# ``JailbreakDetector``

A lightweight Swift package for detecting common jailbreak indicators on iOS.

## Overview

Use JailbreakDetector to run a small set of jailbreak checks before enabling security-sensitive app flows.

The detector skips checks when running in the simulator. On device, the default configuration checks suspicious application paths, suspicious system paths, sandbox write behavior, loaded dynamic libraries, and suspicious runtime environment variables. Environment variable checks are skipped for debug builds to avoid flagging legitimate development tooling. Release and TestFlight builds keep these checks enabled.

## Installation

Add JailbreakDetector as a Swift Package dependency:

```swift
.package(url: "https://github.com/swift-man/JailbreakDetector", .upToNextMinor(from: "0.5.2"))
```

JailbreakDetector supports iOS 15.0 and later.

## Usage

Create a detector and call ``JailbreakDetector/detect(options:)``.

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

## Custom Checks

Pass ``JailbreakCheckOptions`` to choose which checks should run.

```swift
try detector.detect(options: [.filePathChecks, .sandboxWrite, .dyldScan, .environmentVariableChecks])
```

Use ``JailbreakCheckOptions/all`` only when the app should also run the more aggressive system write probe.

The ``JailbreakCheckOptions/sandboxWrite`` and ``JailbreakCheckOptions/systemWrite`` checks intentionally attempt writes outside the app sandbox. Failed writes are expected on non-jailbroken devices, but they can create diagnostic or crash-reporting noise in some production telemetry. If that is a problem for your app, pass a custom option set that omits those checks.

JailbreakDetector intentionally avoids URL scheme checks such as `cydia://`, `sileo://`, `zebra://`, and `filza://` in its default flow because those schemes can be registered without proving that the device is jailbroken.

Rootless `/var/jb` symbolic link findings are reported as ``JailbreakDetectionError/suspiciousSymbolicLink(path:)`` with error code `08`, so telemetry can distinguish symlink-based signals from regular suspicious system paths.

## Version

The current release is 0.5.2.

## Topics

### Detection

- ``JailbreakDetector``
- ``JailbreakDetecting``
- ``JailbreakCheckOptions``
- ``JailbreakDetectionError``
