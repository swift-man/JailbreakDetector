# ``JailbreakDetector``

A lightweight Swift package for detecting common jailbreak indicators on iOS.

## Overview

Use JailbreakDetector to run a small set of jailbreak checks before enabling security-sensitive app flows.

The detector skips checks when running in the simulator. On device, the default configuration checks suspicious application paths, suspicious system paths, sandbox write behavior, and loaded dynamic libraries.

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
try detector.detect(options: [.filePathChecks, .sandboxWrite, .dyldScan])
```

Use ``JailbreakCheckOptions/all`` only when the app should also run the more aggressive system write probe.

## Topics

### Detection

- ``JailbreakDetector``
- ``JailbreakDetecting``
- ``JailbreakCheckOptions``
- ``JailbreakDetectionError``
