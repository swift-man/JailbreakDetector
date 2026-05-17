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

Or add it to `Package.swift` before the first version tag:

```swift
.package(url: "https://github.com/swift-man/JailbreakDetector", branch: "main")
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
try detector.detect(options: [.filePathChecks, .sandboxWrite, .dyldScan])
```
