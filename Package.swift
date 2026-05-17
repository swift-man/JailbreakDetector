// swift-tools-version: 5.9

import PackageDescription

let package = Package(
  name: "JailbreakDetector",
  platforms: [
    .iOS(.v15)
  ],
  products: [
    .library(
      name: "JailbreakDetector",
      targets: ["JailbreakDetector"]
    )
  ],
  targets: [
    .target(
      name: "JailbreakDetector"
    ),
    .testTarget(
      name: "JailbreakDetectorTests",
      dependencies: ["JailbreakDetector"]
    )
  ],
  swiftLanguageVersions: [.v5]
)
