// swift-tools-version: 5.9

import PackageDescription

let package = Package(
  name: "JailbreakDetector",
  platforms: [
    .iOS(.v15),
    .macOS(.v10_15)
  ],
  products: [
    .library(
      name: "JailbreakDetector",
      targets: ["JailbreakDetector"]
    ),
    .library(
      name: "JailbreakDetectorFirebaseAnalytics",
      targets: ["JailbreakDetectorFirebaseAnalytics"]
    )
  ],
  dependencies: [
    .package(url: "https://github.com/firebase/firebase-ios-sdk.git", from: "12.13.0")
  ],
  targets: [
    .target(
      name: "JailbreakDetector"
    ),
    .target(
      name: "JailbreakDetectorFirebaseAnalytics",
      dependencies: [
        "JailbreakDetector",
        .product(name: "FirebaseAnalytics", package: "firebase-ios-sdk"),
        .product(name: "FirebaseCore", package: "firebase-ios-sdk")
      ]
    ),
    .testTarget(
      name: "JailbreakDetectorTests",
      dependencies: ["JailbreakDetector"]
    ),
    .testTarget(
      name: "JailbreakDetectorFirebaseAnalyticsTests",
      dependencies: ["JailbreakDetectorFirebaseAnalytics"]
    )
  ],
  swiftLanguageVersions: [.v5]
)
