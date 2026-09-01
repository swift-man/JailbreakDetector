// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "FirebaseMinimumConsumer",
  platforms: [
    .iOS(.v15),
    .macOS(.v10_15)
  ],
  products: [
    .library(
      name: "FirebaseMinimumConsumer",
      targets: ["FirebaseMinimumConsumer"]
    )
  ],
  dependencies: [
    .package(name: "JailbreakDetector", path: "../../.."),
    .package(
      url: "https://github.com/firebase/firebase-ios-sdk.git",
      exact: "12.14.0"
    )
  ],
  targets: [
    .target(
      name: "FirebaseMinimumConsumer",
      dependencies: [
        .product(
          name: "JailbreakDetectorFirebaseAnalytics",
          package: "JailbreakDetector"
        ),
        .product(name: "FirebaseCore", package: "firebase-ios-sdk")
      ]
    )
  ]
)
