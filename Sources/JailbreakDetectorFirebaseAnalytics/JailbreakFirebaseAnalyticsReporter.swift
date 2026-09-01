import FirebaseAnalytics
import FirebaseCore
import Foundation
import JailbreakDetector

/// A Firebase Analytics event describing a jailbreak block during app launch.
public struct JailbreakLaunchAnalyticsEvent: Equatable, Sendable {
  /// The stable Firebase Analytics event name.
  public static let name = "jailbreak_launch_blocked"
  static let maximumParameterStringLength = 100

  /// The stable event parameters accepted by Firebase Analytics.
  public let parameters: [String: String]

  /// Creates an event from a detection error and app bundle metadata.
  public init(error: JailbreakDetectionError, bundle: Bundle = .main) {
    self.init(
      error: error,
      appVersion: Self.bundleValue(
        forKey: "CFBundleShortVersionString",
        bundle: bundle
      ),
      buildNumber: Self.bundleValue(
        forKey: kCFBundleVersionKey as String,
        bundle: bundle
      )
    )
  }

  init(
    error: JailbreakDetectionError,
    appVersion: String,
    buildNumber: String
  ) {
    parameters = [
      "reason_code": Self.limitedValue(error.code),
      "reason_message": Self.limitedValue(Self.stableMessage(for: error)),
      "app_version": Self.nonEmptyValue(appVersion),
      "build_number": Self.nonEmptyValue(buildNumber)
    ]
  }

  private static func bundleValue(forKey key: String, bundle: Bundle) -> String {
    nonEmptyValue(bundle.object(forInfoDictionaryKey: key) as? String)
  }

  private static func nonEmptyValue(_ value: String?) -> String {
    guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines),
          !value.isEmpty else {
      return "unknown"
    }
    return limitedValue(value)
  }

  private static func limitedValue(_ value: String) -> String {
    String(value.prefix(maximumParameterStringLength))
  }

  private static func stableMessage(for error: JailbreakDetectionError) -> String {
    if case .sandboxWriteSucceeded = error {
      return "Sandbox write check succeeded"
    }
    return error.message
  }
}

/// Reports jailbreak launch blocks without coupling the launch flow to Firebase APIs.
public protocol JailbreakLaunchAnalyticsReporting: Sendable {
  /// Reports a jailbreak error that caused the app launch to be blocked.
  func reportLaunchBlocked(_ error: JailbreakDetectionError)
}

/// Sends jailbreak launch-block events to the configured default Firebase app.
public struct JailbreakFirebaseAnalyticsReporter: JailbreakLaunchAnalyticsReporting, Sendable {
  private let bundle: Bundle
  private let isFirebaseConfigured: @Sendable () -> Bool
  private let logEvent: @Sendable (String, [String: String]) -> Void

  /// Creates a reporter using the default Firebase app and the supplied app bundle.
  public init(bundle: Bundle = .main) {
    self.bundle = bundle
    isFirebaseConfigured = {
      FirebaseApp.app() != nil
    }
    logEvent = { name, parameters in
      Analytics.logEvent(
        name,
        parameters: parameters as [String: Any]
      )
    }
  }

  init(
    bundle: Bundle = .main,
    isFirebaseConfigured: @escaping @Sendable () -> Bool,
    logEvent: @escaping @Sendable (String, [String: String]) -> Void
  ) {
    self.bundle = bundle
    self.isFirebaseConfigured = isFirebaseConfigured
    self.logEvent = logEvent
  }

  /// Reports the error when a default Firebase app has already been configured.
  public func reportLaunchBlocked(_ error: JailbreakDetectionError) {
    guard isFirebaseConfigured() else {
      return
    }

    let event = JailbreakLaunchAnalyticsEvent(error: error, bundle: bundle)
    logEvent(JailbreakLaunchAnalyticsEvent.name, event.parameters)
  }
}
