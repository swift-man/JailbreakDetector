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
      "reason_code": error.code,
      "reason_message": String(error.message.prefix(Self.maximumParameterStringLength)),
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
    return value
  }
}

/// Reports jailbreak launch blocks without coupling the launch flow to Firebase APIs.
public protocol JailbreakLaunchAnalyticsReporting {
  /// Reports a jailbreak error that caused the app launch to be blocked.
  func reportLaunchBlocked(_ error: JailbreakDetectionError)
}

/// Sends jailbreak launch-block events to the configured default Firebase app.
public struct JailbreakFirebaseAnalyticsReporter: JailbreakLaunchAnalyticsReporting {
  private let bundle: Bundle
  private let isFirebaseConfigured: () -> Bool
  private let logEvent: (String, [String: String]) -> Void

  /// Creates a reporter using the default Firebase app and the supplied app bundle.
  public init(bundle: Bundle = .main) {
    self.bundle = bundle
    isFirebaseConfigured = { FirebaseApp.app() != nil }
    logEvent = { name, parameters in
      Analytics.logEvent(
        name,
        parameters: parameters.reduce(into: [String: Any]()) { result, parameter in
          result[parameter.key] = parameter.value
        }
      )
    }
  }

  init(
    bundle: Bundle = .main,
    isFirebaseConfigured: @escaping () -> Bool,
    logEvent: @escaping (String, [String: String]) -> Void
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
