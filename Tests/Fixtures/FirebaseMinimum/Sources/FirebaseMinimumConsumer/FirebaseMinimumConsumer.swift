import FirebaseCore
import JailbreakDetectorFirebaseAnalytics

public enum FirebaseMinimumConsumer {
  public static func makeReporter() -> JailbreakFirebaseAnalyticsReporter {
    JailbreakFirebaseAnalyticsReporter()
  }

  public static var defaultFirebaseApp: FirebaseApp? {
    FirebaseApp.app()
  }
}
