import SwiftUI

@main
struct HWSignApp: App {
  #if os(macOS)
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
  #endif

  @StateObject private var themeManager = ThemeManager()

  var body: some Scene {
    WindowGroup {
      ContentView()
        .environmentObject(themeManager)
        #if os(macOS)
          .frame(minWidth: 400, minHeight: 400)
        #endif
        .preferredColorScheme(themeManager.isDarkMode ? .dark : .light)
    }
    #if os(macOS)
      .windowStyle(HiddenTitleBarWindowStyle())
    #endif
  }
}

#if os(macOS)
  class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
      // Setup macOS specific behavior if needed
      let appearance =
        UserDefaults.standard.bool(forKey: "isDarkMode")
        ? NSAppearance(named: .darkAqua) : NSAppearance(named: .aqua)
      NSApp.appearance = appearance
    }
  }
#endif

class ThemeManager: ObservableObject {
  @Published var isDarkMode: Bool {
    didSet {
      UserDefaults.standard.set(isDarkMode, forKey: "isDarkMode")
      #if os(macOS)
        NSApp.appearance = NSAppearance(named: isDarkMode ? .darkAqua : .aqua)
      #endif
    }
  }

  init() {
    // Use saved preference or default to system setting
    if UserDefaults.standard.object(forKey: "isDarkMode") != nil {
      self.isDarkMode = UserDefaults.standard.bool(forKey: "isDarkMode")
    } else {
      #if os(iOS)
        self.isDarkMode = UITraitCollection.current.userInterfaceStyle == .dark
      #else
        self.isDarkMode = false
      #endif
    }
  }
}
