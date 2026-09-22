import Foundation
import FreightLogicNativeCore
import FreightLogicAppleBridge

public enum FreightLogicHostConfigurationError: String, Error, Equatable, Sendable {
    case httpsRequired
    case hostRequired
    case embeddedCredentialsForbidden
}

public struct FreightLogicHostConfiguration: Sendable {
    public let appURL: URL
    public let origin: WebOrigin

    public init(appURL: URL) throws {
        guard appURL.scheme?.lowercased() == "https" else {
            throw FreightLogicHostConfigurationError.httpsRequired
        }
        guard appURL.host != nil else {
            throw FreightLogicHostConfigurationError.hostRequired
        }
        guard appURL.user == nil, appURL.password == nil else {
            throw FreightLogicHostConfigurationError.embeddedCredentialsForbidden
        }
        guard let origin = WebOrigin(
            scheme: appURL.scheme ?? "",
            host: appURL.host ?? "",
            port: appURL.port ?? 0
        ) else {
            throw FreightLogicHostConfigurationError.hostRequired
        }
        self.appURL = appURL
        self.origin = origin
    }

    public func allowsMainFrameNavigation(to url: URL?) -> Bool {
        guard let url,
              let candidate = WebOrigin(
                scheme: url.scheme ?? "",
                host: url.host ?? "",
                port: url.port ?? 0
              ) else {
            return false
        }
        return candidate == origin
    }
}

#if canImport(WebKit)
import WebKit

@MainActor
public final class FreightLogicWebHost: NSObject, WKNavigationDelegate {
    public let configuration: FreightLogicHostConfiguration

    private let bridge: FreightLogicScriptBridge
    private let webViewConfiguration: WKWebViewConfiguration

    public init(
        configuration: FreightLogicHostConfiguration,
        router: any FreightLogicBridgeRouting
    ) {
        self.configuration = configuration

        let contentController = WKUserContentController()
        let bridge = FreightLogicScriptBridge(
            allowlist: OriginAllowlist(origins: [configuration.origin]),
            router: router
        )
        bridge.install(on: contentController)

        let webConfiguration = WKWebViewConfiguration()
        webConfiguration.userContentController = contentController
        webConfiguration.websiteDataStore = .default()

        self.bridge = bridge
        self.webViewConfiguration = webConfiguration
        super.init()
    }

    public func makeWebView() -> WKWebView {
        let webView = WKWebView(frame: .zero, configuration: webViewConfiguration)
        webView.navigationDelegate = self
        return webView
    }

    @discardableResult
    public func loadApp(in webView: WKWebView) -> WKNavigation? {
        webView.load(URLRequest(url: configuration.appURL))
    }

    public func tearDown() {
        bridge.uninstall(from: webViewConfiguration.userContentController)
    }

    public func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping @MainActor @Sendable (WKNavigationActionPolicy) -> Void
    ) {
        if navigationAction.targetFrame?.isMainFrame == false {
            decisionHandler(.allow)
            return
        }
        decisionHandler(configuration.allowsMainFrameNavigation(to: navigationAction.request.url) ? .allow : .cancel)
    }
}
#else
public enum FreightLogicNativeHostAvailability {
    public static let isWebKitAvailable = false
}
#endif
