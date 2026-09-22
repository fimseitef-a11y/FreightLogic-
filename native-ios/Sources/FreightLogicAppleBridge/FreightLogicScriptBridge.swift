import Foundation
import FreightLogicNativeCore

public protocol FreightLogicBridgeRouting: AnyObject {
    @MainActor
    func handle(_ request: BridgeRequest) async -> BridgeResponse
}

#if canImport(WebKit)
import WebKit

@MainActor
public final class FreightLogicScriptBridge: NSObject, WKScriptMessageHandlerWithReply {
    public static let handlerName = "freightLogicNative"

    private let allowlist: OriginAllowlist
    private weak var router: (any FreightLogicBridgeRouting)?
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    public init(allowlist: OriginAllowlist, router: any FreightLogicBridgeRouting) {
        self.allowlist = allowlist
        self.router = router
    }

    public func install(on controller: WKUserContentController) {
        controller.addScriptMessageHandler(self, contentWorld: .page, name: Self.handlerName)
    }

    public func uninstall(from controller: WKUserContentController) {
        controller.removeScriptMessageHandler(forName: Self.handlerName, contentWorld: .page)
    }

    public func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage,
        replyHandler: @escaping (Any?, String?) -> Void
    ) {
        guard message.frameInfo.isMainFrame else {
            replyHandler(Self.replyObject(BridgeResponse(requestID: "", ok: false, errorCode: .deniedFrame, errorMessage: "Main frame required")), nil)
            return
        }

        let securityOrigin = message.frameInfo.securityOrigin
        guard let origin = WebOrigin(
            scheme: securityOrigin.`protocol`,
            host: securityOrigin.host,
            port: securityOrigin.port
        ), allowlist.allows(origin) else {
            replyHandler(Self.replyObject(BridgeResponse(requestID: "", ok: false, errorCode: .deniedOrigin, errorMessage: "Origin not allowed")), nil)
            return
        }

        guard JSONSerialization.isValidJSONObject(message.body),
              let data = try? JSONSerialization.data(withJSONObject: message.body),
              let request = try? decoder.decode(BridgeRequest.self, from: data) else {
            replyHandler(Self.replyObject(BridgeResponse(requestID: "", ok: false, errorCode: .invalidEnvelope, errorMessage: "Invalid bridge envelope")), nil)
            return
        }

        if let validationError = request.validate(using: encoder) {
            let code: BridgeErrorCode
            switch validationError {
            case .unsupportedVersion:
                code = .unsupportedVersion
            case .forbiddenCredentialKey:
                code = .forbiddenCredential
            case .invalidRequestID, .payloadTooLarge, .payloadTooDeep:
                code = .invalidPayload
            }
            replyHandler(Self.replyObject(BridgeResponse(requestID: request.requestID, ok: false, errorCode: code, errorMessage: validationError.rawValue)), nil)
            return
        }

        guard let router else {
            replyHandler(Self.replyObject(BridgeResponse(requestID: request.requestID, ok: false, errorCode: .notReady, errorMessage: "Native router unavailable")), nil)
            return
        }

        Task { @MainActor in
            let response = await router.handle(request)
            replyHandler(Self.replyObject(response), nil)
        }
    }

    private static func replyObject(_ response: BridgeResponse) -> Any {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(response),
              let object = try? JSONSerialization.jsonObject(with: data) else {
            return ["version": BridgeRequest.currentVersion, "requestID": response.requestID, "ok": false, "errorCode": BridgeErrorCode.internalError.rawValue]
        }
        return object
    }
}
#else
public enum FreightLogicScriptBridgeAvailability {
    public static let isWebKitAvailable = false
}
#endif
