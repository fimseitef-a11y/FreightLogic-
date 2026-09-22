import Foundation
import FreightLogicNativeCore

public protocol NativeCapabilityRouting: AnyObject {
    @MainActor
    func handle(_ request: NativeCapabilityRequest) async -> BridgeResponse
}

#if canImport(WebKit)
import WebKit

@MainActor
public final class FreightLogicNativeCapabilityBridge: NSObject, WKScriptMessageHandlerWithReply {
    public static let handlerName = "freightLogicNativeCapability"

    private let allowlist: OriginAllowlist
    private weak var router: (any NativeCapabilityRouting)?
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    public init(allowlist: OriginAllowlist, router: any NativeCapabilityRouting) {
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
        replyHandler: @escaping @MainActor @Sendable (Any?, String?) -> Void
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
              let request = try? decoder.decode(NativeCapabilityRequest.self, from: data) else {
            replyHandler(Self.replyObject(BridgeResponse(requestID: "", ok: false, errorCode: .invalidEnvelope, errorMessage: "Invalid native-capability envelope")), nil)
            return
        }

        if let validationError = request.validate(using: encoder) {
            replyHandler(
                Self.replyObject(
                    BridgeResponse(
                        requestID: request.requestID,
                        ok: false,
                        errorCode: Self.errorCode(for: validationError),
                        errorMessage: validationError.rawValue
                    )
                ),
                nil
            )
            return
        }

        guard let router else {
            replyHandler(Self.replyObject(BridgeResponse(requestID: request.requestID, ok: false, errorCode: .notReady, errorMessage: "Native capability router unavailable")), nil)
            return
        }

        Task { @MainActor in
            let response = await router.handle(request)
            replyHandler(Self.replyObject(response), nil)
        }
    }

    private static func errorCode(for validationError: BridgeValidationError) -> BridgeErrorCode {
        switch validationError {
        case .unsupportedVersion:
            return .unsupportedVersion
        case .forbiddenCredentialKey:
            return .forbiddenCredential
        case .invalidRequestID, .payloadTooLarge, .payloadTooDeep:
            return .invalidPayload
        }
    }

    private static func replyObject(_ response: BridgeResponse) -> Any {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(response),
              let object = try? JSONSerialization.jsonObject(with: data) else {
            return [
                "version": BridgeContractVersion.current,
                "requestID": response.requestID,
                "ok": false,
                "errorCode": BridgeErrorCode.internalError.rawValue
            ]
        }
        return object
    }
}

@MainActor
public final class FreightLogicWebActionDispatcher {
    public static let pageBridgeObject = "FreightLogicNativeActions"

    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init() {}

    public func dispatch(
        _ request: FreightLogicActionRequest,
        in webView: WKWebView
    ) async -> BridgeResponse {
        if let validationError = request.validate(using: encoder) {
            return BridgeResponse(
                requestID: request.requestID,
                ok: false,
                errorCode: Self.errorCode(for: validationError),
                errorMessage: validationError.rawValue
            )
        }

        guard let data = try? encoder.encode(request),
              let requestObject = try? JSONSerialization.jsonObject(with: data) else {
            return BridgeResponse(
                requestID: request.requestID,
                ok: false,
                errorCode: .invalidEnvelope,
                errorMessage: "Unable to encode FreightLogic action request"
            )
        }

        do {
            let result = try await webView.callAsyncJavaScript(
                """
                const bridge = window.FreightLogicNativeActions;
                if (!bridge || typeof bridge.handle !== 'function') {
                  return {
                    version: 1,
                    requestID: request.requestID,
                    ok: false,
                    errorCode: 'notReady',
                    errorMessage: 'FreightLogic native action handler unavailable'
                  };
                }
                return await bridge.handle(request);
                """,
                arguments: ["request": requestObject],
                in: nil,
                contentWorld: .page
            )

            guard JSONSerialization.isValidJSONObject(result as Any),
                  let responseData = try? JSONSerialization.data(withJSONObject: result as Any),
                  let response = try? decoder.decode(BridgeResponse.self, from: responseData) else {
                return BridgeResponse(
                    requestID: request.requestID,
                    ok: false,
                    errorCode: .invalidEnvelope,
                    errorMessage: "Invalid response from FreightLogic web action handler"
                )
            }
            return response
        } catch {
            return BridgeResponse(
                requestID: request.requestID,
                ok: false,
                errorCode: .notReady,
                errorMessage: "FreightLogic web action handler unavailable"
            )
        }
    }

    private static func errorCode(for validationError: BridgeValidationError) -> BridgeErrorCode {
        switch validationError {
        case .unsupportedVersion:
            return .unsupportedVersion
        case .forbiddenCredentialKey:
            return .forbiddenCredential
        case .invalidRequestID, .payloadTooLarge, .payloadTooDeep:
            return .invalidPayload
        }
    }
}
#else
public enum FreightLogicAppleBridgeAvailability {
    public static let isWebKitAvailable = false
}
#endif
