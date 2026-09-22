import Foundation

public enum BridgeTransportFailure: String, Error, Codable, Sendable {
    case malformedMessage
    case unsupportedVersion
    case invalidPayload
    case forbiddenCredential
    case deniedOrigin
    case deniedFrame
    case notReady
    case routerFailure
}

public struct BridgeTransportPolicy: Sendable {
    public let allowedOrigin: OriginAllowlist

    public init(allowedOrigin: OriginAllowlist) {
        self.allowedOrigin = allowedOrigin
    }

    /// Transport policy is deliberately independent of freight economics and persistence.
    /// A host may reject a message before the canonical router is ever invoked.
    public func accepts(origin: WebOrigin, isMainFrame: Bool) -> Bool {
        isMainFrame && allowedOrigin.allows(origin)
    }

    public func failureResponse(
        requestID: String = "",
        code: BridgeErrorCode,
        message: String
    ) -> BridgeResponse {
        BridgeResponse(
            requestID: requestID,
            ok: false,
            errorCode: code,
            errorMessage: message
        )
    }
}
