import Foundation

public enum BridgeContractVersion {
    public static let current = 1
}

public enum FreightLogicAction: String, Codable, CaseIterable, Sendable {
    case evaluateLoad
    case addTrip
    case addExpense
    case addFuel
    case markPaid
    case accountsReceivable
    case trueRPM
    case bestMove
    case startTrip
    case pickup
    case delivered

    public var mutatesFreightLogicState: Bool {
        switch self {
        case .addTrip, .addExpense, .addFuel, .markPaid, .startTrip, .pickup, .delivered:
            return true
        case .evaluateLoad, .accountsReceivable, .trueRPM, .bestMove:
            return false
        }
    }
}

public enum NativeCapabilityAction: String, Codable, CaseIterable, Sendable {
    case capabilities
}

public indirect enum BridgeValue: Equatable, Sendable, Codable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: BridgeValue])
    case array([BridgeValue])
    case null

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null; return }
        if let value = try? container.decode(Bool.self) { self = .bool(value); return }
        if let value = try? container.decode(Double.self) { self = .number(value); return }
        if let value = try? container.decode(String.self) { self = .string(value); return }
        if let value = try? container.decode([String: BridgeValue].self) { self = .object(value); return }
        if let value = try? container.decode([BridgeValue].self) { self = .array(value); return }
        throw DecodingError.typeMismatch(
            BridgeValue.self,
            .init(codingPath: decoder.codingPath, debugDescription: "Unsupported JSON bridge value")
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

public enum BridgeValidationError: String, Error, Equatable, Sendable {
    case unsupportedVersion
    case invalidRequestID
    case payloadTooLarge
    case payloadTooDeep
    case forbiddenCredentialKey
}

private enum BridgePayloadPolicy {
    static let maximumEncodedBytes = 65_536
    static let maximumPayloadDepth = 8

    private static let forbiddenNormalizedKeys: Set<String> = [
        "token", "admintoken", "drivertoken", "bearertoken", "authorizationheader",
        "credential", "password", "passphrase", "applockpin", "adminpin",
        "secret", "apikey"
    ]

    static func validate<T: Encodable>(
        version: Int,
        requestID: String,
        payload: [String: BridgeValue],
        envelope: T,
        using encoder: JSONEncoder
    ) -> BridgeValidationError? {
        guard version == BridgeContractVersion.current else { return .unsupportedVersion }
        guard !requestID.isEmpty, requestID.count <= 128 else { return .invalidRequestID }
        guard depth(of: .object(payload)) <= maximumPayloadDepth else { return .payloadTooDeep }
        guard !containsForbiddenCredentialKey(in: .object(payload)) else { return .forbiddenCredentialKey }
        guard let size = try? encoder.encode(envelope).count, size <= maximumEncodedBytes else { return .payloadTooLarge }
        return nil
    }

    private static func normalizeKey(_ key: String) -> String {
        key.lowercased().filter { $0.isLetter || $0.isNumber }
    }

    private static func containsForbiddenCredentialKey(in value: BridgeValue) -> Bool {
        switch value {
        case .object(let object):
            for (key, nested) in object {
                if forbiddenNormalizedKeys.contains(normalizeKey(key)) { return true }
                if containsForbiddenCredentialKey(in: nested) { return true }
            }
            return false
        case .array(let values):
            return values.contains(where: containsForbiddenCredentialKey)
        case .string, .number, .bool, .null:
            return false
        }
    }

    private static func depth(of value: BridgeValue) -> Int {
        switch value {
        case .object(let object):
            return 1 + (object.values.map(depth).max() ?? 0)
        case .array(let values):
            return 1 + (values.map(depth).max() ?? 0)
        case .string, .number, .bool, .null:
            return 1
        }
    }
}

public struct FreightLogicActionRequest: Codable, Equatable, Sendable {
    public static let maximumEncodedBytes = BridgePayloadPolicy.maximumEncodedBytes
    public static let maximumPayloadDepth = BridgePayloadPolicy.maximumPayloadDepth

    public let version: Int
    public let requestID: String
    public let action: FreightLogicAction
    public let payload: [String: BridgeValue]

    public init(
        version: Int = BridgeContractVersion.current,
        requestID: String,
        action: FreightLogicAction,
        payload: [String: BridgeValue] = [:]
    ) {
        self.version = version
        self.requestID = requestID
        self.action = action
        self.payload = payload
    }

    public func validate(using encoder: JSONEncoder = JSONEncoder()) -> BridgeValidationError? {
        BridgePayloadPolicy.validate(
            version: version,
            requestID: requestID,
            payload: payload,
            envelope: self,
            using: encoder
        )
    }
}

public struct NativeCapabilityRequest: Codable, Equatable, Sendable {
    public let version: Int
    public let requestID: String
    public let action: NativeCapabilityAction
    public let payload: [String: BridgeValue]

    public init(
        version: Int = BridgeContractVersion.current,
        requestID: String,
        action: NativeCapabilityAction,
        payload: [String: BridgeValue] = [:]
    ) {
        self.version = version
        self.requestID = requestID
        self.action = action
        self.payload = payload
    }

    public func validate(using encoder: JSONEncoder = JSONEncoder()) -> BridgeValidationError? {
        BridgePayloadPolicy.validate(
            version: version,
            requestID: requestID,
            payload: payload,
            envelope: self,
            using: encoder
        )
    }
}

public enum BridgeErrorCode: String, Codable, Sendable {
    case invalidEnvelope
    case unsupportedVersion
    case invalidPayload
    case forbiddenCredential
    case deniedOrigin
    case deniedFrame
    case notReady
    case internalError
}

public struct BridgeResponse: Codable, Equatable, Sendable {
    public let version: Int
    public let requestID: String
    public let ok: Bool
    public let result: BridgeValue?
    public let errorCode: BridgeErrorCode?
    public let errorMessage: String?

    public init(
        version: Int = BridgeContractVersion.current,
        requestID: String,
        ok: Bool,
        result: BridgeValue? = nil,
        errorCode: BridgeErrorCode? = nil,
        errorMessage: String? = nil
    ) {
        self.version = version
        self.requestID = requestID
        self.ok = ok
        self.result = result
        self.errorCode = errorCode
        self.errorMessage = errorMessage
    }
}

public struct WebOrigin: Hashable, Sendable {
    public let scheme: String
    public let host: String
    public let port: Int

    public init?(scheme: String, host: String, port: Int) {
        let normalizedScheme = scheme.lowercased()
        let normalizedHost = host.lowercased()
        guard normalizedScheme == "https" || normalizedScheme == "http" else { return nil }
        guard !normalizedHost.isEmpty else { return nil }
        let normalizedPort: Int
        if port > 0 {
            normalizedPort = port
        } else {
            normalizedPort = normalizedScheme == "https" ? 443 : 80
        }
        self.scheme = normalizedScheme
        self.host = normalizedHost
        self.port = normalizedPort
    }
}

public struct OriginAllowlist: Sendable {
    private let origins: Set<WebOrigin>

    public init(origins: Set<WebOrigin>) {
        self.origins = origins
    }

    public func allows(_ origin: WebOrigin) -> Bool {
        origins.contains(origin)
    }
}
