import Foundation

public enum BridgeAction: String, Codable, CaseIterable, Sendable {
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
    case unknownEnvelopeField
    case invalidJSONValue
}

public struct BridgeRequest: Codable, Equatable, Sendable {
    public static let currentVersion = 1
    public static let maximumEncodedBytes = 65_536
    public static let maximumPayloadDepth = 8

    public let version: Int
    public let requestID: String
    public let action: BridgeAction
    public let payload: [String: BridgeValue]

    public init(
        version: Int = BridgeRequest.currentVersion,
        requestID: String,
        action: BridgeAction,
        payload: [String: BridgeValue] = [:]
    ) {
        self.version = version
        self.requestID = requestID
        self.action = action
        self.payload = payload
    }

    /// Inspect the original body before serialization or Codable field removal.
    public static func validateIncomingJSONObject(_ body: Any) -> BridgeValidationError? {
        guard let envelope = body as? [String: Any],
              Set(envelope.keys) == Set(["version", "requestID", "action", "payload"]) else {
            return .unknownEnvelopeField
        }
        var nodes = 0
        var estimatedBytes = 0
        func add(_ bytes: Int) -> Bool {
            guard bytes <= maximumEncodedBytes - estimatedBytes else { return false }
            estimatedBytes += bytes
            return true
        }
        func stringBytes(_ text: String) -> Int {
            var bytes = 2
            for byte in text.utf8 {
                bytes += byte < 32 ? 6 : (byte == 34 || byte == 92 || byte == 47 ? 2 : 1)
                if bytes > maximumEncodedBytes { break }
            }
            return bytes
        }
        func inspect(_ value: Any, depth: Int) -> BridgeValidationError? {
            nodes += 1
            guard nodes <= 4096 else { return .payloadTooLarge }
            guard depth <= maximumPayloadDepth + 1 else { return .payloadTooDeep }
            if let dictionary = value as? [String: Any] {
                guard add(2 + dictionary.count) else { return .payloadTooLarge }
                for (key, nested) in dictionary {
                    guard add(stringBytes(key) + 1) else { return .payloadTooLarge }
                    if let error = inspect(nested, depth: depth + 1) { return error }
                }
            } else if let array = value as? [Any] {
                guard add(2 + array.count) else { return .payloadTooLarge }
                for nested in array {
                    if let error = inspect(nested, depth: depth + 1) { return error }
                }
            } else if let text = value as? String {
                guard add(stringBytes(text)) else { return .payloadTooLarge }
            } else if value is NSNull {
                guard add(4) else { return .payloadTooLarge }
            } else if let number = value as? NSNumber {
                guard number.doubleValue.isFinite else { return .invalidJSONValue }
                guard add(64) else { return .payloadTooLarge }
            } else {
                return .invalidJSONValue
            }
            return nil
        }
        return inspect(envelope, depth: 1)
    }

    public func validate(using encoder: JSONEncoder = JSONEncoder()) -> BridgeValidationError? {
        guard version == Self.currentVersion else { return .unsupportedVersion }
        guard !requestID.isEmpty, requestID.count <= 128 else { return .invalidRequestID }
        guard Self.depth(of: .object(payload)) <= Self.maximumPayloadDepth else { return .payloadTooDeep }
        guard !Self.containsForbiddenCredentialKey(in: .object(payload)) else { return .forbiddenCredentialKey }
        guard let size = try? encoder.encode(self).count, size <= Self.maximumEncodedBytes else { return .payloadTooLarge }
        return nil
    }

    private static let forbiddenNormalizedKeys: Set<String> = [
        "token", "admintoken", "drivertoken", "bearertoken", "authorizationheader",
        "credential", "password", "passphrase", "applockpin", "adminpin",
        "secret", "apikey"
    ]

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
        version: Int = BridgeRequest.currentVersion,
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
