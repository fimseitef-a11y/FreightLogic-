import XCTest
@testable import FreightLogicNativeCore

final class BridgeContractTests: XCTestCase {
    func testFreightActionAllowlistIsExact() {
        XCTAssertEqual(
            Set(FreightLogicAction.allCases.map(\.rawValue)),
            Set(["evaluateLoad", "addTrip", "addExpense", "addFuel", "markPaid", "accountsReceivable", "trueRPM", "bestMove", "startTrip", "pickup", "delivered"])
        )
    }

    func testNativeCapabilityAllowlistIsNarrow() {
        XCTAssertEqual(NativeCapabilityAction.allCases, [.capabilities])
    }

    func testMutationClassification() {
        XCTAssertFalse(FreightLogicAction.evaluateLoad.mutatesFreightLogicState)
        XCTAssertFalse(FreightLogicAction.trueRPM.mutatesFreightLogicState)
        XCTAssertTrue(FreightLogicAction.addTrip.mutatesFreightLogicState)
        XCTAssertTrue(FreightLogicAction.delivered.mutatesFreightLogicState)
    }

    func testRoundTripPreservesNestedPayload() throws {
        let request = FreightLogicActionRequest(
            requestID: "req-1",
            action: .evaluateLoad,
            payload: [
                "origin": .string("Fayetteville, NC"),
                "miles": .object(["loaded": .number(546), "deadhead": .null]),
                "pieces": .array([.number(1)])
            ]
        )
        let data = try JSONEncoder().encode(request)
        XCTAssertEqual(try JSONDecoder().decode(FreightLogicActionRequest.self, from: data), request)
        XCTAssertNil(request.validate())
    }

    func testUnknownDeadheadCanRemainNull() {
        let request = FreightLogicActionRequest(
            requestID: "req-unknown-dh",
            action: .evaluateLoad,
            payload: ["deadheadMiles": .null]
        )
        XCTAssertNil(request.validate())
    }

    func testCredentialKeysAreRejectedRecursively() {
        let request = FreightLogicActionRequest(
            requestID: "req-secret",
            action: .bestMove,
            payload: ["nested": .object(["app_lock_pin": .string("must-not-cross-bridge")])]
        )
        XCTAssertEqual(request.validate(), .forbiddenCredentialKey)
    }

    func testNativeCapabilityRequestAlsoRejectsCredentialKeys() {
        let request = NativeCapabilityRequest(
            requestID: "cap-secret",
            action: .capabilities,
            payload: ["adminToken": .string("must-not-cross-bridge")]
        )
        XCTAssertEqual(request.validate(), .forbiddenCredentialKey)
    }

    func testOrdinaryFreightPickupPinKeyIsNotMistakenForAppCredential() {
        let request = FreightLogicActionRequest(
            requestID: "req-pickup-pin",
            action: .evaluateLoad,
            payload: ["pickupPin": .string("4832")]
        )
        XCTAssertNil(request.validate())
    }

    func testCredentialWordsInsideOrdinaryValuesAreNotRejected() {
        let request = FreightLogicActionRequest(
            requestID: "req-note",
            action: .evaluateLoad,
            payload: ["notes": .string("Broker note mentions a token charge")]
        )
        XCTAssertNil(request.validate())
    }

    func testUnsupportedVersionFailsClosed() {
        let request = FreightLogicActionRequest(version: 99, requestID: "req-v99", action: .trueRPM)
        XCTAssertEqual(request.validate(), .unsupportedVersion)
    }

    func testPayloadDepthIsBounded() {
        var value: BridgeValue = .string("leaf")
        for _ in 0..<9 { value = .array([value]) }
        let request = FreightLogicActionRequest(requestID: "req-deep", action: .bestMove, payload: ["value": value])
        XCTAssertEqual(request.validate(), .payloadTooDeep)
    }

    func testPayloadSizeIsBounded() {
        let request = FreightLogicActionRequest(
            requestID: "req-large",
            action: .evaluateLoad,
            payload: ["blob": .string(String(repeating: "x", count: FreightLogicActionRequest.maximumEncodedBytes))]
        )
        XCTAssertEqual(request.validate(), .payloadTooLarge)
    }

    func testOriginAllowlistNormalizesSchemeHostAndDefaultPort() throws {
        let allowed = try XCTUnwrap(WebOrigin(scheme: "HTTPS", host: "FreightLogic-V2.Fimseitef.Workers.Dev", port: 0))
        let same = try XCTUnwrap(WebOrigin(scheme: "https", host: "freightlogic-v2.fimseitef.workers.dev", port: 443))
        let other = try XCTUnwrap(WebOrigin(scheme: "https", host: "example.com", port: 443))
        let policy = OriginAllowlist(origins: [allowed])
        XCTAssertTrue(policy.allows(same))
        XCTAssertFalse(policy.allows(other))
    }
}
