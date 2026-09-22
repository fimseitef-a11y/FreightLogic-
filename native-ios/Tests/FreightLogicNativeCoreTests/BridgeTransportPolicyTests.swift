import XCTest
@testable import FreightLogicNativeCore

final class BridgeTransportPolicyTests: XCTestCase {
    private let origin = OriginAllowlist(origins: [
        WebOrigin(scheme: "https", host: "freightlogic-v2.fimseitef.workers.dev", port: 443)!
    ])

    func testAllowedMainFrameOriginPasses() {
        let policy = BridgeTransportPolicy(allowedOrigin: origin)
        let requestOrigin = WebOrigin(scheme: "HTTPS", host: "FREIGHTLOGIC-V2.FIMSEITEF.WORKERS.DEV", port: 0)!
        XCTAssertTrue(policy.accepts(origin: requestOrigin, isMainFrame: true))
    }

    func testSubframeIsRejectedEvenWhenOriginMatches() {
        let policy = BridgeTransportPolicy(allowedOrigin: origin)
        let requestOrigin = WebOrigin(scheme: "https", host: "freightlogic-v2.fimseitef.workers.dev", port: 443)!
        XCTAssertFalse(policy.accepts(origin: requestOrigin, isMainFrame: false))
    }

    func testWrongOriginIsRejected() {
        let policy = BridgeTransportPolicy(allowedOrigin: origin)
        let requestOrigin = WebOrigin(scheme: "https", host: "evil.example", port: 443)!
        XCTAssertFalse(policy.accepts(origin: requestOrigin, isMainFrame: true))
    }

    func testFailureResponseIsNonSuccess() {
        let policy = BridgeTransportPolicy(allowedOrigin: origin)
        let response = policy.failureResponse(
            requestID: "r-1",
            code: .deniedOrigin,
            message: "Origin not allowed"
        )
        XCTAssertFalse(response.ok)
        XCTAssertEqual(response.requestID, "r-1")
        XCTAssertEqual(response.errorCode, .deniedOrigin)
    }
}
