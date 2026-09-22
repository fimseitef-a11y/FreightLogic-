import XCTest
@testable import FreightLogicNativeHost

final class FreightLogicHostConfigurationTests: XCTestCase {
    func testProductionStyleHTTPSOriginIsAccepted() throws {
        let configuration = try FreightLogicHostConfiguration(
            appURL: XCTUnwrap(URL(string: "https://freightlogic-v2.fimseitef.workers.dev/"))
        )
        XCTAssertTrue(configuration.allowsMainFrameNavigation(
            to: URL(string: "https://freightlogic-v2.fimseitef.workers.dev/#loads")
        ))
    }

    func testCrossOriginMainFrameNavigationIsRejected() throws {
        let configuration = try FreightLogicHostConfiguration(
            appURL: XCTUnwrap(URL(string: "https://freightlogic-v2.fimseitef.workers.dev/"))
        )
        XCTAssertFalse(configuration.allowsMainFrameNavigation(
            to: URL(string: "https://example.com/")
        ))
    }

    func testHttpHostIsRejected() throws {
        XCTAssertThrowsError(
            try FreightLogicHostConfiguration(
                appURL: XCTUnwrap(URL(string: "http://freightlogic-v2.fimseitef.workers.dev/"))
            )
        ) { error in
            XCTAssertEqual(error as? FreightLogicHostConfigurationError, .httpsRequired)
        }
    }

    func testEmbeddedCredentialsAreRejected() throws {
        XCTAssertThrowsError(
            try FreightLogicHostConfiguration(
                appURL: XCTUnwrap(URL(string: "https://user:secret@freightlogic-v2.fimseitef.workers.dev/"))
            )
        ) { error in
            XCTAssertEqual(error as? FreightLogicHostConfigurationError, .embeddedCredentialsForbidden)
        }
    }

    func testDifferentExplicitPortIsRejected() throws {
        let configuration = try FreightLogicHostConfiguration(
            appURL: XCTUnwrap(URL(string: "https://freightlogic-v2.fimseitef.workers.dev/"))
        )
        XCTAssertFalse(configuration.allowsMainFrameNavigation(
            to: URL(string: "https://freightlogic-v2.fimseitef.workers.dev:8443/")
        ))
    }
}
