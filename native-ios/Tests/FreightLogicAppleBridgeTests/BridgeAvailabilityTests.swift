import XCTest
@testable import FreightLogicAppleBridge

final class BridgeAvailabilityTests: XCTestCase {
    func testPackageBuildsOnNonWebKitHosts() {
        #if canImport(WebKit)
        XCTAssertTrue(true)
        #else
        XCTAssertFalse(FreightLogicAppleBridgeAvailability.isWebKitAvailable)
        #endif
    }
}
