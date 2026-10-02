import XCTest
@testable import FreightLogicAppleBridge

final class BridgeAvailabilityTests: XCTestCase {
    func testPackageBuildsOnNonWebKitHosts() async {
        #if canImport(WebKit)
        let name = await MainActor.run { FreightLogicScriptBridge.handlerName }
        XCTAssertEqual(name, "freightLogicNative")
        #else
        XCTAssertFalse(FreightLogicScriptBridgeAvailability.isWebKitAvailable)
        #endif
    }
}
