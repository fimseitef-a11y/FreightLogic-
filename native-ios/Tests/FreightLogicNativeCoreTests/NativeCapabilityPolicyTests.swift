import XCTest
@testable import FreightLogicNativeCore

final class NativeCapabilityPolicyTests: XCTestCase {
    func testEveryBridgeActionHasExactlyOnePolicy() {
        XCTAssertEqual(Set(FreightLogicNativePolicy.v1.keys), Set(BridgeAction.allCases))
        XCTAssertEqual(FreightLogicNativePolicy.v1.count, BridgeAction.allCases.count)
    }

    func testV1NeverRunsOutsideCanonicalForegroundHost() {
        for action in BridgeAction.allCases {
            XCTAssertEqual(
                FreightLogicNativePolicy.policy(for: action).execution,
                .foregroundCanonicalHost,
                "\(action.rawValue) must not become a second native authority"
            )
        }
    }

    func testEveryMutationRequiresCanonicalUIConfirmation() {
        for action in BridgeAction.allCases where action.mutatesFreightLogicState {
            XCTAssertEqual(
                FreightLogicNativePolicy.policy(for: action).confirmation,
                .canonicalUIRequired,
                "\(action.rawValue) changes FreightLogic state"
            )
        }
    }

    func testOnlyReadOnlySnapshotActionsAreFutureBackgroundCandidates() {
        let eligible = Set(
            BridgeAction.allCases.filter {
                FreightLogicNativePolicy.policy(for: $0).futureBackgroundEligible
            }
        )
        XCTAssertEqual(eligible, Set([.accountsReceivable, .trueRPM, .bestMove]))
    }

    func testEvaluateLoadStaysForegroundAndSupportsImageIntakeSurface() {
        let policy = FreightLogicNativePolicy.policy(for: .evaluateLoad)
        XCTAssertFalse(policy.futureBackgroundEligible)
        XCTAssertTrue(policy.suggestedSurfaces.contains(.imageIntake))
        XCTAssertTrue(policy.suggestedSurfaces.contains(.actionButton))
    }

    func testTripLifecycleCanDriveLiveActivityButStillUsesCanonicalHost() {
        for action in [BridgeAction.startTrip, .pickup, .delivered] {
            let policy = FreightLogicNativePolicy.policy(for: action)
            XCTAssertTrue(policy.suggestedSurfaces.contains(.liveActivity))
            XCTAssertEqual(policy.execution, .foregroundCanonicalHost)
            XCTAssertEqual(policy.confirmation, .canonicalUIRequired)
        }
    }
}
