import Foundation

public enum NativeSurface: String, Codable, CaseIterable, Sendable {
    case appIntent
    case shortcut
    case actionButton
    case spotlight
    case liveActivity
    case notification
    case imageIntake
}

public enum NativeExecutionPolicy: String, Codable, Sendable {
    /// Execute only after the native host has foregrounded the canonical FreightLogic web/core.
    case foregroundCanonicalHost

    /// Reserved for a future read-only snapshot that is proven to share canonical FreightLogic state.
    /// No v1 action uses this execution policy yet.
    case canonicalReadOnlySnapshot
}

public enum NativeConfirmationPolicy: String, Codable, Sendable {
    case canonicalUIRequired
    case noAdditionalNativeConfirmation
}

public struct NativeActionPolicy: Equatable, Sendable {
    public let action: BridgeAction
    public let execution: NativeExecutionPolicy
    public let confirmation: NativeConfirmationPolicy
    public let futureBackgroundEligible: Bool
    public let suggestedSurfaces: Set<NativeSurface>

    public init(
        action: BridgeAction,
        execution: NativeExecutionPolicy,
        confirmation: NativeConfirmationPolicy,
        futureBackgroundEligible: Bool,
        suggestedSurfaces: Set<NativeSurface>
    ) {
        self.action = action
        self.execution = execution
        self.confirmation = confirmation
        self.futureBackgroundEligible = futureBackgroundEligible
        self.suggestedSurfaces = suggestedSurfaces
    }
}

public enum FreightLogicNativePolicy {
    /// Version 1 deliberately routes every action through the foreground canonical host.
    /// This prevents a Siri/Shortcut/native surface from becoming a second persistence or
    /// freight-economics engine before a shared, audited native state contract exists.
    public static let v1: [BridgeAction: NativeActionPolicy] = {
        Dictionary(uniqueKeysWithValues: BridgeAction.allCases.map { action in
            let isMutation = action.mutatesFreightLogicState
            let futureBackgroundEligible: Bool
            switch action {
            case .accountsReceivable, .trueRPM, .bestMove:
                futureBackgroundEligible = true
            case .evaluateLoad, .addTrip, .addExpense, .addFuel, .markPaid, .startTrip, .pickup, .delivered:
                futureBackgroundEligible = false
            }

            var surfaces: Set<NativeSurface> = [.appIntent, .shortcut]
            switch action {
            case .evaluateLoad:
                surfaces.formUnion([.actionButton, .imageIntake])
            case .addExpense, .addFuel:
                surfaces.insert(.actionButton)
            case .startTrip, .pickup, .delivered:
                surfaces.formUnion([.actionButton, .liveActivity, .notification])
            case .accountsReceivable, .trueRPM, .bestMove:
                surfaces.insert(.spotlight)
            case .addTrip, .markPaid:
                break
            }

            return (
                action,
                NativeActionPolicy(
                    action: action,
                    execution: .foregroundCanonicalHost,
                    confirmation: isMutation ? .canonicalUIRequired : .noAdditionalNativeConfirmation,
                    futureBackgroundEligible: futureBackgroundEligible,
                    suggestedSurfaces: surfaces
                )
            )
        })
    }()

    public static func policy(for action: BridgeAction) -> NativeActionPolicy {
        // The dictionary is generated from BridgeAction.allCases, so a missing value is a
        // programming defect rather than a runtime condition. Keep the fallback maximally safe.
        v1[action] ?? NativeActionPolicy(
            action: action,
            execution: .foregroundCanonicalHost,
            confirmation: .canonicalUIRequired,
            futureBackgroundEligible: false,
            suggestedSurfaces: []
        )
    }
}
