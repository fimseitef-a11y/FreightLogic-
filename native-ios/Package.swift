// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FreightLogicNative",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "FreightLogicNativeCore", targets: ["FreightLogicNativeCore"]),
        .library(name: "FreightLogicAppleBridge", targets: ["FreightLogicAppleBridge"])
    ],
    targets: [
        .target(name: "FreightLogicNativeCore"),
        .target(
            name: "FreightLogicAppleBridge",
            dependencies: ["FreightLogicNativeCore"]
        ),
        .testTarget(
            name: "FreightLogicNativeCoreTests",
            dependencies: ["FreightLogicNativeCore"]
        ),
        .testTarget(
            name: "FreightLogicAppleBridgeTests",
            dependencies: ["FreightLogicAppleBridge", "FreightLogicNativeCore"]
        )
    ]
)
