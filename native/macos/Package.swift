// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "WardenDesktop", platforms: [.macOS(.v13)], products: [
    .library(name: "WardenDesktop", targets: ["WardenDesktop"]),
    .executable(name: "warden-desktop", targets: ["WardenDesktopHost"]),
], targets: [
    .target(name: "WardenDesktop"),
    .executableTarget(name: "WardenDesktopHost", dependencies: ["WardenDesktop"]),
])
