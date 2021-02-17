import XCTest
#if canImport(Combine)
import Combine
#endif
@testable import TIMEncryptedStorage

#if canImport(Combine)
@available(iOS 13, *)
private var combineStore: Set<AnyCancellable> = Set()
#endif

final class TIMKeyServiceTests: XCTestCase {
    private var createKeyModel: TIMKeyModel?

    override class func setUp() {
        super.setUp()
        let config = TIMKeyServiceConfiguration(
            realmBaseUrl: "https://oidc-test.hosted.trifork.com/auth/realms/dev",
            version: .v1
        )
        TIMKeyService.configure(config)
    }

    override class func tearDown() {
        #if canImport(Combine)
        if #available(iOS 13, *) {
            combineStore.removeAll()
        }
        #endif
        super.tearDown()
    }

    func testConfigurationNotSet() {
        XCTAssertFalse(TIMKeyService.verifyConfiguration(nil))
    }

    func testValidConfigurationSet() {
        let config = TIMKeyServiceConfiguration(
            realmBaseUrl: "https://oidc-test.hosted.trifork.com/auth/realms/my-realm",
            version: .v1
        )
        TIMKeyService.configure(config)
        XCTAssertTrue(TIMKeyService.verifyConfiguration(config))
    }

    func testInvalidConfigureSet() {
        let config = TIMKeyServiceConfiguration(
            realmBaseUrl: "INVALID URL",
            version: .v1
        )
        XCTAssertFalse(TIMKeyService.verifyConfiguration(config))
    }

    func testKeyServiceUrl() {
        let config = TIMKeyServiceConfiguration(
            realmBaseUrl: "https://oidc-test.hosted.trifork.com/auth/realms/my-realm",
            version: .v1
        )
        TIMKeyService.configure(config)
        XCTAssertEqual(
            "https://oidc-test.hosted.trifork.com/auth/realms/my-realm/keyservice/v1/key",
            TIMKeyService.keyServiceUrl(endpoint: .key).absoluteString
        )
    }

    // Keychain cannot be tested due to missing entitlements, when running tests 🤯
}

