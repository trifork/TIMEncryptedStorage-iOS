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

    static var config = TIMKeyServiceConfiguration(
        realmBaseUrl: "https://oidc-test.hosted.trifork.com/auth/realms/dev",
        version: .v1
    )

    private let keyService: TIMKeyService = TIMKeyService(configuration: config)

    override class func setUp() {
        super.setUp()
    }

    override class func tearDown() {
        #if canImport(Combine)
        if #available(iOS 13, *) {
            combineStore.removeAll()
        }
        #endif
        super.tearDown()
    }

    func testValidConfigurationSet() {
        XCTAssertTrue(keyService.verifyConfiguration(Self.config))
    }

    func testInvalidConfigureSet() {
        let config = TIMKeyServiceConfiguration(
            realmBaseUrl: "INVALID URL",
            version: .v1
        )
        XCTAssertFalse(keyService.verifyConfiguration(config))
    }

    func testKeyServiceUrl() {
        XCTAssertEqual(
            "https://oidc-test.hosted.trifork.com/auth/realms/dev/keyservice/v1/key",
            keyService.keyServiceUrl(endpoint: .key).absoluteString
        )
    }

    // Methods accessing the Apple Keychain cannot be tested due to missing entitlements, when running tests 🤯
}

