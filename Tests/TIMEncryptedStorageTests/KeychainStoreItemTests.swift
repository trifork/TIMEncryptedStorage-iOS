import XCTest
@testable import TIMEncryptedStorage

final class KeychainStoreItemTests: XCTestCase {
    func testKeychainStoreItem() {
        let storeId: StoreID = "testStoreAndGet"
        var item = TIMKeychainStoreItem(id: storeId)
        XCTAssertEqual(storeId, item.parameters[kSecAttrAccount as String] as! String)
        XCTAssertEqual(kSecClassGenericPassword, item.parameters[kSecClass as String] as! CFString)
        XCTAssertEqual(2, item.parameters.count)

        item.enableUseAuthenticationUI(kSecUseAuthenticationUIAllow)
        XCTAssertEqual(kSecUseAuthenticationUIAllow, item.parameters[kSecUseAuthenticationUI as String] as! CFString)
        XCTAssertEqual(3, item.parameters.count)

        let biometricFlag: SecAccessControlCreateFlags
        if #available(iOS 11.3, *) {
            biometricFlag = .biometryAny
        } else {
            biometricFlag = .touchIDAny
        }
        let sacObject: SecAccessControl? = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            biometricFlag,
            nil
        )
        item.enableSafeAccessControl(sacObject!)
        XCTAssertNotNil(item.parameters[kSecAttrAccessControl as String])
        XCTAssertEqual(4, item.parameters.count)
    }

    // Keychain cannot be tested due to missing entitlements, when running tests 🤯
}

