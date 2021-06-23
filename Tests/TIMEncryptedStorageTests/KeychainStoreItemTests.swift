import XCTest
@testable import TIMEncryptedStorage

final class KeychainStoreItemTests: XCTestCase {
    let keychain = TIMKeychain()

    func testKeychainStoreItem() {
        let storeId: StorageID = "testStoreAndGet"
        var item = TIMKeychainStorageItem(id: storeId)
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

    func testStoreStatusMapping() {
        let result = keychain.mapStoreStatusToResult(noErr)
        assertResult(result, expectedDataType: Void.self, expectedError: nil)

        let result2 = keychain.mapStoreStatusToResult(errSecAuthFailed)
        assertResult(result2, expectedDataType: nil, expectedError: .authenticationFailedForData)

        let result3 = keychain.mapStoreStatusToResult(errSecDeviceFailed)
        assertResult(result3, expectedDataType: nil, expectedError: .failedToStoreData(Int(errSecDeviceFailed)))
    }

    func testLoadStatusMapping() {
        let result = keychain.mapLoadStatusToResult(noErr, data: Data() as AnyObject)
        assertResult(result, expectedDataType: Data.self, expectedError: nil)

        let result2 = keychain.mapLoadStatusToResult(errSecAuthFailed, data: nil)
        assertResult(result2, expectedDataType: nil, expectedError: .authenticationFailedForData)

        let result3 = keychain.mapLoadStatusToResult(errSecDeviceFailed, data: nil)
        assertResult(result3, expectedDataType: nil, expectedError: .failedToLoadData(Int(errSecDeviceFailed)))
    }

    private func assertResult<T>(_ result: Result<T, TIMSecureStorageError>, expectedDataType: T.Type?, expectedError: TIMSecureStorageError?) {
        switch result {
        case .success(let dataType):
            XCTAssertTrue(type(of: dataType) == expectedDataType)
            XCTAssertNil(expectedError)
        case .failure(let error):
            XCTAssertEqual(expectedError, error)
            XCTAssertNil(expectedDataType)
        }
    }

    // `TIMKeychain` cannot be tested due to missing entitlements, when running tests 🤯
}


