import Foundation

/// Keychain wrapper for Trifork Identity Manager.
///
/// This wrapper is mainly for use internally in the TIMEncryptedStorage packages,
/// but it might come in handy as public in rare cases.
public final class TIMKeychain : TIMSecureStorage {

    public init() {

    }

    public func remove(item: TIMKeychainStorageItem) {
        SecItemDelete(item.parameters as CFDictionary)
    }

    public func store(data: Data, item: TIMKeychainStorageItem) -> Result<Void, TIMSecureStorageError> {
        remove(item: item) //Remove before adding to avoid override errors
        var mutableParameters = item.parameters
        mutableParameters.updateValue(data, forKey: kSecValueData as String)
        let status = SecItemAdd(mutableParameters as CFDictionary, nil)
        return mapStoreStatusToResult(status)
    }

    public func storeBiometricProtected(data: Data, item: TIMKeychainStorageItem) -> Result<Void, TIMSecureStorageError> {
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

        let result: Result<Void, TIMSecureStorageError>
        if let safeAccessControl = sacObject {
            var mutableItem = item
            mutableItem.enableUseAuthenticationUI(kSecUseAuthenticationUIAllow)
            mutableItem.enableSafeAccessControl(safeAccessControl)
            result = store(data: data, item: mutableItem)
        } else {
            result = .failure(.failedToStoreData("Failed to generate SecAccessControl object for data."))
        }
        return result
    }

    public func get(item: TIMKeychainStorageItem) -> Result<Data, TIMSecureStorageError> {
        var dataResult: AnyObject?
        var mutableParameters = item.parameters
        mutableParameters.updateValue(kSecMatchLimitOne, forKey: kSecMatchLimit as String)
        mutableParameters.updateValue(kCFBooleanTrue as Any, forKey: kSecReturnData as String)

        // Search
        let status = withUnsafeMutablePointer(to: &dataResult) {
            SecItemCopyMatching(mutableParameters as CFDictionary, UnsafeMutablePointer($0))
        }

        return mapLoadStatusToResult(status, data: dataResult)
    }

    public func getBiometricProtected(item: TIMKeychainStorageItem) -> Result<Data, TIMSecureStorageError> {
        var mutableItem = item
        mutableItem.enableUseAuthenticationUI(kSecUseAuthenticationUIAllow)
        return get(item: mutableItem)
    }

    public func hasValue(item: TIMKeychainStorageItem) -> Bool {
        var result: AnyObject?
        // Search
        let status = withUnsafeMutablePointer(to: &result) { pointer in
            SecItemCopyMatching(item.parameters as CFDictionary, UnsafeMutablePointer(pointer))
        }
        return status == noErr || status == errSecInteractionNotAllowed // it should either ok or unaccessible to us.
    }

    public func hasBiometricProtectedValue(item: TIMKeychainStorageItem) -> Bool {
        var mutableItem = item
        mutableItem.enableUseAuthenticationUI(kSecUseAuthenticationUIFail)
        return hasValue(item: mutableItem)
    }

    func mapStoreStatusToResult(_ status: OSStatus) -> Result<Void, TIMSecureStorageError> {
        let result: Result<Void, TIMSecureStorageError>
        switch status {
        case errSecAuthFailed:
            result = .failure(.authenticationFailedForData)
        case noErr:
            result = .success(Void())
        default:
            result = .failure(.failedToStoreData(status.errorDescription))
        }
        return result
    }

    func mapLoadStatusToResult(_ status: OSStatus, data: AnyObject?) -> Result<Data, TIMSecureStorageError> {
        let result: Result<Data, TIMSecureStorageError>
        switch status {
        // `errSecInteractionNotAllowed` can occur if the screen is locked while the biometric dialog is open.
        case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed:
            result = Result.failure(.authenticationFailedForData)
        case noErr:
            if let optData = (data as? Data) {
                result = .success(optData)
            } else {
                result = .failure(.failedToLoadData(status.errorDescription))
            }
        default:
            result = .failure(.failedToLoadData(status.errorDescription))
        }
        return result
    }
}
