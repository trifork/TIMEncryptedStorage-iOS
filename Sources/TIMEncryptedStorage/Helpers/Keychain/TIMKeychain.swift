import Foundation

public protocol TIMSecureStore {
    associatedtype SecureStoreItem: TIMSecureStoreItem

    func remove(item: SecureStoreItem)
    func store(data: Data, item: SecureStoreItem) -> Result<Void, TIMKeychainError>
    func storeBiometricProtected(data: Data, item: SecureStoreItem) -> Result<Void, TIMKeychainError>
    func get(item: SecureStoreItem) -> Result<Data, TIMKeychainError>
    func getBiometricProtected(item: SecureStoreItem) -> Result<Data, TIMKeychainError>
    func hasValue(item: SecureStoreItem) -> Bool
    func hasBiometricProtectedValue(item: SecureStoreItem) -> Bool
}

/// Keychain wrapper for Trifork Identity Manager.
///
/// This wrapper is mainly for use internally in the TIMEncryptedStorage packages,
/// but it might come in handy in rare cases.
public final class TIMKeychain : TIMSecureStore {

    public init() {

    }

    /// Removes KeychainStoreItem from the keychain.
    /// - Parameter item: The item to remove.
    public func remove(item: TIMKeychainStoreItem) {
        SecItemDelete(item.parameters as CFDictionary)
    }


    /// Saves data for an KeychainStoreItem in the keychain.
    /// - Parameters:
    ///   - data: Data to save.
    ///   - item: The item to identify the data.
    /// - Returns: Result indicating whether it was a success or not.
    public func store(data: Data, item: TIMKeychainStoreItem) -> Result<Void, TIMKeychainError> {
        remove(item: item) //Remove before adding to avoid override errors
        var mutableParameters = item.parameters
        mutableParameters.updateValue(data, forKey: kSecValueData as String)
        let status = SecItemAdd(mutableParameters as CFDictionary, nil)
        return mapStoreStatusToResult(status)
    }


    /// Saves data in the keychain with biometric protection (meaning that only TouchID or FaceID can unlock the access to the data)
    /// - Parameters:
    ///   - data: Data to save.
    ///   - item: The item to identify the data.
    /// - Returns: Result indicating whether it was a success or not.
    public func storeBiometricProtected(data: Data, item: TIMKeychainStoreItem) -> Result<Void, TIMKeychainError> {
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

        let result: Result<Void, TIMKeychainError>
        if let safeAccessControl = sacObject {
            var mutableItem = item
            mutableItem.enableUseAuthenticationUI(kSecUseAuthenticationUIAllow)
            mutableItem.enableSafeAccessControl(safeAccessControl)
            result = store(data: data, item: mutableItem)
        } else {
            result = .failure(.failedToStoreData)
        }
        return result
    }


    /// Gets data from the keychain.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: If there is data for the specified item, it will return the Data object, otherwise a failing result with a matching error
    public func get(item: TIMKeychainStoreItem) -> Result<Data, TIMKeychainError> {
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


    /// Gets biometric protected data from the keychain - this will prompt the user for biometric verification.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: If there is data for the specified item, it will return the Data object, otherwise `nil`
    public func getBiometricProtected(item: TIMKeychainStoreItem) -> Result<Data, TIMKeychainError> {
        var mutableItem = item
        mutableItem.enableUseAuthenticationUI(kSecUseAuthenticationUIAllow)
        return get(item: mutableItem)
    }


    /// Checks whether an item exists in the keychain or not.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: `true` if the item exists, otherwise `false`
    public func hasValue(item: TIMKeychainStoreItem) -> Bool {
        var result: AnyObject?
        // Search
        let status = withUnsafeMutablePointer(to: &result) { pointer in
            SecItemCopyMatching(item.parameters as CFDictionary, UnsafeMutablePointer(pointer))
        }
        return status == noErr || status == errSecInteractionNotAllowed // it should either ok or unaccessible to us.
    }


    /// Checks whether an item exists with biometric protection in the keychain or not.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: `true` if the item exists, otherwise `false`
    public func hasBiometricProtectedValue(item: TIMKeychainStoreItem) -> Bool {
        var mutableItem = item
        mutableItem.enableUseAuthenticationUI(kSecUseAuthenticationUIFail)
        return hasValue(item: mutableItem)
    }

    func mapStoreStatusToResult(_ status: OSStatus) -> Result<Void, TIMKeychainError> {
        let result: Result<Void, TIMKeychainError>
        switch status {
        case errSecAuthFailed:
            result = .failure(.authenticationFailedForData)
        case noErr:
            result = .success(Void())
        default:
            result = .failure(.failedToStoreData)
        }
        return result
    }

    func mapLoadStatusToResult(_ status: OSStatus, data: AnyObject?) -> Result<Data, TIMKeychainError> {
        let result: Result<Data, TIMKeychainError>
        switch status {
        case errSecAuthFailed, errSecUserCanceled:
            result = Result.failure(.authenticationFailedForData)
        case noErr:
            if let optData = (data as? Data) {
                result = .success(optData)
            } else {
                result = .failure(.failedToLoadData)
            }
        default:
            result = .failure(.failedToLoadData)
        }
        return result
    }
}
