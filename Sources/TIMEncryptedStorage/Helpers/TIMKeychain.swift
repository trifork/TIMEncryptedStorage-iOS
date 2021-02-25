import Foundation

/// Represents a item in the keychain with a given ID
public struct TIMKeychainStoreItem {

    let id: String

    private (set) var parameters: [String: Any]

    /// Constructor
    /// - Parameter id: Identifier for the object in the keychain
    public init(id: String) {
        self.id = id
        self.parameters = [kSecAttrAccount as String: id,
                           kSecClass as String: kSecClassGenericPassword]
    }

    mutating func addParameter(key: String, value: Any) {
        parameters.updateValue(value, forKey: key)
    }

    mutating func enableUseAuthenticationUI(_ authenticationUI: CFString) {
        addParameter(key: kSecUseAuthenticationUI as String, value: authenticationUI)
    }

    mutating func enableSafeAccessControl(_ safeAccessControl: SecAccessControl) {
        addParameter(key: kSecAttrAccessControl as String, value: safeAccessControl)
    }
}



/// Keychain wrapper for Trifork Identity Manager.
///
/// This wrapper is mainly for use internally in the TIMEncryptedStorage packages,
/// but it might come in handy in rare cases.
public final class TIMKeychain {


    /// Removes KeychainStoreItem from the keychain.
    /// - Parameter item: The item to remove.
    public static func remove(item: TIMKeychainStoreItem) {
        SecItemDelete(item.parameters as CFDictionary)
    }


    /// Saves data for an KeychainStoreItem in the keychain.
    /// - Parameters:
    ///   - data: Data to save.
    ///   - item: The item to identify the data.
    /// - Returns: Result indicating whether it was a success or not.
    public static func store(data: Data, item: TIMKeychainStoreItem) -> Result<Void, TIMKeychainError> {
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
    public static func storeBiometricProtected(data: Data, item: TIMKeychainStoreItem) -> Result<Void, TIMKeychainError> {
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
    public static func get(item: TIMKeychainStoreItem) -> Result<Data, TIMKeychainError> {
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
    public static func getBiometricProtected(item: TIMKeychainStoreItem) -> Result<Data, TIMKeychainError> {
        var mutableItem = item
        mutableItem.enableUseAuthenticationUI(kSecUseAuthenticationUIAllow)
        return get(item: mutableItem)
    }


    /// Checks whether an item exists in the keychain or not.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: `true` if the item exists, otherwise `false`
    public static func hasValue(item: TIMKeychainStoreItem) -> Bool {
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
    public static func hasBiometricProtectedValue(item: TIMKeychainStoreItem) -> Bool {
        var mutableItem = item
        mutableItem.enableUseAuthenticationUI(kSecUseAuthenticationUIFail)
        return hasValue(item: mutableItem)
    }

    static func mapStoreStatusToResult(_ status: OSStatus) -> Result<Void, TIMKeychainError> {
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

    static func mapLoadStatusToResult(_ status: OSStatus, data: AnyObject?) -> Result<Data, TIMKeychainError> {
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
