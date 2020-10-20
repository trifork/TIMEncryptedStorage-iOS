import Foundation

#if canImport(Combine)
import Combine
#endif

/// StoreId typealias
public typealias StoreID = String


/// Trifork Identity Manager Encrypted Storage class.
///
/// The purpose of this classes is to store and load encrypted data based on a secret or biometric protection.
///
/// This class depends on the Trifork Identity Manager Key Service (`TIMKeyService`), which handles encryption keys.
public final class TIMEncryptedStorage {

    private init() { }


    /// Configures the key service. This has to be called before you call any other function in this class.
    /// - Parameter keyServiceConfiguration: The configuration
    public static func configure(keyServiceConfiguration: TIMKeyServiceConfiguration) {
        TIMKeyService.configure(keyServiceConfiguration)
    }


    /// Checks whether there is a stored value in the keychain or not.
    /// - Parameter id: The identifier for the stored item.
    /// - Returns: `true` if the item is present, otherwise `false`
    public static func hasValue(id: StoreID) -> Bool {
        TIMKeychain.hasValue(item: TIMKeychainStoreItem(id: id))
    }

    /// Checks whether there is a stored value in the keychain with biometric protection or not.
    /// - Parameters:
    ///   - id: The identifier for the stored item.
    ///   - keyId: The identifier for the key that was used when it was saved.
    /// - Returns: `true` if the item is present, otherwise `false`
    public static func hasBiometricProtectedValue(id: StoreID, keyId: String) -> Bool {
        let keychainKey = longSecretKeychainId(keyId: keyId)
        return TIMKeychain.hasBiometricProtectedValue(item: TIMKeychainStoreItem(id: keychainKey)) &&
            TIMKeychain.hasValue(item: TIMKeychainStoreItem(id: id))
    }


    /// Removes a stored item.
    /// - Parameter id: The identifier for the stored item.
    public static func remove(id: StoreID) {
        TIMKeychain.remove(item: TIMKeychainStoreItem(id: id))
    }


    /// Removes the longSecret from the keychain.
    /// This will disable biometric protection for all values with the specified keyId.
    /// - Parameter keyId: The identifier for the key that was used when it was saved.
    public static func removeLongSecret(keyId: String) {
        let keychainKey = longSecretKeychainId(keyId: keyId)
        remove(id: keychainKey)
    }

    //MARK: - Private helpers

    private static func longSecretKeychainId(keyId: String) -> String {
        return "TIMEncryptedStorage.longSecret.\(keyId)"
    }

    private static func storeLongSecret(keyId: String, longSecret: String) -> Result<Void, TIMEncryptedStorageError> {
        let keychainKey = longSecretKeychainId(keyId: keyId)
        let success = TIMKeychain.storeBiometricProtected(data: Data(longSecret.utf8), item: TIMKeychainStoreItem(id: keychainKey))
        if success {
            return .success(())
        } else {
            return .failure(.failedToStoreLongSecretViaBiometric)
        }
    }

    private static func handleKeyServerResultAndEncryptData(keyServerResult: Result<TIMKeyModel, TIMKeyServiceError>, id: StoreID, data: Data) -> Result<Void, TIMEncryptedStorageError> {
        switch keyServerResult {
        case .success(let keyModel):
            return encryptAndStoreInKeychain(id: id, data: data, keyModel: keyModel)
        case .failure(let error):
            return .failure(.keyServiceFailed(error))
        }
    }

    private static func handleKeyServerResultAndDecryptData(keyServerResult: Result<TIMKeyModel, TIMKeyServiceError>, id: StoreID) -> Result<Data, TIMEncryptedStorageError> {
        switch keyServerResult {
        case .success(let keyModel):
            return loadFromKeychainAndDecrypt(id: id, keyModel: keyModel)
        case .failure(let error):
            return .failure(.keyServiceFailed(error))
        }
    }

    private static func encryptAndStoreInKeychain(id: StoreID, data: Data, keyModel: TIMKeyModel) -> Result<Void, TIMEncryptedStorageError> {
        guard let encryptedData = keyModel.encrypt(data: data) else {
            return .failure(.failedToEncryptData)
        }
        let success = TIMKeychain.store(data: encryptedData, item: TIMKeychainStoreItem(id: id))
        if success {
            return .success(())
        } else {
            return .failure(.failedToStoreInKeychain)
        }
    }

    private static func loadFromKeychainAndDecrypt(id: StoreID, keyModel: TIMKeyModel) -> Result<Data, TIMEncryptedStorageError> {
        if let encryptedData = TIMKeychain.get(item: TIMKeychainStoreItem(id: id)) {
            if let decryptedData = keyModel.decrypt(data: encryptedData) {
                return .success(decryptedData)
            } else {
                return .failure(.failedToDecryptData)
            }
        } else {
            return .failure(.failedToLoadDataInKeychain)
        }
    }
}

#if canImport(Combine)
// MARK: - New Combine wrappers 🥳
@available(iOS 13, *)
public extension TIMEncryptedStorage {


    /// Combine wrapper for `store(id:data:keyId:secret:completion:)`
    static func store(id: StoreID, data: Data, keyId: String, secret: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            store(id: id, data: data, keyId: keyId, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `store(id:data:keyId:longSecret:completion:)`
    static func store(id: StoreID, data: Data, keyId: String, longSecret: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            store(id: id, data: data, keyId: keyId, longSecret: longSecret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeWithNewKey(id:data:secret:completion:)`
    static func storeWithNewKey(id: StoreID, data: Data, secret: String) -> Future<TIMESKeyCreationResult, TIMEncryptedStorageError> {
        Future { promise in
            storeWithNewKey(id: id, data: data, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeViaBiometric(id:data:keyId:completion:)`
    static func storeViaBiometric(id: StoreID, data: Data, keyId: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            storeViaBiometric(id: id, data: data, keyId: keyId, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeViaBiometricWithNewKey(id:data:secret:completion:)`
    static func storeViaBiometricWithNewKey(id: StoreID, data: Data, secret: String) -> Future<TIMESKeyCreationResult, TIMEncryptedStorageError> {
        Future { promise in
            storeViaBiometricWithNewKey(id: id, data: data, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `get(id:keyId:secret:completion:)`
    static func get(id: StoreID, keyId: String, secret: String) -> Future<Data, TIMEncryptedStorageError> {
        Future { promise in
            get(id: id, keyId: keyId, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `getViaBiometric(id:keyId:completion:)`
    static func getViaBiometric(id: StoreID, keyId: String) -> Future<TIMESBiometricLoadResult, TIMEncryptedStorageError> {
        Future { promise in
            getViaBiometric(id: id, keyId: keyId, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `enableBiometric(keyId:secret:completion:)`
    static func enableBiometric(keyId: String, secret: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            enableBiometric(keyId: keyId, secret: secret, completion: { promise($0) })
        }
    }
}
#endif

// MARK: -

@available(iOS, deprecated: 13)
public extension TIMEncryptedStorage {
    /// Default status completion with no value or error
    typealias TIMESStatusCompletion = (Result<Void, TIMEncryptedStorageError>) -> Void

    /// Result value is keyId from created key.
    typealias TIMESNewKeyStoreCompletion = (Result<TIMESKeyCreationResult, TIMEncryptedStorageError>) -> Void

    /// Result value is the decrypted data
    typealias TIMESLoadCompletion = (Result<Data, TIMEncryptedStorageError>) -> Void

    /// Result value is a struct containing descrypted data and the longSecret used to load it.
    typealias TIMESBiometricLoadCompletion = (Result<TIMESBiometricLoadResult, TIMEncryptedStorageError>) -> Void

    /// Stores encrypted data for a keyId and secret combination.
    /// - Parameters:
    ///   - id: The identifier for the data, which it can be recalled from.
    ///   - data: The data to encrypt and save.
    ///   - keyId: The identifier for the key that was created with the `secret`.
    ///   - secret: The secret for the key.
    ///   - completion: Invoked when the operation is done with a `Result`.
    static func store(id: StoreID, data: Data, keyId: String, secret: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Get encryption key with keyId + secret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in Keychain with id
        // 4. Return bool result for success
        TIMKeyService.getKey(secret: secret, keyId: keyId) { (keyServerResult) in
            let result = handleKeyServerResultAndEncryptData(keyServerResult: keyServerResult, id: id, data: data)
            completion(result)
        }
    }

    /// Stores encrypted data for a keyId and longSecret combination.
    /// - Parameters:
    ///   - id: The identifier for the data, which it can be recalled from.
    ///   - data: The data to encrypt and save.
    ///   - keyId: The identifier for the key that was created with the `secret`.
    ///   - longSecret: The longSecret for the key.
    ///   - completion: Invoked when the operation is done with a `Result`.
    static func store(id: StoreID, data: Data, keyId: String, longSecret: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Get encryption key with keyId + longSecret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in Keychain with id
        // 4. Return bool result for success
        TIMKeyService.getKeyViaLongSecret(longSecret: longSecret, keyId: keyId) { (keyServerResult) in
            let result = handleKeyServerResultAndEncryptData(keyServerResult: keyServerResult, id: id, data: data)
            completion(result)
        }
    }

    /// Stores encrypted data and creates a new encryption key with the secret.
    /// - Parameters:
    ///   - id: The identifier for the data, which it can be recalled from.
    ///   - data: The data to encrypt and save.
    ///   - secret: The secret for the new key.
    ///   - completion: Invoked when the operation is done with a `Result` containing the `keyId` for the new key.
    static func storeWithNewKey(id: StoreID, data: Data, secret: String, completion: @escaping TIMESNewKeyStoreCompletion) {
        // 1. Create new encryption key with secret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in Keychain with id
        // 4. Return bool result for success + keyId
        TIMKeyService.createKey(secret: secret) { (keyServerResult) in
            switch keyServerResult {
            case .success(let keyModel):
                guard let longSecret = keyModel.longSecret else {
                    completion(.failure(.keyServiceFailed(.responseHasNoLongSecret)))
                    return
                }
                let result = encryptAndStoreInKeychain(id: id, data: data, keyModel: keyModel)
                completion(result.map({ TIMESKeyCreationResult(keyId: keyModel.keyId, longSecret: longSecret )}))
            case .failure(let error):
                completion(.failure(.keyServiceFailed(error)))
            }
        }
    }

    /// Stores encrypted data for a keyId using biometric protection.
    /// This will prompt the user for biometric verification.
    /// - Parameters:
    ///   - id: The identifier for the data, which it can be recalled from.
    ///   - data: The data to encrypt and save.
    ///   - keyId: The identifier for the key, which can be recalled with the `longSecret` for biometric protection.
    ///   - completion: Invoked when the operation is done with a `Result`.
    static func storeViaBiometric(id: StoreID, data: Data, keyId: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Load longSecret for keyId via FaceID/TouchID
        // 2. Call store(id: id, data: data, keyId: keyId, longSecret: <loadedLongSecret>)
        // 3. Return result of store function

        let keychainKey = longSecretKeychainId(keyId: keyId)
        if  let longSecretData = TIMKeychain.getBiometricProtected(item: TIMKeychainStoreItem(id: keychainKey)),
            let longSecret = String(data: longSecretData, encoding: .utf8) {
            store(id: id, data: data, keyId: keyId, longSecret: longSecret, completion: completion)
        } else {
            completion(.failure(.failedToLoadLongSecretViaBiometric))
        }
    }

    /// Stores encrypted data by creating a new key with the secret, and storing the `longSecret` with biometric protection.
    /// - Parameters:
    ///   - id: The identifier for the data, which it can be recalled from.
    ///   - data: The data to encrypt and save.
    ///   - secret: The secret for the new key.
    ///   - completion: Invoked when the operation is done with a `Result` containing the `keyId` for the new key.
    static func storeViaBiometricWithNewKey(id: StoreID, data: Data, secret: String, completion: @escaping TIMESNewKeyStoreCompletion) {
        // 1. Create new encryption key with secret
        // 2. Save longSecret for keyId via FaceID/TouchID
        // 3. Encrypt data with encryption key from response
        // 4. Store encrypted data in Keychain with id
        // 5. Return bool result for success + keyId

        TIMKeyService.createKey(secret: secret) { (keyServerResult) in
            switch keyServerResult {
            case .success(let keyModel):
                guard let longSecret = keyModel.longSecret else {
                    completion(.failure(.keyServiceFailed(.responseHasNoLongSecret)))
                    return
                }
                let result = storeLongSecret(keyId: keyModel.keyId, longSecret: longSecret)
                    .flatMap { _ -> Result<String, TIMEncryptedStorageError> in
                        let encryptResult = encryptAndStoreInKeychain(id: id, data: data, keyModel: keyModel)
                        return encryptResult.map({ keyModel.keyId })
                    }
                completion(result.map({ _ in TIMESKeyCreationResult(keyId: keyModel.keyId, longSecret: longSecret)}))
            case .failure(let error):
                completion(.failure(.keyServiceFailed(error)))
            }
        }
    }


    /// Gets and decrypts data for a keyId and secret combination.
    /// - Parameters:
    ///   - id: The identifier for the data, which it was saved with.
    ///   - keyId: The identifier for the key that was created with the `secret`.
    ///   - secret: The secret which was used to create the `keyId`
    ///   - completion: Invoked when the operation is done with a `Result` containing the loaded data.
    static func get(id: StoreID, keyId: String, secret: String, completion: @escaping TIMESLoadCompletion) {
        // 1. Get encryption key with keyId + secret
        // 2. Load encrypted data from Keychain with id
        // 3. Decrypt data with encryption key
        // 4. Return decrypted data

        TIMKeyService.getKey(secret: secret, keyId: keyId) { (keyServerResult) in
            let result = handleKeyServerResultAndDecryptData(keyServerResult: keyServerResult, id: id)
            completion(result)
        }
    }

    /// Gets and decrypts data for a keyId by loading the `longSecret` using biometric protection.
    /// This will prompt the user for biometric verfication.
    /// - Parameters:
    ///   - id: The identifier for the data, which it was saved with.
    ///   - keyId: The identifier for the key that was created with the `secret`.
    ///   - completion: Invoked when the operation is done with a `Result` containing the loaded data and the `longSecret` that was used with the `keyId`.
    static func getViaBiometric(id: StoreID, keyId: String, completion: @escaping TIMESBiometricLoadCompletion) {
        // 1. Load longSecret for keyId via FaceID/TouchID
        // 2. Get encryption key with keyId + longSecret
        // 3. Load encrypted data from Keychain with id
        // 4. Decrypt data with encryption key
        // 5. Return decrypted data + longSecret
        let keychainKey = longSecretKeychainId(keyId: keyId)
        if let longSecretData = TIMKeychain.getBiometricProtected(item: TIMKeychainStoreItem(id: keychainKey)),
           let longSecret = String(data: longSecretData, encoding: .utf8) {
            TIMKeyService.getKeyViaLongSecret(longSecret: longSecret, keyId: keyId) { (keyServerResult) in
                let result = handleKeyServerResultAndDecryptData(keyServerResult: keyServerResult, id: id)
                completion(result.map({ TIMESBiometricLoadResult(data: $0, longSecret: longSecret) }))
            }
        } else {
            completion(.failure(.failedToLoadLongSecretViaBiometric))
        }
    }


    /// Enables biometric protection for a keyId, by getting the `longSecret` and saving it with biometric protection.
    ///
    /// Relevant to old versions of key services:
    /// If you experience the `getKeyResponseHasNoLongSecret` error you should look into the `enableBiometric(keyId:longSecret)` method
    /// and handle the `longSecret` response value on creation of keys.
    /// - Parameters:
    ///   - keyId: The identifier for the key that was created with the `secret`.
    ///   - secret: The secret which was used to create the `keyId`
    ///   - completion: Invoked when the operation is done with a `Result`
    static func enableBiometric(keyId: String, secret: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Get longSecret with keyId + secret
        // 2. Save longSecret for keyId via FaceID/TouchID
        // 5. Return bool result for success
        TIMKeyService.getKey(secret: secret, keyId: keyId) { (result) in
            switch result {
            case .success(let keyModel):
                guard let longSecret = keyModel.longSecret else {
                    completion(.failure(.keyServiceFailed(.responseHasNoLongSecret)))
                    return
                }
                let result = storeLongSecret(keyId: keyModel.keyId, longSecret: longSecret)
                completion(result)
            case .failure(let error):
                completion(.failure(.keyServiceFailed(error)))
            }
        }
    }

    /// Enables biometric protection for a keyId, by saving the `longSecret` with biometric protection.
    /// - Parameters:
    ///   - keyId: The identifier for the key that was created with the `longSecret`.
    ///   - longSecret: The longSecret which was created with the `keyId`
    static func enableBiometric(keyId: String, longSecret: String) -> Result<Void, TIMEncryptedStorageError> {
        storeLongSecret(keyId: keyId, longSecret: longSecret)
    }
}
