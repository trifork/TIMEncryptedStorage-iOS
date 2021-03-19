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
public final class TIMEncryptedStorage<SecureStore: TIMSecureStore> {

    private let secureStore: SecureStore
    private let keyService: TIMKeyService
    private let encryptionMethod: TIMESEncryptionMethod

    /// Defines the encryption algorithm used by the framework.
    /// It is recommended to use `.aesGcm` when running on iOS 13 or newer.
    public init(secureStore: SecureStore, keyService: TIMKeyService, encryptionMethod: TIMESEncryptionMethod) {
        self.secureStore = secureStore
        self.encryptionMethod = encryptionMethod
        self.keyService = keyService
    }

    /// Checks whether there is a stored value in the keychain or not.
    /// - Parameter id: The identifier for the stored item.
    /// - Returns: `true` if the item is present, otherwise `false`
    public func hasValue(id: StoreID) -> Bool {
        secureStore.hasValue(item: SecureStore.SecureStoreItem(id: id))
    }

    /// Checks whether there is a stored value in the keychain with biometric protection or not.
    /// - Parameters:
    ///   - id: The identifier for the stored item.
    ///   - keyId: The identifier for the key that was used when it was saved.
    /// - Returns: `true` if the item is present, otherwise `false`
    public func hasBiometricProtectedValue(id: StoreID, keyId: String) -> Bool {
        let keychainKey = longSecretKeychainId(keyId: keyId)
        return secureStore.hasBiometricProtectedValue(item: SecureStore.SecureStoreItem(id: keychainKey)) &&
            secureStore.hasValue(item: SecureStore.SecureStoreItem(id: id))
    }


    /// Removes a stored item.
    /// - Parameter id: The identifier for the stored item.
    public func remove(id: StoreID) {
        secureStore.remove(item: SecureStore.SecureStoreItem(id: id))
    }


    /// Removes the longSecret from the keychain.
    /// This will disable biometric protection for all values with the specified keyId.
    /// - Parameter keyId: The identifier for the key that was used when it was saved.
    public func removeLongSecret(keyId: String) {
        let keychainKey = longSecretKeychainId(keyId: keyId)
        remove(id: keychainKey)
    }

    //MARK: - Private helpers

    private func longSecretKeychainId(keyId: String) -> String {
        return "TIMEncryptedStorage.longSecret.\(keyId)"
    }

    private func storeLongSecret(keyId: String, longSecret: String) -> Result<Void, TIMEncryptedStorageError> {
        let keychainKey = longSecretKeychainId(keyId: keyId)
        let result = secureStore.storeBiometricProtected(data: Data(longSecret.utf8), item: SecureStore.SecureStoreItem(id: keychainKey))
        return result.mapError({ TIMEncryptedStorageError.keychainFailed($0) })
    }

    private func handleKeyServerResultAndEncryptData(keyServerResult: Result<TIMKeyModel, TIMKeyServiceError>, id: StoreID, data: Data) -> Result<Void, TIMEncryptedStorageError> {
        switch keyServerResult {
        case .success(let keyModel):
            return encryptAndStoreInKeychain(id: id, data: data, keyModel: keyModel)
        case .failure(let error):
            return .failure(.keyServiceFailed(error))
        }
    }

    private func handleKeyServerResultAndDecryptData(keyServerResult: Result<TIMKeyModel, TIMKeyServiceError>, id: StoreID) -> Result<Data, TIMEncryptedStorageError> {
        switch keyServerResult {
        case .success(let keyModel):
            return loadFromKeychainAndDecrypt(id: id, keyModel: keyModel)
        case .failure(let error):
            return .failure(.keyServiceFailed(error))
        }
    }

    private func encryptAndStoreInKeychain(id: StoreID, data: Data, keyModel: TIMKeyModel) -> Result<Void, TIMEncryptedStorageError> {
        let result: Result<Void, TIMEncryptedStorageError>
        do {
            let encryptedData = try keyModel.encrypt(data: data, encryptionMethod: encryptionMethod)
            let storeResult = secureStore.store(data: encryptedData, item: SecureStore.SecureStoreItem(id: id))
            result = storeResult.mapError({ TIMEncryptedStorageError.keychainFailed($0) })
        }
        catch let error as TIMEncryptedStorageError {
            result = .failure(error)
        }
        catch {
            result = .failure(.failedToEncryptData)
        }
        return result
    }

    private func loadFromKeychainAndDecrypt(id: StoreID, keyModel: TIMKeyModel) -> Result<Data, TIMEncryptedStorageError> {
        let result: Result<Data, TIMEncryptedStorageError>
        let loadResult: Result<Data, TIMKeychainError> = secureStore.get(item: SecureStore.SecureStoreItem(id: id))

        switch loadResult {
        case .success(let encryptedData):
            do {
                let decryptedData = try keyModel.decrypt(data: encryptedData, encryptionMethod: encryptionMethod)
                result = .success(decryptedData)
            }
            catch let error as TIMEncryptedStorageError {
                result = .failure(error)
            }
            catch {
                result = .failure(.failedToDecryptData)
            }
        case .failure(let keychainError):
            result = .failure(.keychainFailed(keychainError))
        }

        return result
    }
}

#if canImport(Combine)
// MARK: - New Combine wrappers 🥳
@available(iOS 13, *)
public extension TIMEncryptedStorage {

    /// Combine wrapper for `store(id:data:keyId:secret:completion:)`
    func store(id: StoreID, data: Data, keyId: String, secret: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            self.store(id: id, data: data, keyId: keyId, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `store(id:data:keyId:longSecret:completion:)`
    func store(id: StoreID, data: Data, keyId: String, longSecret: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            self.store(id: id, data: data, keyId: keyId, longSecret: longSecret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeWithNewKey(id:data:secret:completion:)`
    func storeWithNewKey(id: StoreID, data: Data, secret: String) -> Future<TIMESKeyCreationResult, TIMEncryptedStorageError> {
        Future { promise in
            self.storeWithNewKey(id: id, data: data, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeViaBiometric(id:data:keyId:completion:)`
    func storeViaBiometric(id: StoreID, data: Data, keyId: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            self.storeViaBiometric(id: id, data: data, keyId: keyId, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeViaBiometricWithNewKey(id:data:secret:completion:)`
    func storeViaBiometricWithNewKey(id: StoreID, data: Data, secret: String) -> Future<TIMESKeyCreationResult, TIMEncryptedStorageError> {
        Future { promise in
            self.storeViaBiometricWithNewKey(id: id, data: data, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `get(id:keyId:secret:completion:)`
    func get(id: StoreID, keyId: String, secret: String) -> Future<Data, TIMEncryptedStorageError> {
        Future { promise in
            self.get(id: id, keyId: keyId, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `getViaBiometric(id:keyId:completion:)`
    func getViaBiometric(id: StoreID, keyId: String) -> Future<TIMESBiometricLoadResult, TIMEncryptedStorageError> {
        Future { promise in
            self.getViaBiometric(id: id, keyId: keyId, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `enableBiometric(keyId:secret:completion:)`
    func enableBiometric(keyId: String, secret: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            self.enableBiometric(keyId: keyId, secret: secret, completion: { promise($0) })
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
    func store(id: StoreID, data: Data, keyId: String, secret: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Get encryption key with keyId + secret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in Keychain with id
        // 4. Return bool result for success
        keyService.getKey(secret: secret, keyId: keyId) { (keyServerResult) in
            let result = self.handleKeyServerResultAndEncryptData(keyServerResult: keyServerResult, id: id, data: data)
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
    func store(id: StoreID, data: Data, keyId: String, longSecret: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Get encryption key with keyId + longSecret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in Keychain with id
        // 4. Return bool result for success
        keyService.getKeyViaLongSecret(longSecret: longSecret, keyId: keyId) { (keyServerResult) in
            let result = self.handleKeyServerResultAndEncryptData(keyServerResult: keyServerResult, id: id, data: data)
            completion(result)
        }
    }

    /// Stores encrypted data and creates a new encryption key with the secret.
    /// - Parameters:
    ///   - id: The identifier for the data, which it can be recalled from.
    ///   - data: The data to encrypt and save.
    ///   - secret: The secret for the new key.
    ///   - completion: Invoked when the operation is done with a `Result` containing the `keyId` for the new key.
    func storeWithNewKey(id: StoreID, data: Data, secret: String, completion: @escaping TIMESNewKeyStoreCompletion) {
        // 1. Create new encryption key with secret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in Keychain with id
        // 4. Return bool result for success + keyId
        keyService.createKey(secret: secret) { (keyServerResult) in
            switch keyServerResult {
            case .success(let keyModel):
                guard let longSecret = keyModel.longSecret else {
                    completion(.failure(.keyServiceFailed(.responseHasNoLongSecret)))
                    return
                }
                let result = self.encryptAndStoreInKeychain(id: id, data: data, keyModel: keyModel)
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
    func storeViaBiometric(id: StoreID, data: Data, keyId: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Load longSecret for keyId via FaceID/TouchID
        // 2. Call store(id: id, data: data, keyId: keyId, longSecret: <loadedLongSecret>)
        // 3. Return result of store function

        let keychainKey = longSecretKeychainId(keyId: keyId)
        let loadResult = secureStore.getBiometricProtected(item: SecureStore.SecureStoreItem(id: keychainKey))

        switch loadResult {
        case .failure(let keychainError):
            completion(.failure(.keychainFailed(keychainError)))
        case .success(let longSecretData):
            if let longSecret = String(data: longSecretData, encoding: .utf8) {
                store(id: id, data: data, keyId: keyId, longSecret: longSecret, completion: completion)
            } else {
                completion(.failure(.unexpectedData))
            }
        }
    }

    /// Stores encrypted data by creating a new key with the secret, and storing the `longSecret` with biometric protection.
    /// - Parameters:
    ///   - id: The identifier for the data, which it can be recalled from.
    ///   - data: The data to encrypt and save.
    ///   - secret: The secret for the new key.
    ///   - completion: Invoked when the operation is done with a `Result` containing the `keyId` for the new key.
    func storeViaBiometricWithNewKey(id: StoreID, data: Data, secret: String, completion: @escaping TIMESNewKeyStoreCompletion) {
        // 1. Create new encryption key with secret
        // 2. Save longSecret for keyId via FaceID/TouchID
        // 3. Encrypt data with encryption key from response
        // 4. Store encrypted data in Keychain with id
        // 5. Return bool result for success + keyId

        keyService.createKey(secret: secret) { (keyServerResult) in
            switch keyServerResult {
            case .success(let keyModel):
                guard let longSecret = keyModel.longSecret else {
                    completion(.failure(.keyServiceFailed(.responseHasNoLongSecret)))
                    return
                }
                let result = self.storeLongSecret(keyId: keyModel.keyId, longSecret: longSecret)
                    .flatMap { _ -> Result<String, TIMEncryptedStorageError> in
                        let encryptResult = self.encryptAndStoreInKeychain(id: id, data: data, keyModel: keyModel)
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
    func get(id: StoreID, keyId: String, secret: String, completion: @escaping TIMESLoadCompletion) {
        // 1. Get encryption key with keyId + secret
        // 2. Load encrypted data from Keychain with id
        // 3. Decrypt data with encryption key
        // 4. Return decrypted data

        keyService.getKey(secret: secret, keyId: keyId) { (keyServerResult) in
            let result = self.handleKeyServerResultAndDecryptData(keyServerResult: keyServerResult, id: id)
            completion(result)
        }
    }

    /// Gets and decrypts data for a keyId by loading the `longSecret` using biometric protection.
    /// This will prompt the user for biometric verfication.
    /// - Parameters:
    ///   - id: The identifier for the data, which it was saved with.
    ///   - keyId: The identifier for the key that was created with the `secret`.
    ///   - completion: Invoked when the operation is done with a `Result` containing the loaded data and the `longSecret` that was used with the `keyId`.
    func getViaBiometric(id: StoreID, keyId: String, completion: @escaping TIMESBiometricLoadCompletion) {
        // 1. Load longSecret for keyId via FaceID/TouchID
        // 2. Get encryption key with keyId + longSecret
        // 3. Load encrypted data from Keychain with id
        // 4. Decrypt data with encryption key
        // 5. Return decrypted data + longSecret
        let keychainKey = longSecretKeychainId(keyId: keyId)
        let longSecretResult = secureStore.getBiometricProtected(item: SecureStore.SecureStoreItem(id: keychainKey))

        switch longSecretResult {
        case .success(let longSecretData):
            if let longSecret = String(data: longSecretData, encoding: .utf8) {
                keyService.getKeyViaLongSecret(longSecret: longSecret, keyId: keyId) { (keyServerResult) in
                    let result = self.handleKeyServerResultAndDecryptData(keyServerResult: keyServerResult, id: id)
                    completion(result.map({ TIMESBiometricLoadResult(data: $0, longSecret: longSecret) }))
                }
            } else {
                completion(.failure(.unexpectedData))
            }
        case .failure(let keychainError):
            completion(.failure(.keychainFailed(keychainError)))
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
    func enableBiometric(keyId: String, secret: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Get longSecret with keyId + secret
        // 2. Save longSecret for keyId via FaceID/TouchID
        // 5. Return bool result for success
        keyService.getKey(secret: secret, keyId: keyId) { (result) in
            switch result {
            case .success(let keyModel):
                guard let longSecret = keyModel.longSecret else {
                    completion(.failure(.keyServiceFailed(.responseHasNoLongSecret)))
                    return
                }
                let result = self.storeLongSecret(keyId: keyModel.keyId, longSecret: longSecret)
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
    func enableBiometric(keyId: String, longSecret: String) -> Result<Void, TIMEncryptedStorageError> {
        storeLongSecret(keyId: keyId, longSecret: longSecret)
    }
}
