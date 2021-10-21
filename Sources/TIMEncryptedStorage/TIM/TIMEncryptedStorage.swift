import Foundation

#if canImport(Combine)
import Combine
#endif

/// StoreId typealias
public typealias StorageID = String


/// Trifork Identity Manager Encrypted Storage class.
///
/// The purpose of this classes is to store and load encrypted data based on a secret or biometric protection.
///
/// This class depends on the Trifork Identity Manager Key Service (`TIMKeyService`), which handles encryption keys.
public final class TIMEncryptedStorage<SecureStorage: TIMSecureStorage> {

    /// The secure storage instance that was injected upon creation
    public let secureStorage: SecureStorage

    private let keyService: TIMKeyServiceProtocol
    private let encryptionMethod: TIMESEncryptionMethod

    /// Constructor for `TIMEncryptedStorage`.
    /// - Parameters:
    ///   - secureStorage: The secure storage implementation. `TIMKeychain` is recommended.
    ///   - keyService: The key service implementation to use. `TIMKeyService` is recommended.
    ///   - encryptionMethod: Defines the encryption algorithm used by the framework. `.aesGcm` is recommended for iOS 13 or newer.
    public init(secureStorage: SecureStorage, keyService: TIMKeyServiceProtocol, encryptionMethod: TIMESEncryptionMethod) {
        self.secureStorage = secureStorage
        self.encryptionMethod = encryptionMethod
        self.keyService = keyService
    }

    /// Checks whether there is a stored value in the secure store or not.
    /// - Parameter id: The identifier for the stored item.
    /// - Returns: `true` if the item is present, otherwise `false`
    public func hasValue(id: StorageID) -> Bool {
        secureStorage.hasValue(item: SecureStorage.SecureStorageItem(id: id))
    }

    /// Checks whether there is a stored value in the secure store with biometric protection or not.
    /// - Parameters:
    ///   - id: The identifier for the stored item.
    ///   - keyId: The identifier for the key that was used when it was saved.
    /// - Returns: `true` if the item is present, otherwise `false`
    public func hasBiometricProtectedValue(id: StorageID, keyId: String) -> Bool {
        let secureStoreKey = longSecretSecureStoreId(keyId: keyId)
        return secureStorage.hasBiometricProtectedValue(item: SecureStorage.SecureStorageItem(id: secureStoreKey)) &&
            secureStorage.hasValue(item: SecureStorage.SecureStorageItem(id: id))
    }


    /// Removes a stored item.
    /// - Parameter id: The identifier for the stored item.
    public func remove(id: StorageID) {
        secureStorage.remove(item: SecureStorage.SecureStorageItem(id: id))
    }


    /// Removes the longSecret from the secure store.
    /// This will disable biometric protection for all values with the specified keyId.
    /// - Parameter keyId: The identifier for the key that was used when it was saved.
    public func removeLongSecret(keyId: String) {
        let secureStoreKey = longSecretSecureStoreId(keyId: keyId)
        remove(id: secureStoreKey)
    }

    //MARK: - Private helpers

    private func longSecretSecureStoreId(keyId: String) -> String {
        return "TIMEncryptedStorage.longSecret.\(keyId)"
    }

    private func storeLongSecret(keyId: String, longSecret: String) -> Result<Void, TIMEncryptedStorageError> {
        let secureStorageKey = longSecretSecureStoreId(keyId: keyId)
        let result = secureStorage.storeBiometricProtected(data: Data(longSecret.utf8), item: SecureStorage.SecureStorageItem(id: secureStorageKey))
        return result.mapError({ TIMEncryptedStorageError.secureStorageFailed($0) })
    }

    private func handleKeyServerResultAndEncryptData(keyServerResult: Result<TIMKeyModel, TIMKeyServiceError>, id: StorageID, data: Data) -> Result<Void, TIMEncryptedStorageError> {
        switch keyServerResult {
        case .success(let keyModel):
            return encryptAndStore(id: id, data: data, keyModel: keyModel)
        case .failure(let error):
            return .failure(.keyServiceFailed(error))
        }
    }

    private func handleKeyServerResultAndDecryptData(keyServerResult: Result<TIMKeyModel, TIMKeyServiceError>, id: StorageID) -> Result<Data, TIMEncryptedStorageError> {
        switch keyServerResult {
        case .success(let keyModel):
            return loadAndDecrypt(id: id, keyModel: keyModel)
        case .failure(let error):
            return .failure(.keyServiceFailed(error))
        }
    }

    private func encryptAndStore(id: StorageID, data: Data, keyModel: TIMKeyModel) -> Result<Void, TIMEncryptedStorageError> {
        let result: Result<Void, TIMEncryptedStorageError>
        do {
            let encryptedData = try keyModel.encrypt(data: data, encryptionMethod: encryptionMethod)
            let storeResult = secureStorage.store(data: encryptedData, item: SecureStorage.SecureStorageItem(id: id))
            result = storeResult.mapError({ TIMEncryptedStorageError.secureStorageFailed($0) })
        }
        catch let error as TIMEncryptedStorageError {
            result = .failure(error)
        }
        catch let error {
            result = .failure(.failedToEncryptData(error))
        }
        return result
    }

    private func loadAndDecrypt(id: StorageID, keyModel: TIMKeyModel) -> Result<Data, TIMEncryptedStorageError> {
        let result: Result<Data, TIMEncryptedStorageError>
        let loadResult: Result<Data, TIMSecureStorageError> = secureStorage.get(item: SecureStorage.SecureStorageItem(id: id))

        switch loadResult {
        case .success(let encryptedData):
            do {
                let decryptedData = try keyModel.decrypt(data: encryptedData, encryptionMethod: encryptionMethod)
                result = .success(decryptedData)
            }
            catch let error as TIMEncryptedStorageError {
                result = .failure(error)
            }
            catch let error {
                result = .failure(.failedToDecryptData(error))
            }
        case .failure(let secureStorageError):
            result = .failure(.secureStorageFailed(secureStorageError))
        }

        return result
    }
}

#if canImport(Combine)
// MARK: - New Combine wrappers 🥳
@available(iOS 13, *)
public extension TIMEncryptedStorage {

    /// Combine wrapper for `store(id:data:keyId:secret:completion:)`
    func store(id: StorageID, data: Data, keyId: String, secret: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            self.store(id: id, data: data, keyId: keyId, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `store(id:data:keyId:longSecret:completion:)`
    func store(id: StorageID, data: Data, keyId: String, longSecret: String) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            self.store(id: id, data: data, keyId: keyId, longSecret: longSecret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeWithNewKey(id:data:secret:completion:)`
    func storeWithNewKey(id: StorageID, data: Data, secret: String) -> Future<TIMESKeyCreationResult, TIMEncryptedStorageError> {
        Future { promise in
            self.storeWithNewKey(id: id, data: data, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeViaBiometric(id:data:keyId:willBeginNetworkRequests:completion:)`
    func storeViaBiometric(id: StorageID, data: Data, keyId: String, willBeginNetworkRequests: TIMESWillBeginNetworkRequests? = nil) -> Future<Void, TIMEncryptedStorageError> {
        Future { promise in
            self.storeViaBiometric(id: id, data: data, keyId: keyId, willBeginNetworkRequests: willBeginNetworkRequests, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `storeViaBiometricWithNewKey(id:data:secret:completion:)`
    func storeViaBiometricWithNewKey(id: StorageID, data: Data, secret: String) -> Future<TIMESKeyCreationResult, TIMEncryptedStorageError> {
        Future { promise in
            self.storeViaBiometricWithNewKey(id: id, data: data, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `get(id:keyId:secret:completion:)`
    func get(id: StorageID, keyId: String, secret: String) -> Future<Data, TIMEncryptedStorageError> {
        Future { promise in
            self.get(id: id, keyId: keyId, secret: secret, completion: { promise($0) })
        }
    }

    /// Combine wrapper for `getViaBiometric(id:keyId:willBeginNetworkRequests:completion:)`
    func getViaBiometric(id: StorageID, keyId: String, willBeginNetworkRequests: TIMESWillBeginNetworkRequests? = nil) -> Future<TIMESBiometricLoadResult, TIMEncryptedStorageError> {
        Future { promise in
            self.getViaBiometric(id: id, keyId: keyId, willBeginNetworkRequests: willBeginNetworkRequests, completion: { promise($0) })
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

    /// Result value is a struct containing descrypted data and the longSecret used to load it.
    typealias TIMESWillBeginNetworkRequests = () -> Void

    /// Stores encrypted data for a keyId and secret combination.
    /// - Parameters:
    ///   - id: The identifier for the data, which it can be recalled from.
    ///   - data: The data to encrypt and save.
    ///   - keyId: The identifier for the key that was created with the `secret`.
    ///   - secret: The secret for the key.
    ///   - completion: Invoked when the operation is done with a `Result`.
    func store(id: StorageID, data: Data, keyId: String, secret: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Get encryption key with keyId + secret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in secure storage with id
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
    func store(id: StorageID, data: Data, keyId: String, longSecret: String, completion: @escaping TIMESStatusCompletion) {
        // 1. Get encryption key with keyId + longSecret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in secure storage with id
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
    func storeWithNewKey(id: StorageID, data: Data, secret: String, completion: @escaping TIMESNewKeyStoreCompletion) {
        // 1. Create new encryption key with secret
        // 2. Encrypt data with encryption key from response
        // 3. Store encrypted data in secure storage with id
        // 4. Return bool result for success + keyId
        keyService.createKey(secret: secret) { (keyServerResult) in
            switch keyServerResult {
            case .success(let keyModel):
                guard let longSecret = keyModel.longSecret else {
                    completion(.failure(.keyServiceFailed(.responseHasNoLongSecret)))
                    return
                }
                let result = self.encryptAndStore(id: id, data: data, keyModel: keyModel)
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
    ///   - keyId: The identifier for the key, which can be recalled with the `longSecret` for biometric protection. This can be useful to show spinners.
    ///   - willBeginNetworkRequests: Optional closure, which will be invoked right before network requests are initiated. Will always be invoked on main thread.
    ///   - completion: Invoked when the operation is done with a `Result`.
    func storeViaBiometric(id: StorageID, data: Data, keyId: String, willBeginNetworkRequests: TIMESWillBeginNetworkRequests? = nil, completion: @escaping TIMESStatusCompletion) {
        // 1. Load longSecret for keyId via FaceID/TouchID
        // 2. Call store(id: id, data: data, keyId: keyId, longSecret: <loadedLongSecret>)
        // 3. Return result of store function

        let secureStorageKey = longSecretSecureStoreId(keyId: keyId)
        let longSecretResult = secureStorage.getBiometricProtected(item: SecureStorage.SecureStorageItem(id: secureStorageKey))

        switch longSecretResult {
        case .failure(let secureStorageError):
            completion(.failure(.secureStorageFailed(secureStorageError)))
        case .success(let longSecretData):
            if let longSecret = String(data: longSecretData, encoding: .utf8) {
                DispatchQueue.main.async {
                    willBeginNetworkRequests?()
                }
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
    func storeViaBiometricWithNewKey(id: StorageID, data: Data, secret: String, completion: @escaping TIMESNewKeyStoreCompletion) {
        // 1. Create new encryption key with secret
        // 2. Save longSecret for keyId via FaceID/TouchID
        // 3. Encrypt data with encryption key from response
        // 4. Store encrypted data in secure storage with id
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
                        let encryptResult = self.encryptAndStore(id: id, data: data, keyModel: keyModel)
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
    func get(id: StorageID, keyId: String, secret: String, completion: @escaping TIMESLoadCompletion) {
        // 1. Get encryption key with keyId + secret
        // 2. Load encrypted data from secure storage with id
        // 3. Decrypt data with encryption key
        // 4. Return decrypted data

        keyService.getKey(secret: secret, keyId: keyId) { (keyServerResult) in
            let result = self.handleKeyServerResultAndDecryptData(keyServerResult: keyServerResult, id: id)
            completion(result)
        }
    }

    /// Gets and decrypts data for a keyId by loading the `longSecret` using biometric protection.
    /// This will prompt the user for biometric verification.
    /// - Parameters:
    ///   - id: The identifier for the data, which it was saved with.
    ///   - keyId: The identifier for the key that was created with the `secret`.
    ///   - willBeginNetworkRequests: Optional closure, which will be invoked right before network requests are initiated. Will always be invoked on main thread.
    ///   - completion: Invoked when the operation is done with a `Result` containing the loaded data and the `longSecret` that was used with the `keyId`.
    func getViaBiometric(id: StorageID, keyId: String, willBeginNetworkRequests: TIMESWillBeginNetworkRequests? = nil, completion: @escaping TIMESBiometricLoadCompletion) {
        // 1. Load longSecret for keyId via FaceID/TouchID
        // 2. Get encryption key with keyId + longSecret
        // 3. Load encrypted data from secure storage with id
        // 4. Decrypt data with encryption key
        // 5. Return decrypted data + longSecret
        let secureStorageKey = longSecretSecureStoreId(keyId: keyId)
        let longSecretResult = secureStorage.getBiometricProtected(item: SecureStorage.SecureStorageItem(id: secureStorageKey))

        switch longSecretResult {
        case .success(let longSecretData):
            if let longSecret = String(data: longSecretData, encoding: .utf8) {
                DispatchQueue.main.async {
                    willBeginNetworkRequests?()
                }
                keyService.getKeyViaLongSecret(longSecret: longSecret, keyId: keyId) { (keyServerResult) in
                    let result = self.handleKeyServerResultAndDecryptData(keyServerResult: keyServerResult, id: id)
                    completion(result.map({ TIMESBiometricLoadResult(data: $0, longSecret: longSecret) }))
                }
            } else {
                completion(.failure(.unexpectedData))
            }
        case .failure(let secureStorageError):
            completion(.failure(.secureStorageFailed(secureStorageError)))
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
