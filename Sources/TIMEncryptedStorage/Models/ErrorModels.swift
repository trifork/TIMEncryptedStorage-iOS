import Foundation

/// Possible errors for TIMEncryptedStorage
public enum TIMEncryptedStorageError: Error, LocalizedError {

    // MARK: - Encryption errors
    case failedToEncryptData
    case failedToDecryptData
    case invalidEncryptionMethod
    case invalidEncryptionKey

    // MARK: - KeySever errors
    case keyServiceFailed(TIMKeyServiceError)

    // MARK: - Keychain errors
    case keychainFailed(TIMKeychainError)

    // MARK: - Unexpected data from Keychain
    case unexpectedData


    public var errorDescription: String? {
        switch self {
        case .failedToEncryptData:
            return "Failed to encrypt data with specified key."
        case .failedToDecryptData:
            return "Failed to decrypt data with specified key."
        case .invalidEncryptionMethod:
            return "The encryption method is invalid. Did you remember to call the configure method?"
        case .invalidEncryptionKey:
            return "The encryption key is invalid."
        case .keyServiceFailed(let error):
            return "The KeyService failed with error: \(error)"
        case .keychainFailed(let error):
            return "The Keychain failed with error: \(error)"
        case .unexpectedData:
            return "The Keychain loaded unexpected data. Failed to use the data."
        }
    }
}

/// Possible errors for the KeyService
public enum TIMKeyServiceError: Error, Equatable, LocalizedError {
    case badPassword
    case keyLocked
    case keyMissing
    case unableToCreateKey
    case badInternet
    case potentiallyNoInternet
    case unableToDecode

    /// Handles old versions of the key server, where the longSecret isn't returned.
    case responseHasNoLongSecret

    /// Unable to map KeyServer error
    case unknown(Int?, String?)

    public var errorDescription: String? {
        switch self {
        case .badPassword:
            return "The entered pin code was wrong."
        case .keyLocked:
            return "The used key was locked."
        case .keyMissing:
            return "There is no key with specified ID."
        case .unableToCreateKey:
            return "The key service failed to create key - contact your key service provider."
        case .badInternet, .potentiallyNoInternet:
            return "The connection to the key server failed - are you connected to the internet?"
        case .unableToDecode:
            return "The TIMEncryptedStorage framework failed to parse the result from the key service. Are you using the wrong version of the key service?"
        case .responseHasNoLongSecret:
            return "The key is an old version, which does not have longSecret for key results. You have to store the longSecret locally and use that instead of the secret."
        case .unknown(let code, let str):
            return "Unknown error [\(code?.description ?? "N/A")]: \(str ?? "N/A")"
        }
    }
}

public enum TIMKeychainError : Error, LocalizedError {
    /// Failed to store data
    case failedToStoreData

    /// Failed to load data
    case failedToLoadData

    /// Authentication failed for data retrieve (e.g. TouchID/FaceID)
    case authenticationFailedForData

    public var errorDescription: String? {
        switch self {
        case .authenticationFailedForData:
            return "The authentication failed for data, e.g. the user failed to unlock or cancelled the biometric ID prompt."
        case .failedToLoadData:
            return "Failed to load data from keychain."
        case .failedToStoreData:
            return "Failed to store data in keychain."
        }
    }
}

func mapKeyServerError(_ error: Error?) -> TIMKeyServiceError {
    guard let err = error else {
        return .unknown(nil, nil)
    }

    let error = err as NSError
    return mapKeyServerError(withCode: error.code, errorDescription: error.localizedDescription)
}

func mapKeyServerError(withCode code: Int, errorDescription: String? = nil) -> TIMKeyServiceError {
    switch code {
    case -1009: return .potentiallyNoInternet
    case let code where code < 0: return .badInternet
    case 401: return .badPassword
    case 204, 403: return .keyLocked
    case 404: return .keyMissing
    case 500: return .unableToCreateKey
    default: return .unknown(code, errorDescription)
    }
}
