import Foundation

#if canImport(Combine)
import Combine
#endif

/// The key service is responsible for creating and getting encryption keys based on a pin code or long secret (from biometric identification).
///
/// This protocol mainly exists for testing purposes.
public protocol TIMKeyServiceProtocol {
    /// Gets a existing encryption key from the key server, by using a `secret`
    /// - Parameters:
    ///   - secret: The `secret`, which was used when the key was created.
    ///   - keyId: The identifier for the encryption key.
    ///   - completion: Invoked when the request is done. Contains a `Result` with the response from the server.
    func getKey(secret: String, keyId: String, completion: @escaping (Result<TIMKeyModel, TIMKeyServiceError>) -> Void)

    /// Gets a existing encryption key from the key server, by using a `longSecret`
    /// - Parameters:
    ///   - longSecret: The `longSecret`, which was returned when the key was created with a `secret`.
    ///   - keyId: The identifier for the encryption key.
    ///   - completion: Invoked when the request is done. Contains a `Result` with the response from the server.
    func getKeyViaLongSecret(longSecret: String, keyId: String, completion: @escaping (Result<TIMKeyModel, TIMKeyServiceError>) -> Void)

    /// Creates a new key with a secret.
    /// - Parameters:
    ///   - secret: The `secret`, which was used when the key was created.
    ///   - completion: Invoked when the request is done. Contains a `Result` with the response from the server.
    func createKey(secret: String, completion: @escaping (Result<TIMKeyModel, TIMKeyServiceError>) -> Void)

    #if canImport(Combine)
    /// Combine wrapper for `getKey` function.
    @available(iOS 13, *)
    func getKey(secret: String, keyId: String) -> Future<TIMKeyModel, TIMKeyServiceError>

    /// Combine wrapper for `getKeyViaLongSecret` function.
    @available(iOS 13, *)
    func getKeyViaLongSecret(longSecret: String, keyId: String) -> Future<TIMKeyModel, TIMKeyServiceError>

    /// Combine wrapper for `createKey` function.
    @available(iOS 13, *)
    func createKey(secret: String) -> Future<TIMKeyModel, TIMKeyServiceError>
    #endif
}
