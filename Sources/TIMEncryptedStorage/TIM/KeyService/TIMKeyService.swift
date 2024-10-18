import Foundation

#if canImport(Combine)
import Combine
#endif

/// End points supported by the `TIMKeyService`
enum TIMKeyServiceEndpoints: String {
    /// create key endpoint name
    case createKey = "createkey"

    /// get key endpoint name
    case key = "key"

    var urlPath: String {
        rawValue
    }
}

/// Key service wrapper for Trifork Identity Manager.
///
/// This wrapper is mainly for use internally in the TIMEncryptedStorage packages,
/// but it might come in handy in rare cases.
public final class TIMKeyService : TIMKeyServiceProtocol {

    /// The configuration of the key service
    private let configuration: TIMKeyServiceConfiguration

    /// The `URLSession` to perform the network requests to the Trifork Identity Manager KeyService.
    private let urlSession: URLSession
    /// The chosen URLSessionConfiguration chosen in the initialiser, used for re-initialising the URLSession if needed.
    private let urlSessionConfiguration: URLSessionConfiguration
    /// The number of times a failed url request is reattempted before an error is thrown
    private let requestRetryAttempts: Int

    /// Sets the configuration of the key service. This should be called before you call any other functions on this class.
    /// - Parameter configuration: The configuration.
    /// - Parameter networkSession: The `URLSession` to perform the network requests to the Trifork Identity Manager KeyService. Default is `URLSession(configuration: .ephemeral)`
    public init(
        configuration: TIMKeyServiceConfiguration,
        urlSession: URLSession = URLSession(configuration: .ephemeral),
        requestRetryAttempts: Int = 1
    ) {
        self.configuration = configuration
        self.urlSession = urlSession
        self.urlSessionConfiguration = urlSession.configuration
        self.requestRetryAttempts = requestRetryAttempts

        guard verifyConfiguration(configuration) else {
            fatalError("TIMKeyService configuration is invalid!")
        }
    }

    private func request<T: Decodable>(_ url: URL, parameters: [String: String], completion: @escaping (Result<T, TIMKeyServiceError>) -> Void) {
        // Helper method to perform the request and handle retries
        func performRequest(with urlSession: URLSession, retryCount: Int) {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try? JSONEncoder().encode(parameters)

            let task = urlSession.dataTask(with: request) { [weak self] (data, response, error) in
                guard let self else { fatalError("❗️No reference to self in \(#function)") }
                
                guard let response = response as? HTTPURLResponse else {
                    // Check if we can retry the request
                    if retryCount > 0 {
                        // Recreate the URLSession and retry the request
                        let newSession = URLSession(configuration: self.urlSessionConfiguration)
                        performRequest(with: newSession, retryCount: retryCount - 1)
                    } else {
                        // If no retries left, return the error
                        DispatchQueue.main.async {
                            completion(.failure(mapKeyServiceError(error)))
                        }
                    }
                    return
                }

                if response.statusCode == 200, let data = data {
                    if let keyModel = try? JSONDecoder().decode(T.self, from: data) {
                        DispatchQueue.main.async {
                            completion(.success(keyModel))
                        }
                    } else {
                        DispatchQueue.main.async {
                            completion(.failure(TIMKeyServiceError.unableToDecode))
                        }
                    }
                } else {
                    DispatchQueue.main.async {
                        completion(.failure(mapKeyServiceError(withCode: response.statusCode)))
                    }
                }
            }

            task.resume()
        }

        // Initial request attempt with the current URLSession
        performRequest(with: urlSession, retryCount: requestRetryAttempts)
    }

    func keyServiceUrl(endpoint: TIMKeyServiceEndpoints) -> URL {
        return URL(string: configuration.realmBaseUrl)!
            .appendingPathComponent("keyservice")
            .appendingPathComponent(configuration.version.urlPath)
            .appendingPathComponent(endpoint.urlPath)
    }

    func verifyConfiguration(_ configuration: TIMKeyServiceConfiguration) -> Bool {
        URL(string: configuration.realmBaseUrl) != nil
    }
}

#if canImport(Combine)
// MARK: - New Combine wrappers 🥳
@available(iOS 13, *)
public extension TIMKeyService {

    func getKey(secret: String, keyId: String) -> Future<TIMKeyModel, TIMKeyServiceError> {
        Future { promise in
            self.getKey(secret: secret, keyId: keyId, completion: promise)
        }
    }

    func getKeyViaLongSecret(longSecret: String, keyId: String) -> Future<TIMKeyModel, TIMKeyServiceError> {
        Future { promise in
            self.getKeyViaLongSecret(longSecret: longSecret, keyId: keyId, completion: promise)
        }
    }

    func createKey(secret: String) -> Future<TIMKeyModel, TIMKeyServiceError> {
        Future { promise in
            self.createKey(secret: secret, completion: promise)
        }
    }
}
#endif

// MARK: - 

@available(iOS, deprecated: 13)
public extension TIMKeyService {
    func getKey(secret: String, keyId: String, completion: @escaping (Result<TIMKeyModel, TIMKeyServiceError>) -> Void) {
        let parameters =
                ["secret": secret,
                 "keyid": keyId]

        let url = keyServiceUrl(endpoint: .key)
        request(url, parameters: parameters, completion: completion)
    }

    func getKeyViaLongSecret(longSecret: String, keyId: String, completion: @escaping (Result<TIMKeyModel, TIMKeyServiceError>) -> Void) {
        let parameters = ["longsecret": longSecret,
                          "keyid": keyId]
        let url = keyServiceUrl(endpoint: .key)
        request(url, parameters: parameters, completion: completion)
    }

    func createKey(secret: String, completion: @escaping (Result<TIMKeyModel, TIMKeyServiceError>) -> Void) {
        let parameters = ["secret": secret]
        let url = keyServiceUrl(endpoint: .createKey)
        request(url, parameters: parameters, completion: completion)
    }
}
