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
    ///
    /// - Parameter serverAddress: eg "https://someserver.com/auth/realms/myrealm/keyservice/v1/"
    private let configuration: TIMKeyServiceConfiguration

    /// Sets the configuration of the key service. This should be called before you call any other fuctions on this class.
    /// - Parameter configuration: The configuration.
    public init(configuration: TIMKeyServiceConfiguration) {
        self.configuration = configuration

        guard verifyConfiguration(configuration) else {
            fatalError("TIMKeyService configuration is invalid!")
        }
    }

    private func request<T: Decodable>(_ url: URL, parameters: [String : String], completion: @escaping (Result<T, TIMKeyServiceError>) -> Void) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONEncoder().encode(parameters)

        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let response = response as? HTTPURLResponse else {
                DispatchQueue.main.async {
                    completion(.failure(mapKeyServerError(error)))
                }
                return
            }

            if response.statusCode == 200,
                let data = data {
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
                    completion(.failure(mapKeyServerError(withCode: response.statusCode)))
                }
            }
        }

        task.resume()
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
