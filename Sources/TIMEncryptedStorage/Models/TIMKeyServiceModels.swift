import Foundation

/// Available versions for the key service API.
public enum TIMKeyServiceVersion {
    case v1

    var urlPath: String {
        switch self {
        case .v1:
            return "v1"
        }
    }
}

/// Configuration for the TIMKeyService.
public struct TIMKeyServiceConfiguration {
    let realmBaseUrl: String
    let version: TIMKeyServiceVersion

    /// Constructor for configuration
    /// - Parameters:
    ///   - realmBaseUrl: The baseUrl for your realm, e.g. https://oidc-test.hosted.trifork.com/auth/realms/myrealm
    ///   - version: The key service API version of your realm.
    public init(realmBaseUrl: String, version: TIMKeyServiceVersion) {
        self.realmBaseUrl = realmBaseUrl
        self.version = version
    }
}


/// Response model from key service
public class TIMKeyModel: Codable {
    enum CodingKeys: String, CodingKey {
        case key = "key"
        case keyId = "keyid"
        case longSecret = "longsecret"
    }

    /// The identifier for this encryption key
    public let keyId: String

    /// Encryption key for keyId
    public let key: String

    /// longSecret used as secret when logging in with biometric protection
    public let longSecret: String?

    public init(keyId: String, key: String, longSecret: String?) {
        self.key = key
        self.keyId = keyId
        self.longSecret = longSecret
    }
}
