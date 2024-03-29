import Foundation

/// Biometric load result model
public struct TIMESKeyCreationResult {

    /// The keyId
    public let keyId: String

    /// The longSecret, which can be used for biometric protection
    public let longSecret: String

    /// Initializer
    public init(keyId: String, longSecret: String) {
        self.keyId = keyId
        self.longSecret = longSecret
    }
}

