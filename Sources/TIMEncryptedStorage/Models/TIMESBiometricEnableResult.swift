import Foundation


/// Biometric load result model
public struct TIMESBiometricLoadResult {

    /// The loaded data
    public let data: Data


    /// The longSecret unlocked via biometric protection (used as secret for encryption key)
    public let longSecret: String
}
