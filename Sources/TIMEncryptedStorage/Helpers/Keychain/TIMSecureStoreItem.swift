import Foundation

public protocol TIMSecureStoreItem {
    var id: String { get }

    init(id: String)
}

/// Represents a item in the keychain with a given ID
public struct TIMKeychainStoreItem: TIMSecureStoreItem {

    public let id: String
    private (set) var parameters: [String: Any]

    public init(id: String) {
        self.id = id
        self.parameters = [kSecAttrAccount as String: id,
                           kSecClass as String: kSecClassGenericPassword]
    }

    mutating func addParameter(key: String, value: Any) {
        parameters.updateValue(value, forKey: key)
    }

    mutating func enableUseAuthenticationUI(_ authenticationUI: CFString) {
        addParameter(key: kSecUseAuthenticationUI as String, value: authenticationUI)
    }

    mutating func enableSafeAccessControl(_ safeAccessControl: SecAccessControl) {
        addParameter(key: kSecAttrAccessControl as String, value: safeAccessControl)
    }
}
