import Foundation

/// Support encryption methods by TIMEncryptedStorage
public enum TIMESEncryptionMethod {
    /// AES GCM - currently recommended!
    @available(iOS 13, *)
    case aesGcm

    /// AES CBC PKCS7
    /// CBC with PKCS7 padding is considered insecure due to the "padding oracle attack". Use the AES GCM for iOS 13+
    @available(iOS, deprecated: 13)
    case aesCbc
}
