import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

extension TIMESCryptor.AES {
    #if canImport(CryptoKit)
    @available(iOS 13, *)
    struct GCM  {
        @available(iOS 13, *)
        static func encrypt(key: Data, data: Data) throws -> Data {
            let nonce = CryptoKit.AES.GCM.Nonce()
            let symmetricKey = SymmetricKey(data: key)
            let sealedData = try CryptoKit.AES.GCM.seal(data, using: symmetricKey, nonce: nonce)
            if let encryptedContent = sealedData.combined {
                return encryptedContent
            } else {
                throw TIMEncryptedStorageError.failedToEncryptData(nil)
            }
        }

        @available(iOS 13, *)
        static func decrypt(key: Data, data: Data) throws -> Data {
            let symmetricKey = SymmetricKey(data: key)
            do {
                let sealedBox = try CryptoKit.AES.GCM.SealedBox(combined: data)
                return try CryptoKit.AES.GCM.open(sealedBox, using: symmetricKey)
            } catch let error {
                throw TIMEncryptedStorageError.failedToDecryptData(error)
            }
        }
    }
    #else
    // Dummy implementation. iOS 13 should always be able to import CryptoKit, but the archiving fails for Xcode 13+.
    // This way we can make the implementations available on compile time, to avoid build errors.
    @available(iOS 13, *)
    struct GCM  {
        @available(iOS 13, *)
        static func encrypt(key: Data, data: Data) throws -> Data {
            fatalError("Failed to import CryptoKit!")
        }

        @available(iOS 13, *)
        static func decrypt(key: Data, data: Data) throws -> Data {
            fatalError("Failed to import CryptoKit!")
        }
    }
    #endif
}
