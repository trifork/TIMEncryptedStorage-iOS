import Foundation
import CryptoKit

extension TIMESCryptor.AES {
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
                throw TIMEncryptedStorageError.failedToEncryptData
            }
        }

        @available(iOS 13, *)
        static func decrypt(key: Data, data: Data) throws -> Data {
            let symmetricKey = SymmetricKey(data: key)
            let sealedBox = try CryptoKit.AES.GCM.SealedBox(combined: data)
            return try CryptoKit.AES.GCM.open(sealedBox, using: symmetricKey)
        }
    }
}
