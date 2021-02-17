import Foundation
import CommonCrypto
import CryptoKit

extension TIMKeyModel {

    /// Encrypts data, using the data in the receiver model
    /// Note that the returned data is a combined set of nonce and encrypted data.
    func encrypt(data: Data) throws -> Data {
        guard let keyRaw = keyRaw else {
            throw TIMEncryptedStorageError.invalidEncryptionKey
        }

        let encrypted: Data
        switch TIMEncryptedStorage.encryptionMethod {
        case .aesCbc:
            let iv = IVGenerator.randomIv()
            let encryptedData = try TIMESCryptor.AES.CBC.encrypt(key: keyRaw, data: data, iv: iv)
            var combined = iv
            combined.append(encryptedData)
            encrypted = combined
        default:
            if #available(iOS 13, *) {
                if TIMEncryptedStorage.encryptionMethod == .aesGcm {
                    encrypted = try TIMESCryptor.AES.GCM.encrypt(key: keyRaw, data: data)
                } else {
                    throw TIMEncryptedStorageError.invalidEncryptionMethod
                }
            } else {
                throw TIMEncryptedStorageError.invalidEncryptionMethod
            }
        }

        return encrypted
    }

    /// Decrypts data using the data in the receiver mode.
    /// Note that this method expects a combined set of data, with nonce and encrypted data.
    func decrypt(data: Data) throws -> Data {
        guard let keyRaw = keyRaw else {
            throw TIMEncryptedStorageError.invalidEncryptionKey
        }

        let decrypted: Data
        switch TIMEncryptedStorage.encryptionMethod {
        case .aesCbc:
            let iv = data.prefix(IVGenerator.ivSize)
            let encryptedData = data.suffix(from: IVGenerator.ivSize)
            decrypted = try TIMESCryptor.AES.CBC.decrypt(key: keyRaw, data: encryptedData, iv: iv)
        default:
            if #available(iOS 13, *) {
                if TIMEncryptedStorage.encryptionMethod == .aesGcm {
                    decrypted = try TIMESCryptor.AES.GCM.decrypt(key: keyRaw, data: data)
                } else {
                    throw TIMEncryptedStorageError.invalidEncryptionMethod
                }
            } else {
                throw TIMEncryptedStorageError.invalidEncryptionMethod
            }
        }

        return decrypted
    }

    /// Decodes the key from Base64 into raw data, since the KeyService model contains base64 encoded keys.
    private var keyRaw: Data? {
        Data(base64Encoded: key, options: .ignoreUnknownCharacters)
    }
}
