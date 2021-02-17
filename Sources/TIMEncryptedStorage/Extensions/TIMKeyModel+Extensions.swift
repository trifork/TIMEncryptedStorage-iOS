import Foundation
import CommonCrypto
import CryptoKit

extension TIMKeyModel {

    func encrypt(data: Data) throws -> Data {
        guard let keyRaw = keyRaw else {
            throw TIMEncryptedStorageError.invalidEncryptionKey
        }

        let encrypted: Data
        switch TIMEncryptedStorage.encryptionMethod {
        case .aesPkcs7:
            let iv = IVGenerator.randomIv()
            let encryptedData = try TIMESCryptor.AES.PCKS7.encrypt(key: keyRaw, data: data, iv: iv)
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

    func decrypt(data: Data) throws -> Data {
        guard let keyRaw = keyRaw else {
            throw TIMEncryptedStorageError.invalidEncryptionKey
        }

        let decrypted: Data
        switch TIMEncryptedStorage.encryptionMethod {
        case .aesPkcs7:
            let iv = data.prefix(IVGenerator.ivSize)
            let encryptedData = data.suffix(from: IVGenerator.ivSize)
            decrypted = try TIMESCryptor.AES.PCKS7.decrypt(key: keyRaw, data: encryptedData, iv: iv)
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

    /// decodes the key from base64 into raw data.
    private var keyRaw: Data? {
        Data(base64Encoded: key, options: .ignoreUnknownCharacters)
    }
}
