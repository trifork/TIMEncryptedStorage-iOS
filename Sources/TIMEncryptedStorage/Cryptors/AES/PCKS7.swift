import Foundation
import CommonCrypto

extension TIMESCryptor.AES {
    struct PCKS7 {
        static func encrypt(key: Data, data: Data, iv: Data) throws -> Data {
            try crypt(key: key, input: data, iv: iv, operation: kCCEncrypt)
        }

        static func decrypt(key: Data, data: Data, iv: Data) throws -> Data {
            try crypt(key: key, input: data, iv: iv, operation: kCCDecrypt)
        }

        private static func crypt(key: Data, input: Data, iv: Data, operation: Int) throws -> Data {
            var outLength = Int(0)
            var outBytes = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
            var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)

            input.withUnsafeBytes { rawBufferPointer in
                let encryptedBytes = rawBufferPointer.baseAddress

                iv.withUnsafeBytes { rawBufferPointer in
                    let ivBytes = rawBufferPointer.baseAddress

                    key.withUnsafeBytes { rawBufferPointer in
                        let keyBytes = rawBufferPointer.baseAddress

                        status = CCCrypt(
                            CCOperation(operation),
                            CCAlgorithm(kCCAlgorithmAES128), // algorithm
                            CCOptions(kCCOptionPKCS7Padding), // options
                            keyBytes, // key
                            key.count, // keylength
                            ivBytes, // iv
                            encryptedBytes, // dataIn
                            input.count, // dataInLength
                            &outBytes, // dataOut
                            outBytes.count, // dataOutAvailable
                            &outLength
                        )
                    }
                }
            }

            guard status == kCCSuccess else {
                if operation == kCCEncrypt {
                    throw TIMEncryptedStorageError.failedToEncryptData
                } else {
                    throw TIMEncryptedStorageError.failedToDecryptData
                }
            }

            return Data(bytes: &outBytes, count: outLength)
        }
    }
}
