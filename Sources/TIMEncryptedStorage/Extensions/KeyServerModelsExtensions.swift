import Foundation
import CommonCrypto

extension TIMKeyModel {

    /// encrypts the given data with this keymodel
    /// internally uses AES 128 (since the keyserver supplies 128 bit keys)
    /// with cbc PKSC 7 padding
    ///
    /// - Parameter data: plaintext
    /// - Returns: ciphertext
    func encrypt(data: Data) -> Data? {
        guard let keyRaw = keyRaw else {
            return nil
        }
        return aesCbcPkcs7(data, key: keyRaw, iv: nil, operation: kCCEncrypt)
    }

    /// decrypts the given data with this keymodel
    ///
    /// - Parameter data: ciphertext
    /// - Returns: plaintext
    func decrypt(data: Data) -> Data? {
        guard let keyRaw = keyRaw else {
            return nil
        }
        return aesCbcPkcs7(data, key: keyRaw, iv: nil, operation: kCCDecrypt)
    }


    /// Performs the given aes operation
    ///
    /// - Parameters:
    ///   - input: the data input to operate on
    ///   - key: the key to use for AES
    ///   - iv: the IV to use for AES
    ///   - operation: either an encryption or decryption
    /// - Returns: the operation result iff posible or nil if not.
    private func aesCbcPkcs7(_ input: Data, key: Data, iv: Data?, operation: Int) -> Data? {
        let keyBytes: UnsafeRawPointer = (key as NSData).bytes//.bindMemory(to: Void.self, capacity: key.count)
        let cipherDataLength: Int = input.count
        let cipherDataBytes: UnsafeRawPointer = (input as NSData).bytes//.bindMemory(to: Void.self, capacity: input.count)

        guard let bufferData: NSMutableData = NSMutableData(length: cipherDataLength + kCCBlockSizeAES128) else {
            return nil
        }
        let bufferPointer: UnsafeMutableRawPointer? = bufferData.mutableBytes
        let bufferLength: Int = size_t(bufferData.length)

        let ivBuffer: UnsafeRawPointer?
        if let iv = iv {
            ivBuffer = (iv as NSData).bytes//.bindMemory(to: Void.self, capacity: iv)
        } else {
            ivBuffer = nil
        }
        var bytesDecrypted: Int = 0
        // Perform operation
        let cryptStatus = CCCrypt(
                CCOperation(operation), // Operation
                CCAlgorithm(kCCAlgorithmAES128), // Algorithm
                CCOptions(kCCOptionPKCS7Padding | kCCModeCBC), // Options
                keyBytes, // key data
                kCCKeySizeAES128, // key length
                ivBuffer, // IV buffer
                cipherDataBytes, // input data
                cipherDataLength, // input length
                bufferPointer, // output buffer
                bufferLength, // output buffer length
                &bytesDecrypted)                        // output bytes decrypted real length

        if cryptStatus == kCCSuccess {
            bufferData.length = bytesDecrypted // Adjust buffer size to real bytes
            return bufferData as Data
        } else {
            return nil
        }
    }


    /// decodes the key from base64 into raw data.
    private var keyRaw: Data? {
        Data(base64Encoded: key, options: .ignoreUnknownCharacters)
    }
}
