import XCTest
import CommonCrypto
@testable import TIMEncryptedStorage

final class TIMCryptorTests: XCTestCase {
    let data: Data = "All-My-Random-Data-😎".data(using: .utf8)!
    let key: Data = "2s5v8y/A?D(G+KbP".data(using: .utf8)!
    let key2: Data = "E)H@McQfTjWnZr4u7x!A%D*F-JaNdRgU".data(using: .utf8)!
    let iv: Data = "D*G-KaPdSgVkYp3s".data(using: .utf8)!
    let iv2: Data = "JaNdRgUjXn2r5u8x".data(using: .utf8)!

    @available(iOS 13, *)
    func testAESGCM() {

        let encryptedData = try! TIMESCryptor.AES.GCM.encrypt(key: key, data: data)
        let encryptedData2 = try! TIMESCryptor.AES.GCM.encrypt(key: key, data: data)
        let encryptedData3 = try! TIMESCryptor.AES.GCM.encrypt(key: key2, data: data)
        XCTAssertNotEqual(data, encryptedData)
        XCTAssertNotEqual(data, encryptedData2)
        XCTAssertNotEqual(encryptedData, encryptedData2) // Different nonces!
        XCTAssertNotEqual(encryptedData, encryptedData3) // Different keys!

        let decryptedData = try! TIMESCryptor.AES.GCM.decrypt(key: key, data: encryptedData)
        let decryptedData2 = try! TIMESCryptor.AES.GCM.decrypt(key: key, data: encryptedData2)
        let decryptedData3 = try! TIMESCryptor.AES.GCM.decrypt(key: key2, data: encryptedData3)
        XCTAssertNotEqual(encryptedData, decryptedData)
        XCTAssertNotEqual(encryptedData2, decryptedData2)
        XCTAssertEqual(data, decryptedData)
        XCTAssertEqual(decryptedData, decryptedData2)
        XCTAssertEqual(decryptedData, decryptedData3)
    }

    func testAESCBC() {
        let encryptedData = try! TIMESCryptor.AES.CBC.encrypt(key: key, data: data, iv: iv)
        let encryptedData2 = try! TIMESCryptor.AES.CBC.encrypt(key: key, data: data, iv: iv2)
        let encryptedData3 = try! TIMESCryptor.AES.CBC.encrypt(key: key2, data: data, iv: iv)
        XCTAssertNotEqual(data, encryptedData)
        XCTAssertNotEqual(data, encryptedData2)
        XCTAssertNotEqual(encryptedData, encryptedData2) // Different IVs!
        XCTAssertNotEqual(encryptedData, encryptedData3) // Different keys!

        let decryptedData = try! TIMESCryptor.AES.CBC.decrypt(key: key, data: encryptedData, iv: iv)
        let decryptedData2 = try! TIMESCryptor.AES.CBC.decrypt(key: key, data: encryptedData2, iv: iv2)
        let decryptedData3 = try! TIMESCryptor.AES.CBC.decrypt(key: key2, data: encryptedData3, iv: iv)
        XCTAssertNotEqual(encryptedData, decryptedData)
        XCTAssertNotEqual(encryptedData2, decryptedData2)
        XCTAssertEqual(data, decryptedData)
        XCTAssertEqual(decryptedData, decryptedData2)
        XCTAssertEqual(decryptedData, decryptedData3)
    }

    @available(iOS 13, *)
    func testErrorHandling() {
        let encryptedData = try! TIMESCryptor.AES.CBC.encrypt(key: key, data: data, iv: iv)
        do {
            _ = try TIMESCryptor.AES.GCM.decrypt(key: key, data: encryptedData)
            XCTFail("This should fail.")
        } catch let error {
            XCTAssertEqual("Failed to decrypt data with specified key: authenticationFailure", error.localizedDescription)
        }
    }
}

