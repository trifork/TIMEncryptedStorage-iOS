import XCTest
@testable import TIMEncryptedStorage

final class TIMKeyModelExtensionsTests: XCTestCase {

    @available(iOS 13, *)
    func testEncryptDecryptGCMConfig() {
        let key = "UWZUalduWnI0dTd4IUElRA==" // KeyModel expects a base64 encoded key input
        let model = TIMKeyModel(keyId: "id", key: key, longSecret: nil)
        let myData = "My-test-data-to-encrypt-🔒".data(using: .utf8)!
        assertModel(model, originalData: myData, encryptionMethod: .aesGcm)
    }

    func testEncryptDecryptCBCConfig() {
        let key = "TWJRZVRoV21acTR0Nnc5eg=="
        let model = TIMKeyModel(keyId: "id", key: key, longSecret: nil)
        let myData = "My-test-data-to-encrypt-🔒".data(using: .utf8)!
        assertModel(model, originalData: myData, encryptionMethod: .aesCbc)
    }

    func testErrorHandlingForInvalidKey() {
        let model = TIMKeyModel(keyId: "id", key: "123", longSecret: nil)
        let myData = "My-test-data-to-encrypt-🔒".data(using: .utf8)!
        do {
            _ = try model.encrypt(data: myData, encryptionMethod: .aesCbc)
        } catch let error as TIMEncryptedStorageError {
            switch error {
            case .invalidEncryptionKey:
                break //All good!
            default:
                XCTFail("Error was supposed to be `.invalidEncryptionKey` but was \(error)")
            }
        } catch {
            XCTFail("Unexpected error!")
        }
    }

    private func assertModel(_ model: TIMKeyModel, originalData: Data, encryptionMethod: TIMESEncryptionMethod) {
        let encryptedData = try! model.encrypt(data: originalData, encryptionMethod: encryptionMethod)
        XCTAssertNotEqual(originalData, encryptedData)

        let decryptedData = try! model.decrypt(data: encryptedData, encryptionMethod: encryptionMethod)
        XCTAssertEqual(originalData, decryptedData)
    }
}

