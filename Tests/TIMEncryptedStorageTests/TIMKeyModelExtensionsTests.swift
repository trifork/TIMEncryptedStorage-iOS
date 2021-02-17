import XCTest
@testable import TIMEncryptedStorage

final class TIMKeyModelExtensionsTests: XCTestCase {

    @available(iOS 13, *)
    func testEncryptDecryptGCMConfig() {
        TIMEncryptedStorage.configure(
            keyServiceConfiguration: TIMKeyServiceConfiguration(realmBaseUrl: "", version: .v1),
            encryptionMethod: .aesGcm
        )
        let key = "UWZUalduWnI0dTd4IUElRA==" // KeyModel expects a base64 encoded key input
        let model = TIMKeyModel(keyId: "id", key: key, longSecret: nil)
        let myData = "My-test-data-to-encrypt-🔒".data(using: .utf8)!
        assertModel(model, originalData: myData)
    }

    func testEncryptDecryptCBCConfig() {
        TIMEncryptedStorage.configure(
            keyServiceConfiguration: TIMKeyServiceConfiguration(realmBaseUrl: "", version: .v1),
            encryptionMethod: .aesCbc
        )
        let key = "TWJRZVRoV21acTR0Nnc5eg=="
        let model = TIMKeyModel(keyId: "id", key: key, longSecret: nil)
        let myData = "My-test-data-to-encrypt-🔒".data(using: .utf8)!
        assertModel(model, originalData: myData)
    }

    private func assertModel(_ model: TIMKeyModel, originalData: Data) {
        let encryptedData = try! model.encrypt(data: originalData)
        XCTAssertNotEqual(originalData, encryptedData)

        let decryptedData = try! model.decrypt(data: encryptedData)
        XCTAssertEqual(originalData, decryptedData)
    }
}

