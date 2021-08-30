import XCTest
#if canImport(Combine)
import Combine
#endif
@testable import TIMEncryptedStorage

final class TIMEncryptedStorageTests: XCTestCase {
    private static let baseUrl = "https://oidc-test.hosted.trifork.com/auth/realms/dev"

    private static let testStore = SecureStorageMock()
    private static let keyService = TIMKeyService(
        configuration: TIMKeyServiceConfiguration(
            realmBaseUrl: baseUrl,
            version: .v1
        ),
        urlSession: .mockSession
    )

    static let keyId: String = UUID().uuidString
    static let secret: String = "1234"
    static let longSecret: String = "longSecret"

    override class func setUp() {
        super.setUp()
        URLSessionStubResults.reset()
        testStore.reset()

        // Configure mock key service
        let keyModel = TIMKeyModel(keyId: keyId, key: "TWJRZVRoV21acTR0Nnc5eg==", longSecret: longSecret)
        URLSessionStubResults.setKeyModel(baseUrl: baseUrl, endpoint: .key, keyModel: keyModel)
    }

    func testHasValue() {
        let id = "test"
        for method in TIMESEncryptionMethod.allCases {
            Self.testStore.reset()

            let storage = self.storage(method)
            XCTAssertFalse(storage.hasValue(id: id))

            storeData(storage: storage, id: id, data: "test".data(using: .utf8)!, assert: nil)
            XCTAssertTrue(storage.hasValue(id: id))

            storage.remove(id: id)
            XCTAssertFalse(storage.hasValue(id: id))

            // hasValue should also cover bio-values:
            enableBio(storage: storage)

            storeDataWithBio(storage: storage, id: id, data: "test".data(using: .utf8)!) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success:
                    break
                }
            }
            XCTAssertTrue(storage.hasValue(id: id))
        }
    }

    func testHasBiometricProtectedValue() {
        let id = "test"
        for method in TIMESEncryptionMethod.allCases {
            Self.testStore.reset()

            let storage = self.storage(method)
            XCTAssertFalse(storage.hasValue(id: id))
            XCTAssertFalse(storage.hasBiometricProtectedValue(id: id, keyId: Self.keyId))

            storeData(storage: storage, id: id, data: "test".data(using: .utf8)!, assert: nil)

            XCTAssertFalse(storage.hasBiometricProtectedValue(id: id, keyId: Self.keyId)) // Nope, this is not bio protected!
            storage.remove(id: id)

            // Enable biometric
            enableBio(storage: storage)

            storeDataWithBio(storage: storage, id: id, data: "test".data(using: .utf8)!) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success:
                    break
                }
            }

            XCTAssertTrue(storage.hasBiometricProtectedValue(id: id, keyId: Self.keyId))
            XCTAssertFalse(storage.hasBiometricProtectedValue(id: id, keyId: "Not-The-Right-Key-Id"))
        }
    }

    func testRemoveLongSecret() {
        let id = "test"
        for method in TIMESEncryptionMethod.allCases {
            Self.testStore.reset()
            let storage = self.storage(method)

            // Enable biometric
            enableBio(storage: storage)

            // Store something with bio
            let data = "test".data(using: .utf8)!
            storeDataWithBio(storage: storage, id: id, data: data) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success: break
                }
            }

            // Get it via bio to make sure it is accessible via the used longSecret
            loadDataWithBio(storage: storage, id: id) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let result):
                    XCTAssertEqual(result.longSecret, Self.longSecret)
                    XCTAssertEqual(result.data, data)
                }
            }

            // Remove!
            storage.removeLongSecret(keyId: Self.keyId)

            // It should be inaccessible with the longSecret now ...
            loadDataWithBio(storage: storage, id: id) { (result) in
                switch result {
                case .failure(let error):
                    if case TIMEncryptedStorageError.secureStorageFailed(.failedToLoadData) = error {
                        break //All good
                    } else {
                        XCTFail("Should have caused `.failedToLoadData`")
                    }
                case .success:
                    XCTFail("The long secret should have been removed for this key id!")
                }
            }
            XCTAssertFalse(storage.hasBiometricProtectedValue(id: id, keyId: Self.keyId))
        }
    }

    func testStoreAndLoadData() {
        let id = "test"
        let data = "testData".data(using: .utf8)!
        for method in TIMESEncryptionMethod.allCases {
            Self.testStore.reset()
            let storage = self.storage(method)
            storeData(storage: storage, id: id, data: data) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success: // All good!
                    break
                }
            }

            // Just a quick sanity check 😅
            let savedData = try! Self.testStore.get(item: SecureStorageMockItem(id: id)).get()
            XCTAssertNotEqual(savedData, data) // The data we saved shouldn't be equal to the data in the storage. We would expect it to be encrypted!

            loadData(storage: storage, id: id) { (result) in
                switch result {
                case .success(let loadedData):
                    XCTAssertEqual(loadedData, data)
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                }
            }
        }
    }

    func testStoreAndLoadWithLongSecretData() {
        let id = "test"
        let data = "testData".data(using: .utf8)!
        for method in TIMESEncryptionMethod.allCases {
            Self.testStore.reset()
            let storage = self.storage(method)

            let expect = XCTestExpectation(description: "Store should have returned")
            storage.store(id: id, data: data, keyId: Self.keyId, longSecret: Self.longSecret) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success:
                    break
                }
                expect.fulfill()
            }
            wait(for: [expect], timeout: 1.0)

            let expectLoad = XCTestExpectation(description: "Store should have returned")
            loadData(storage: storage, id: id) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let loadedData):
                    XCTAssertEqual(loadedData, data)
                }
                expectLoad.fulfill()
            }
            wait(for: [expectLoad], timeout: 1.0)
        }
    }

    func testStoreWithNewKey() {
        let createKeyId = UUID().uuidString
        let createKeyModel = TIMKeyModel(keyId: createKeyId, key: "JkYpSkBNY1FmVGpXblpyNA==", longSecret: "longSecret2")
        URLSessionStubResults.setKeyModel(baseUrl: Self.baseUrl, endpoint: .createKey, keyModel: createKeyModel)
        URLSessionStubResults.setKeyModel(baseUrl: Self.baseUrl, endpoint: .key, keyModel: createKeyModel)
        
        let id = "test"
        let data = "testData".data(using: .utf8)!
        for method in TIMESEncryptionMethod.allCases {
            Self.testStore.reset()
            let storage = self.storage(method)
            let expect = XCTestExpectation(description: "Store did not return")
            storage.storeWithNewKey(id: id, data: data, secret: Self.secret) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let creationResult):
                    XCTAssertEqual(creationResult.keyId, createKeyId)
                    XCTAssertEqual(creationResult.longSecret, "longSecret2")
                }
                expect.fulfill()
            }
            wait(for: [expect], timeout: 1.0)

            let expectLoad = XCTestExpectation(description: "Store did not return")
            storage.get(id: id, keyId: createKeyId, secret: Self.secret) { result in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let d):
                    XCTAssertEqual(d, data)
                }
                expectLoad.fulfill()
            }
            wait(for: [expectLoad], timeout: 1.0)
        }
    }

    func testStoreViaBiometricWithNewKey() {
        let createKeyId = UUID().uuidString
        let createKeyModel = TIMKeyModel(keyId: createKeyId, key: "JkYpSkBNY1FmVGpXblpyNA==", longSecret: "longSecret2")
        URLSessionStubResults.setKeyModel(baseUrl: Self.baseUrl, endpoint: .createKey, keyModel: createKeyModel)
        URLSessionStubResults.setKeyModel(baseUrl: Self.baseUrl, endpoint: .key, keyModel: createKeyModel)

        let id = "test"
        let data = "testData".data(using: .utf8)!
        for method in TIMESEncryptionMethod.allCases {
            Self.testStore.reset()
            let storage = self.storage(method)
            let expect = XCTestExpectation(description: "Store did not return")

            storage.storeViaBiometricWithNewKey(id: id, data: data, secret: Self.secret) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let creationResult):
                    XCTAssertEqual(creationResult.keyId, createKeyId)
                    XCTAssertEqual(creationResult.longSecret, "longSecret2")
                }
                expect.fulfill()
            }
            wait(for: [expect], timeout: 1.0)

            let expectLoad = XCTestExpectation(description: "Store did not return")
            storage.getViaBiometric(id: id, keyId: createKeyId) { (result) in
                switch result {
                case .failure(let error):
                    XCTFail(error.localizedDescription)
                case .success(let d):
                    XCTAssertEqual(d.data, data)
                    XCTAssertEqual(d.longSecret, "longSecret2")
                }
                expectLoad.fulfill()
            }
            wait(for: [expectLoad], timeout: 1.0)
        }
    }


    // MARK: - Test helpers using predefined keyId, secret and longSecret.

    private func storeData(storage: TIMEncryptedStorage<SecureStorageMock>, id: String, data: Data, assert: ((Result<Void, TIMEncryptedStorageError>) -> Void)?) {
        let expectStore = XCTestExpectation(description: "Store should have returned.")
        storage.store(id: id, data: data, keyId: Self.keyId, secret: Self.secret) { (result) in
            assert?(result)
            expectStore.fulfill()
        }
        wait(for: [expectStore], timeout: 1.0)
    }

    private func loadData(storage: TIMEncryptedStorage<SecureStorageMock>, id: String, assert: ((Result<Data, TIMEncryptedStorageError>) -> Void)?) {
        let expectStore = XCTestExpectation(description: "Store should have returned.")
        storage.get(id: id, keyId: Self.keyId, secret: Self.secret) { (result) in
            assert?(result)
            expectStore.fulfill()
        }
        wait(for: [expectStore], timeout: 1.0)
    }

    private func enableBio(storage: TIMEncryptedStorage<SecureStorageMock>) {
        let expectBioEnabling = XCTestExpectation(description: "Store should have returned.")
        storage.enableBiometric(keyId: Self.keyId, secret: Self.secret) { (result) in
            switch result {
            case .failure(let error):
                XCTFail(error.localizedDescription)
            case .success:
                break
            }
            expectBioEnabling.fulfill()
        }
        wait(for: [expectBioEnabling], timeout: 1.0)
    }

    private func storeDataWithBio(storage: TIMEncryptedStorage<SecureStorageMock>, id: String, data: Data, assert: ((Result<Void, TIMEncryptedStorageError>) -> Void)?) {
        let expectBioStore = XCTestExpectation(description: "Store should have returned.")
        storage.storeViaBiometric(id: id, data: data, keyId: Self.keyId) { (result) in
            assert?(result)
            expectBioStore.fulfill()
        }
        wait(for: [expectBioStore], timeout: 1.0)
    }

    private func loadDataWithBio(storage: TIMEncryptedStorage<SecureStorageMock>, id: String, assert: ((Result<TIMESBiometricLoadResult, TIMEncryptedStorageError>) -> Void)?) {
        let expectBioLoad = XCTestExpectation(description: "Store should have returned.")
        storage.getViaBiometric(id: id, keyId: Self.keyId) { (result) in
            assert?(result)
            expectBioLoad.fulfill()
        }
        wait(for: [expectBioLoad], timeout: 1.0)
    }

    private func storage(_ method: TIMESEncryptionMethod) -> TIMEncryptedStorage<SecureStorageMock> {
        switch method {
        case .aesCbc:
            return TIMEncryptedStorage(
                secureStorage: Self.testStore,
                keyService: Self.keyService,
                encryptionMethod: .aesCbc
            )
        default:
            if #available(iOS 13, *) {
                if method ==  .aesGcm {
                    return TIMEncryptedStorage(
                        secureStorage: Self.testStore,
                        keyService: Self.keyService,
                        encryptionMethod: .aesGcm
                    )
                } else {
                    fatalError("This encryption method is not supported.")
                }
            } else {
                fatalError("This encryption method is not supported.")
            }
        }
    }
}
