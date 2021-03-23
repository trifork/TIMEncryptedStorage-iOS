import XCTest
#if canImport(Combine)
import Combine
#endif
@testable import TIMEncryptedStorage

final class TIMKeyServiceTests: XCTestCase {
    static var config = TIMKeyServiceConfiguration(
        realmBaseUrl: "https://oidc-test.hosted.trifork.com/auth/realms/dev",
        version: .v1
    )
    private static let baseUrl = config.realmBaseUrl

    private let keyService: TIMKeyService = TIMKeyService(configuration: config, urlSession: .mockSession)

    override class func setUp() {
        super.setUp()
        URLSessionStubResults.reset()
    }

    func testValidConfigurationSet() {
        XCTAssertTrue(keyService.verifyConfiguration(Self.config))
    }

    func testInvalidConfigureSet() {
        let config = TIMKeyServiceConfiguration(
            realmBaseUrl: "INVALID URL",
            version: .v1
        )
        XCTAssertFalse(keyService.verifyConfiguration(config))
    }

    func testKeyServiceUrl() {
        XCTAssertEqual(
            "https://oidc-test.hosted.trifork.com/auth/realms/dev/keyservice/v1/key",
            keyService.keyServiceUrl(endpoint: .key).absoluteString
        )
    }

    func testGetKey() {
        let expectedKeyModel: TIMKeyModel = .stub()
        performKeyModelRequest(expectedKeyModel: expectedKeyModel, endpoint: .key) { (completion) in
            keyService.getKey(secret: "1234", keyId: expectedKeyModel.keyId, completion: completion)
        }
    }

    @available(iOS 13, *)
    func testGetKeyPublisher() {
        let keyModel: TIMKeyModel = .stub()
        performKeyModelPublisher(keyService.getKey(secret: "1234", keyId: keyModel.keyId), expectedKeyModel: keyModel, endpoint: .key)
    }

    func testCreateKey() {
        let keyModel: TIMKeyModel = .stub()
        performKeyModelRequest(expectedKeyModel: keyModel, endpoint: .createKey) { (completion) in
            keyService.createKey(secret: "1234", completion: completion)
        }
    }

    @available(iOS 13, *)
    func testCreateKeyPublisher() {
        let keyModel: TIMKeyModel = .stub()
        performKeyModelPublisher(keyService.createKey(secret: "1234"), expectedKeyModel: keyModel, endpoint: .createKey)
    }

    func testGetKeyViaLongSecret() {
        let keyModel: TIMKeyModel = .stub()
        performKeyModelRequest(expectedKeyModel: keyModel, endpoint: .key) { (completion) in
            keyService.getKeyViaLongSecret(longSecret: keyModel.longSecret!, keyId: keyModel.keyId, completion: completion)
        }
    }

    @available(iOS 13, *)
    func testGetKeyViaLongSecretPublisher() {
        let keyModel: TIMKeyModel = .stub()
        performKeyModelPublisher(keyService.getKeyViaLongSecret(longSecret: keyModel.longSecret!, keyId: keyModel.keyId), expectedKeyModel: keyModel, endpoint: .key)
    }

    func testUnknownStatusCode() {
        let url = URL(string: Self.baseUrl)!.appendingPathComponent("keyservice/v1/key")
        let keyModel: TIMKeyModel = .stub()
        URLSessionStubResults.resultsForUrls[url] = .dataResponse(
            data: try! JSONEncoder().encode(keyModel),
            response: HTTPURLResponse(url: url, statusCode: 600, httpVersion: nil, headerFields: nil)!
        )
        let expectation = XCTestExpectation()
        keyService.getKey(secret: "1234", keyId: keyModel.keyId) { (result) in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error, .unknown(600, nil))
            case .success:
                XCTFail("This response should have failed!")
            }
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)
    }

    func testUnableToDecode() {
        let url = URL(string: Self.baseUrl)!.appendingPathComponent("keyservice/v1/key")
        URLSessionStubResults.resultsForUrls[url] = .dataResponse(
            data: "NotJson".data(using: .utf8)!,
            response: HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let expectation = XCTestExpectation()
        keyService.getKey(secret: "1234", keyId: UUID().uuidString) { (result) in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error, .unableToDecode)
            case .success:
                XCTFail("This response should have failed!")
            }
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)
    }

    func testUnexpectedResponse() {
        let url = URL(string: Self.baseUrl)!.appendingPathComponent("keyservice/v1/key")
        let keyModel = TIMKeyModel.stub()
        URLSessionStubResults.resultsForUrls[url] = .dataResponse(
            data: try! JSONEncoder().encode(keyModel),
            response: URLResponse(url: url, mimeType: nil, expectedContentLength: -1, textEncodingName: nil)
        )
        let expectation = XCTestExpectation()
        keyService.getKey(secret: "1234", keyId: keyModel.keyId) { (result) in
            switch result {
            case .failure(let error):
                XCTAssertEqual(error, .unknown(nil, nil))
            case .success:
                XCTFail("This response should have failed!")
            }
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)
    }

    // MARK: - Private test helpers

    private func performKeyModelRequest(expectedKeyModel: TIMKeyModel, endpoint: TIMKeyServiceEndpoints, performRequest: (@escaping (Result<TIMKeyModel, TIMKeyServiceError>) -> Void) -> Void) {
        let keyModel: TIMKeyModel = .stub()
        URLSessionStubResults.setKeyModel(baseUrl: Self.baseUrl, endpoint: endpoint, keyModel: keyModel)
        let expect = XCTestExpectation(description: "KeyService should have returned.")
        performRequest({ result in
            switch result {
            case .failure(let error):
                XCTFail("This shouldn't have failed: \(error)")
            case .success(let km):
                XCTAssertEqual(km, keyModel)
            }
            expect.fulfill()
        })
        wait(for: [expect], timeout: 1.0)
    }

    @available(iOS 13, *)
    private func performKeyModelPublisher(_ publisher: Future<TIMKeyModel, TIMKeyServiceError>, expectedKeyModel: TIMKeyModel, endpoint: TIMKeyServiceEndpoints) {
        URLSessionStubResults.setKeyModel(baseUrl: Self.baseUrl, endpoint: endpoint, keyModel: expectedKeyModel)

        let expectation = XCTestExpectation(description: "Publisher should have completed.")
        var cancelBag = Set<AnyCancellable>()
        publisher
            .sink(
                receiveCompletion: { completion in
                    switch completion {
                    case .failure(let error):
                        XCTFail("This shouldn't have failed: \(error)")
                    case .finished: break
                    }
                    expectation.fulfill()

                },
                receiveValue: { km in
                    XCTAssertEqual(km, expectedKeyModel)
                })
            .store(in: &cancelBag)

        wait(for: [expectation], timeout: 1.0)
    }
}

extension TIMKeyModel: Equatable, CustomDebugStringConvertible {
    public static func == (lhs: TIMKeyModel, rhs: TIMKeyModel) -> Bool {
        return lhs.key == rhs.key && lhs.keyId == rhs.keyId && lhs.longSecret == rhs.longSecret
    }

    static func stub() -> TIMKeyModel {
        let keyId = UUID().uuidString
        let encryptionKey = "abcdefghlmnopqrstuwvxyz"
        let longSecret = String(encryptionKey.reversed())

        return TIMKeyModel(keyId: keyId, key: encryptionKey, longSecret: longSecret)
    }

    public var debugDescription: String {
        return "keyId=\(keyId),key=\(key),longSecret=\(longSecret ?? "nil")"
    }
}
