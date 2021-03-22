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
    private static let baseUrl = URL(string: config.realmBaseUrl)!

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
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/key")
        let expectedKeyModel = TIMKeyModel.stub()
        performKeyModelRequest(expectedKeyModel: expectedKeyModel, url: url) { (completion) in
            keyService.getKey(secret: "1234", keyId: expectedKeyModel.keyId, completion: completion)
        }
    }

    @available(iOS 13, *)
    func testGetKeyPublisher() throws {
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/key")
        let keyModel = TIMKeyModel.stub()
        performKeyModelPublisher(keyService.getKey(secret: "1234", keyId: keyModel.keyId), expectedKeyModel: keyModel, url: url)
    }

    func testCreateKey() {
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/createkey")
        let keyModel = TIMKeyModel.stub()
        performKeyModelRequest(expectedKeyModel: keyModel, url: url) { (completion) in
            keyService.createKey(secret: "1234", completion: completion)
        }
    }

    @available(iOS 13, *)
    func testCreateKeyPublisher() {
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/createkey")
        performKeyModelPublisher(keyService.createKey(secret: "1234"), expectedKeyModel: .stub(), url: url)
    }

    func testGetKeyViaLongSecret() {
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/key")
        let keyModel = TIMKeyModel.stub()
        performKeyModelRequest(expectedKeyModel: keyModel, url: url) { (completion) in
            keyService.getKeyViaLongSecret(longSecret: keyModel.longSecret!, keyId: keyModel.keyId, completion: completion)
        }
    }

    @available(iOS 13, *)
    func testGetKeyViaLongSecretPublisher() {
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/key")
        let keyModel = TIMKeyModel.stub()
        performKeyModelPublisher(keyService.getKeyViaLongSecret(longSecret: keyModel.longSecret!, keyId: keyModel.keyId), expectedKeyModel: keyModel, url: url)
    }

    func testUnknownStatusCode() {
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/key")
        let keyModel = TIMKeyModel.stub()
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
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/key")
        let keyModel = TIMKeyModel.stub()
        URLSessionStubResults.resultsForUrls[url] = .dataResponse(
            data: "NotJson".data(using: .utf8)!,
            response: HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let expectation = XCTestExpectation()
        keyService.getKey(secret: "1234", keyId: keyModel.keyId) { (result) in
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
        let url = Self.baseUrl.appendingPathComponent("keyservice/v1/key")
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

    private func performKeyModelRequest(expectedKeyModel: TIMKeyModel, url: URL, performRequest: (@escaping (Result<TIMKeyModel, TIMKeyServiceError>) -> Void) -> Void) {
        let keyModel = TIMKeyModel.stub()
        let jsonData = try! JSONEncoder().encode(keyModel)
        URLSessionStubResults.resultsForUrls[url] = URLSessionStubResult.dataResponse(
            data: jsonData,
            response: HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
        let expect = XCTestExpectation(description: "CreateKey should have returned.")
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
    private func performKeyModelPublisher(_ publisher: Future<TIMKeyModel, TIMKeyServiceError>, expectedKeyModel: TIMKeyModel, url: URL) {
        let jsonData = try! JSONEncoder().encode(expectedKeyModel)
        URLSessionStubResults.resultsForUrls[url] = URLSessionStubResult.dataResponse(
            data: jsonData,
            response: HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )

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

extension TIMKeyModel: Equatable {
    public static func == (lhs: TIMKeyModel, rhs: TIMKeyModel) -> Bool {
        return lhs.key == rhs.key && lhs.keyId == rhs.keyId && lhs.longSecret == rhs.longSecret
    }

    static func stub() -> TIMKeyModel {
        let keyId = UUID().uuidString
        let encryptionKey = "abcdefghlmnopqrstuwvxyz"
        let longSecret = String(encryptionKey.reversed())

        return TIMKeyModel(keyId: keyId, key: encryptionKey, longSecret: longSecret)
    }
}
