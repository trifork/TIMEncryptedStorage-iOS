import XCTest
@testable import TIMEncryptedStorage

final class TIMKeyServiceErrorTests: XCTestCase {

    override class func setUp() {
        super.setUp()

    }

    func testMapKeyServiceErrorFromCode() {
        XCTAssertEqual(
            TIMKeyServiceError.potentiallyNoInternet,
            mapKeyServiceError(withCode: -1009, errorDescription: nil)
        )

        XCTAssertEqual(
            TIMKeyServiceError.badInternet,
            mapKeyServiceError(withCode: -1234, errorDescription: nil)
        )

        XCTAssertEqual(
            TIMKeyServiceError.badPassword,
            mapKeyServiceError(withCode: 401, errorDescription: nil)
        )

        XCTAssertEqual(
            TIMKeyServiceError.keyLocked,
            mapKeyServiceError(withCode: 204, errorDescription: nil)
        )

        XCTAssertEqual(
            TIMKeyServiceError.keyLocked,
            mapKeyServiceError(withCode: 403, errorDescription: nil)
        )

        XCTAssertEqual(
            TIMKeyServiceError.keyMissing,
            mapKeyServiceError(withCode: 404, errorDescription: nil)
        )

        XCTAssertEqual(
            TIMKeyServiceError.unableToCreateKey,
            mapKeyServiceError(withCode: 500, errorDescription: nil)
        )

        XCTAssertEqual(
            TIMKeyServiceError.unknown(600, nil),
            mapKeyServiceError(withCode: 600, errorDescription: nil)
        )

        XCTAssertEqual(
            TIMKeyServiceError.unknown(1234, "test"),
            mapKeyServiceError(withCode: 1234, errorDescription: "test")
        )
    }

    func testMapKeyServiceErrorFromError() {
        XCTAssertEqual(
            TIMKeyServiceError.potentiallyNoInternet,
            mapKeyServiceError(NSError(domain: "test", code: -1009, userInfo: nil))
        )

        XCTAssertEqual(
            TIMKeyServiceError.keyMissing,
            mapKeyServiceError(NSError(domain: "test", code: 404, userInfo: nil))
        )

        XCTAssertEqual(
            TIMKeyServiceError.unknown(1111, "The operation couldn’t be completed. (test error 1111.)"),
            mapKeyServiceError(NSError(domain: "test", code: 1111, userInfo: nil))
        )
    }
}
