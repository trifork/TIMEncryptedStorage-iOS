import XCTest
@testable import TIMEncryptedStorage

final class IVGeneratorTests: XCTestCase {
    func testRandomIV() {
        let iv = IVGenerator.randomIv()
        XCTAssertEqual(iv.count, IVGenerator.ivSize)
    }
}

