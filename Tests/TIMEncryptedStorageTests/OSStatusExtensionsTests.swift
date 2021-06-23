@testable import TIMEncryptedStorage
import XCTest
import Security

final class OSStatusExtensionsTests: XCTestCase {
    func testErrorDescription() {
        let status: OSStatus = errSecCreateChainFailed
        let expectedString = "[-25318]: A required component (data storage module) could not be loaded. You may need to restart your computer."
        XCTAssertEqual(expectedString, status.errorDescription)
    }
}
