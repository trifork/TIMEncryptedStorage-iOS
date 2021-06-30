@testable import TIMEncryptedStorage
import XCTest
import Security

final class OSStatusExtensionsTests: XCTestCase {
    func testErrorDescription() {
        let status: OSStatus = errSecCreateChainFailed
        let expectedString = "[-25318]: One or more certificates required to validate this certificate cannot be found."
        XCTAssertEqual(expectedString, status.errorDescription)

        let status2: OSStatus = errSecInteractionRequired
        let expectedString2 = "[-25315]: User interaction is required, but is currently not allowed."
        XCTAssertEqual(expectedString2, status2.errorDescription)
    }
}
