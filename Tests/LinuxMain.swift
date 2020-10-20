import XCTest

import TIMEncryptedStorageTests

var tests = [XCTestCaseEntry]()
tests += KeychainStoreItemTests.allTests()
tests += TIMKeyServiceTests.allTests()
XCTMain(tests)
