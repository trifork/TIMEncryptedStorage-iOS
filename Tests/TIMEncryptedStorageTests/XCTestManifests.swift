import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(KeychainStoreItemTests.allTests),
        testCase(TIMKeyServiceTests.allTests),
    ]
}
#endif
