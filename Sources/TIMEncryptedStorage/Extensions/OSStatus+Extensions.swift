import Foundation
import Security

extension OSStatus {

    /// It would have been preferable to use `CustomStringConvertible`, but `OSStatus` is just an typealias for `Int32`, which already implemented that protocol.
    var errorDescription: String {
        let codeString: String = Int(exactly: self)?.description ?? "nil"
        let codeMessage: String
        if #available(iOS 11.3, *) {
            let osStatusString = (SecCopyErrorMessageString(self, nil) as NSString?) as String?
            codeMessage = osStatusString ?? "-"
        } else {
            codeMessage = "- (not available below iOS 11.3)"
        }
        return "[\(codeString)]: \(codeMessage)"
    }
}
