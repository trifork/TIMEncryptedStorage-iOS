import Foundation
import CommonCrypto

/// Generates randomly secure IV's
final class IVGenerator {

    /// The size of the IV
    static var ivSize: Int {
        kCCBlockSizeAES128
    }

    /// Returns a random IV of `ivSize`
    static func randomIv() -> Data {
        return randomData(length: ivSize)
    }

    /// Generates secure random data.
    static private func randomData(length: Int) -> Data {
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { mutableBytes in
            SecRandomCopyBytes(kSecRandomDefault, length, mutableBytes.baseAddress!)
        }
        assert(status == Int32(0))
        return data
    }
}

