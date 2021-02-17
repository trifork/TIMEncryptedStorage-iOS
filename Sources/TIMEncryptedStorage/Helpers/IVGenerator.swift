import Foundation
import CommonCrypto

final class IVGenerator {

    static var ivSize: Int {
        kCCBlockSizeAES128
    }

    static func randomIv() -> Data {
        return randomData(length: ivSize)
    }

    static private func randomData(length: Int) -> Data {
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { mutableBytes in
            SecRandomCopyBytes(kSecRandomDefault, length, mutableBytes.baseAddress!)
        }
        assert(status == Int32(0))
        return data
    }
}

