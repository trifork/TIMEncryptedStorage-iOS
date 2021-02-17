import Foundation

public enum TIMESEncryptionMethod {
    @available(iOS 13, *)
    case aesGcm

    @available(iOS, deprecated: 13)
    case aesPkcs7
}
