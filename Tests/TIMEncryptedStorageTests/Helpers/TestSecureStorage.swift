import Foundation
import TIMEncryptedStorage

struct TestSecureStorageItem: TIMSecureStorageItem {
    var id: String
    private (set) var isBioProtected: Bool = false

    init(id: String) {
        self.id = id
    }

    mutating func enableBioProtection() {
        isBioProtected = true
    }
}

final class TestSecureStorage : TIMSecureStorage {
    private var bioProtectedData: [StorageID: Data] = [:]
    private var protectedData: [StorageID: Data] = [:]

    func getBiometricProtected(item: TestSecureStorageItem) -> Result<Data, TIMSecureStorageError> {
        var mutableItem = item
        mutableItem.enableBioProtection()
        return get(item: mutableItem)
    }

    func get(item: TestSecureStorageItem) -> Result<Data, TIMSecureStorageError> {
        if item.isBioProtected {
            if let data = bioProtectedData[item.id] {
                return .success(data)
            } else {
                return .failure(.failedToLoadData)
            }
        } else {
            if let data = protectedData[item.id] {
                return .success(data)
            } else {
                return .failure(.failedToLoadData)
            }
        }
    }

    func hasBiometricProtectedValue(item: TestSecureStorageItem) -> Bool {
        bioProtectedData[item.id] != nil
    }

    func store(data: Data, item: TestSecureStorageItem) -> Result<Void, TIMSecureStorageError> {
        if item.isBioProtected {
            bioProtectedData[item.id] = data
        } else {
            protectedData[item.id] = data
        }
        return .success(Void())
    }

    func storeBiometricProtected(data: Data, item: TestSecureStorageItem) -> Result<Void, TIMSecureStorageError> {
        var mutableItem = item
        mutableItem.enableBioProtection()
        return store(data: data, item: mutableItem)
    }

    func remove(item: TestSecureStorageItem) {
        bioProtectedData.removeValue(forKey: item.id)
        protectedData.removeValue(forKey: item.id)
    }

    func hasValue(item: TestSecureStorageItem) -> Bool {
        protectedData[item.id] != nil || bioProtectedData[item.id] != nil
    }

    func reset() {
        protectedData.removeAll()
        bioProtectedData.removeAll()
    }
}
