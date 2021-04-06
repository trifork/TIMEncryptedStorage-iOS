import Foundation

/// This protocol defines a secure store for data.
///
/// The default implementation the secure store is `TIMKeychain`.
public protocol TIMSecureStorage {
    /// The desired identification method of secure stored items.
    associatedtype SecureStorageItem: TIMSecureStorageItem

    /// Removes `SecureStoreItem` from the secure storage.
    /// - Parameter item: The item to remove.
    func remove(item: SecureStorageItem)

    /// Saves data for an `SecureStoreItem` in the secure storage.
    /// - Parameters:
    ///   - data: Data to save.
    ///   - item: The item to identify the data.
    /// - Returns: Result indicating whether it was a success or not.
    func store(data: Data, item: SecureStorageItem) -> Result<Void, TIMSecureStorageError>

    /// Saves data in the secure store with biometric protection (meaning that only TouchID or FaceID can unlock the access to the data)
    /// - Parameters:
    ///   - data: Data to save.
    ///   - item: The item to identify the data.
    /// - Returns: Result indicating whether it was a success or not.
    func storeBiometricProtected(data: Data, item: SecureStorageItem) -> Result<Void, TIMSecureStorageError>

    /// Gets data from the secure storage.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: If there is data for the specified item, it will return the Data object, otherwise a failing result with a matching error
    func get(item: SecureStorageItem) -> Result<Data, TIMSecureStorageError>

    /// Gets biometric protected data from the secure storage - this will prompt the user for biometric verification.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: If there is data for the specified item, it will return the Data object, otherwise `nil`
    func getBiometricProtected(item: SecureStorageItem) -> Result<Data, TIMSecureStorageError>

    /// Checks whether an item exists in the secure storage or not.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: `true` if the item exists, otherwise `false`
    func hasValue(item: SecureStorageItem) -> Bool

    /// Checks whether an item exists with biometric protection in the secure storage or not.
    /// - Parameter item: The item that identifies the data (and which is was saved with)
    /// - Returns: `true` if the item exists, otherwise `false`
    func hasBiometricProtectedValue(item: SecureStorageItem) -> Bool
}
