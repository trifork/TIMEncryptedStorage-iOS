import Foundation

/// Represents an item in a secure storage item
public protocol TIMSecureStorageItem {
    /// The id of the item
    var id: String { get }

    /// Constructor with storage identifier
    /// - Parameter id: The identifier used to store the item with.
    init(id: String)
}
