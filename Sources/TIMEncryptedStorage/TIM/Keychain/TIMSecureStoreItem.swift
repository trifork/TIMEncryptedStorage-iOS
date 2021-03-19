import Foundation

/// Represents an item in a secure store item
public protocol TIMSecureStoreItem {
    /// The id of the item
    var id: String { get }


    /// Constructor with storage identifier
    /// - Parameter id: The identifier used to store the item with.
    init(id: String)
}
