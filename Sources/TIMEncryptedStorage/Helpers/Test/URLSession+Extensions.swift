import Foundation

extension URLSession {
    /// Creates a `URLSession` which mocks all requests with results provided via `URLSessionStubResults`
    public static var mockSession: URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLSessionMockProtocol.self]
        return URLSession(configuration: config)
    }
}
