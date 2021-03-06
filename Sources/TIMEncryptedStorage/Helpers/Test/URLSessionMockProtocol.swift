import Foundation

@objc class URLSessionMockProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool {
        return true
    }

    override class func canInit(with task: URLSessionTask) -> Bool {
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override func startLoading() {
        if let results = URLSessionStubResults.resultsForUrls[request.url] {
            if let data = results.data {
                self.client?.urlProtocol(self, didLoad: data)
            }

            if let response = results.response {
                self.client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            }

            if let error = results.error {
                self.client?.urlProtocol(self, didFailWithError: error)
            }
        }

        self.client?.urlProtocolDidFinishLoading(self)
    }

    // This method is required, but we doesn't need to do anything
    override func stopLoading() {

    }
}

/// Contains the stub results for URLs
struct URLSessionStubResults {
    /// Contains stub results for specific URLs, which will be used when mocking `URLSession` via `URLSessionMockProtocol`
    public static var resultsForUrls: [URL?: URLSessionStubResult] = [:]

    /// Resets the stub storage
    public static func reset() {
        resultsForUrls.removeAll()
    }

    public static func setKeyModel(baseUrl: String, endpoint: TIMKeyServiceEndpoints, keyModel: TIMKeyModel) {
        guard let bUrl = URL(string: baseUrl) else {
            print("Failed to set key model for base url.")
            return
        }
        let url = bUrl.appendingPathComponent("keyservice/v1/\(endpoint.urlPath)")
        URLSessionStubResults.resultsForUrls[url] = .dataResponse(
            data: try! JSONEncoder().encode(keyModel),
            response: HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        )
    }
}

/// Stub results for `URLSession` mocking via `URLSessionMockProtocol`
struct URLSessionStubResult {
    let response: URLResponse?
    let error: NSError?
    let data: Data?

    /// Private init to make sure that we don't create unrealistic setups
    private init(response: URLResponse?, error: NSError?, data: Data?) {
        self.response = response
        self.error = error
        self.data = data
    }

    /// Stub for successful networkRequest with response and data
    static func dataResponse(data: Data, response: URLResponse) -> URLSessionStubResult {
        URLSessionStubResult(
            response: response,
            error: nil,
            data: data
        )
    }

    /// Creates stub for failing network request, e.g. network problems.
    static func error(error: NSError) -> URLSessionStubResult {
        URLSessionStubResult(
            response: nil,
            error: error,
            data: nil
        )
    }
}
