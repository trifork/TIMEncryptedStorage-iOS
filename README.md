# Trifork Identity Manager Encrypted Storage iOS

`TIMEncryptedStorage` is a standalone framework designed for [Trifork Identity Manager](http://identitymanager.trifork.com/) as a encrypted storage handler. .

This framework handles communication with the Trifork Identity Manager KeyService and stores/fetches encrypted/decrypted data from the iOS Keychain. Furthermore, it handles biometric access to data by a long secret from the key service

It is a crucial part of the [TIM-iOS](https://github.com/trifork/TIM-iOS) package, which is full blown Trifork Identity Manager framework, which also handles OpenID Connect operations, access and refresh tokens.

## Setup

### Installation

Add this repo to your SPM 📦

https://github.com/trifork/TIMEncryptedStorage-iOS

### Setup configuration
Before using any function from `TIMEncryptedStorage` you have to configure the framework by calling the `configure` method (typically you want to do this on app startup):

```swift
import TIMEncryptedStorage // Required for TIMKeyServiceConfiguration

let config = TIMKeyServiceConfiguration(
    realmBaseUrl: "<TIM Keyservice URL>",
    version: .v1
)
TIMEncryptedStorage.configure(keyServiceConfiguration: config)
```

## Common use cases

The following exampes uses `TIMEncryptedStorage`'s `Combine` interface, which returns `Future` classes. If you are developing an app with a deployment target lower than iOS 13, the same interfaces exists with completion closures instead (those are deprecated from iOS 13 though).

### Store data encrypted with new key
```swift
// Store data encrypted for the first time with a new secret "1234"
let myRawData = Data("someData".utf8)
TIMEncryptedStorage.storeWithNewKey(id: "my-id", data: myRawData, secret: "1234")
    .sink { (_) in } receiveValue: { (result) in
        print("Key created with id: \(result.keyId)")
        print("Key created with longSecret: \(result.longSecret)")
    }
    .store(in: &myStore)
```

**Note:** You don't have to create a new key for every item you save. Once created, the same key can be used to encrypt multiple types of data (if you will allow the same secret to unlock it). Use the `TIMEncryptedStorage.store(id:data:keyId:secret:)` to achieve that.

### Load and decrypt data
```swift
let keyId = "<keyId from store with newKey>"
TIMEncryptedStorage.get(id: "my-id", keyId: keyId, secret: "1234")
    .sink { (_) in } receiveValue: { (data) in
        let string = String(data: data, encoding: .utf8)
        print("Loaded data from \(keyId): \(string)")
    }
    .store(in: &myStore)
```

---

![Trifork Logo](https://jira.trifork.com/s/-p6q4kx/804003/9c3efa9da3fa1ef9d504f68de6c57528/_/jira-logo-scaled.png)
