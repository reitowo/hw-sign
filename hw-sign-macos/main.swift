import Foundation
import Security

func generateKeyPair() {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeEC,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: "com.example.hw-sign-macos.key"
        ]
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        print("Error generating key pair: \(error!.takeRetainedValue() as Error)")
        return
    }

    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        print("Error retrieving public key")
        return
    }

    print("Key pair generated successfully!")
    print("Public Key: \(publicKey)")
}

// Entry point
print("Generating key pair...")
generateKeyPair()