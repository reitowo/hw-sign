import Foundation
import LocalAuthentication
import Security

class KeyManager {
  static let shared = KeyManager()
  private let tagPrefix = "fan.ovo.hwsign"

  enum KeyType: String {
    case hardware = "hardware"
    case acceleration = "acceleration"
  }

  private init() {}

  // MARK: - Key Management

  func createKey(_ type: KeyType, forceNew: Bool = false) throws -> SecKey {
    let tag = "\(tagPrefix).\(type.rawValue)"

    // Always attempt to delete an existing key with the same tag to avoid conflicts
    try? deleteKey(type)

    let flags: SecAccessControlCreateFlags = [.privateKeyUsage]

    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      flags,
      nil
    )!

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrAccessControl as String: access,
        kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
      ],
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw error!.takeRetainedValue() as Error
    }

    return privateKey
  }

  func loadKey(_ type: KeyType) throws -> SecKey {
    let tag = "\(tagPrefix).\(type.rawValue)"

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    guard status == errSecSuccess else {
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }

    // Fix: Use proper type safety pattern instead of direct force casting
    guard let key = item else {
      throw NSError(
        domain: "KeyManager", code: -1,
        userInfo: [NSLocalizedDescriptionKey: "Retrieved key is nil"])
    }

    return (key as! SecKey)  // This cast is safe because SecItemCopyMatching guarantees a SecKey when using kSecReturnRef
  }

  func deleteKey(_ type: KeyType) throws {
    let tag = "\(tagPrefix).\(type.rawValue)"

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
    ]

    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
  }

  // MARK: - Signing Operations

  func sign(data: Data, with key: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard
      let signature = SecKeyCreateSignature(
        key,
        .ecdsaSignatureMessageX962SHA256,
        data as CFData,
        &error
      ) as Data?
    else {
      throw error!.takeRetainedValue() as Error
    }
    return signature
  }

  func getPublicKey(for privateKey: SecKey) -> SecKey? {
    return SecKeyCopyPublicKey(privateKey)
  }

  func exportPublicKey(_ key: SecKey) throws -> Data {
    // This encodes ec public to x962
    var error: Unmanaged<CFError>?
    guard let exportedKey = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
      throw error!.takeRetainedValue() as Error
    }

    return exportedKey
  }

  // MARK: - Token Management

  func storeAuthToken(_ token: String) {
    UserDefaults.standard.set(token, forKey: "\(tagPrefix).authToken")
  }

  func getAuthToken() -> String? {
    return UserDefaults.standard.string(forKey: "\(tagPrefix).authToken")
  }

  func deleteAuthToken() {
    UserDefaults.standard.removeObject(forKey: "\(tagPrefix).authToken")
  }

  func storeAccelKeyId(_ keyId: String) {
    UserDefaults.standard.set(keyId, forKey: "\(tagPrefix).accelKeyId")
  }

  func getAccelKeyId() -> String? {
    return UserDefaults.standard.string(forKey: "\(tagPrefix).accelKeyId")
  }

  func deleteAccelKeyId() {
    UserDefaults.standard.removeObject(forKey: "\(tagPrefix).accelKeyId")
  }
}
