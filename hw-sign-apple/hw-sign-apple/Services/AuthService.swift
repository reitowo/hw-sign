import Combine
import Foundation
import Security

class AuthService {
  static let shared = AuthService()
  private let baseURL = URL(string: "https://dbcs-api.ovo.fan")!
  // private let baseURL = URL(string: "http://127.0.0.1:28280")!
  private let keyManager = KeyManager.shared
  private var cancellables = Set<AnyCancellable>()

  private init() {}

  // MARK: - Authentication Flow

  func register(username: String, password: String) -> AnyPublisher<String, Error> {
    let body = ["username": username, "password": password]
    return makeRequest("register", method: "POST", body: body, responseType: EmptyResponse.self)
      .map { _ in "Registration successful!" }
      .eraseToAnyPublisher()
  }

  func login(username: String, password: String) -> AnyPublisher<String, Error> {
    return Future { [weak self] promise in
      guard let self = self else {
        promise(
          .failure(
            NSError(
              domain: "AuthService", code: -1,
              userInfo: [NSLocalizedDescriptionKey: "Service unavailable"])))
        return
      }

      do {
        // Create new hardware key for this session
        let hwKey = try self.keyManager.createKey(.hardware, forceNew: true)
        guard let hwPubKey = self.keyManager.getPublicKey(for: hwKey) else {
          throw NSError(
            domain: "AuthService", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "Failed to get public key"])
        }

        let hwPubKeyData = try self.keyManager.exportPublicKey(hwPubKey)
        let hwPubKeyBase64 = hwPubKeyData.base64EncodedString()

        // Make login request with hardware key
        let body = ["username": username, "password": password]
        var request = try self.createRequest("login", method: "POST", body: body)
        request.setValue(hwPubKeyBase64, forHTTPHeaderField: "x-rpc-sec-dbcs-hw-pub")
        request.setValue("ecdsa", forHTTPHeaderField: "x-rpc-sec-dbcs-hw-pub-type")  // Always use ECDSA

        URLSession.shared.dataTaskPublisher(for: request)
          .tryMap { data, response -> Data in
            guard let httpResponse = response as? HTTPURLResponse else {
              throw NSError(
                domain: "AuthService", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Invalid response type"])
            }

            if !(200...299).contains(httpResponse.statusCode) {
              throw NSError(
                domain: "AuthService", code: httpResponse.statusCode,
                userInfo: [NSLocalizedDescriptionKey: "Server error: \(httpResponse.statusCode)"])
            }

            return data
          }
          .decode(type: LoginResponse.self, decoder: JSONDecoder())
          .receive(on: DispatchQueue.main)
          .sink(
            receiveCompletion: { completion in
              if case let .failure(error) = completion {
                promise(.failure(error))
              }
            },
            receiveValue: { response in
              self.keyManager.storeAuthToken(response.token)
              promise(.success("Login successful!"))
            }
          )
          .store(in: &self.cancellables)

      } catch {
        promise(.failure(error))
      }
    }.eraseToAnyPublisher()
  }

  func checkAuthentication() -> AnyPublisher<String, Error> {
    return authenticatedRequest("authenticated", method: "GET", responseType: AuthResponse.self)
      .map { _ in "Authentication verified with hardware security!" }
      .eraseToAnyPublisher()
  }

  func logout() {
    try? keyManager.deleteKey(.hardware)
    try? keyManager.deleteKey(.acceleration)
    keyManager.deleteAuthToken()
    keyManager.deleteAccelKeyId()
  }

  // MARK: - Request Helpers

  private func makeRequest<T: Codable>(
    _ path: String, method: String, body: [String: Any]? = nil, responseType: T.Type
  ) -> AnyPublisher<T, Error> {
    return Future { [weak self] promise in
      guard let self = self else {
        promise(
          .failure(
            NSError(
              domain: "AuthService", code: -1,
              userInfo: [NSLocalizedDescriptionKey: "Service unavailable"])))
        return
      }

      do {
        let request = try self.createRequest(path, method: method, body: body)

        URLSession.shared.dataTaskPublisher(for: request)
          .tryMap { data, response -> Data in
            guard let httpResponse = response as? HTTPURLResponse else {
              throw NSError(
                domain: "AuthService", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Invalid response type"])
            }

            if !(200...299).contains(httpResponse.statusCode) {
              throw NSError(
                domain: "AuthService", code: httpResponse.statusCode,
                userInfo: [NSLocalizedDescriptionKey: "Server error: \(httpResponse.statusCode)"])
            }

            return data
          }
          .decode(type: T.self, decoder: JSONDecoder())
          .receive(on: DispatchQueue.main)
          .sink(
            receiveCompletion: { completion in
              if case let .failure(error) = completion {
                promise(.failure(error))
              }
            },
            receiveValue: { response in
              promise(.success(response))
            }
          )
          .store(in: &self.cancellables)
      } catch {
        promise(.failure(error))
      }
    }.eraseToAnyPublisher()
  }

  private func authenticatedRequest<T: Codable>(
    _ path: String, method: String, responseType: T.Type, body: [String: Any]? = nil
  ) -> AnyPublisher<T, Error> {
    return Future { [weak self] promise in
      guard let self = self else {
        promise(
          .failure(
            NSError(
              domain: "AuthService", code: -1,
              userInfo: [NSLocalizedDescriptionKey: "Service unavailable"])))
        return
      }

      do {
        let timestamp = String(Int(Date().timeIntervalSince1970))
        let accelKeyId = self.keyManager.getAccelKeyId()

        var request = try self.createRequest(path, method: method, body: body)
        request.setValue(
          "Bearer \(self.keyManager.getAuthToken() ?? "")", forHTTPHeaderField: "Authorization")
        request.setValue(timestamp, forHTTPHeaderField: "x-rpc-sec-dbcs-data")

        if let accelKeyId = accelKeyId {
          // Use existing acceleration key
          let accelKey = try self.keyManager.loadKey(.acceleration)
          let signature = try self.keyManager.sign(
            data: timestamp.data(using: .utf8)!, with: accelKey)

          request.setValue(
            signature.base64EncodedString(), forHTTPHeaderField: "x-rpc-sec-dbcs-data-sig")
          request.setValue(accelKeyId, forHTTPHeaderField: "x-rpc-sec-dbcs-accel-pub-id")
        } else {
          // Create new acceleration key
          let accelKey = try self.keyManager.createKey(.acceleration)
          guard let accelPubKey = self.keyManager.getPublicKey(for: accelKey) else {
            throw NSError(
              domain: "AuthService", code: -1,
              userInfo: [NSLocalizedDescriptionKey: "Failed to get acceleration public key"])
          }

          let accelPubKeyData = try self.keyManager.exportPublicKey(accelPubKey)
          let accelPubKeyBase64 = accelPubKeyData.base64EncodedString()

          // Sign acceleration key with hardware key
          let hwKey = try self.keyManager.loadKey(.hardware)
          let accelKeySig = try self.keyManager.sign(
            data: accelPubKeyBase64.data(using: .utf8)!, with: hwKey)

          let signature = try self.keyManager.sign(
            data: timestamp.data(using: .utf8)!, with: accelKey)

          request.setValue(accelPubKeyBase64, forHTTPHeaderField: "x-rpc-sec-dbcs-accel-pub")
          request.setValue("ecdsa", forHTTPHeaderField: "x-rpc-sec-dbcs-accel-pub-type")  // Always use ECDSA
          request.setValue(
            accelKeySig.base64EncodedString(), forHTTPHeaderField: "x-rpc-sec-dbcs-accel-pub-sig")
          request.setValue(
            signature.base64EncodedString(), forHTTPHeaderField: "x-rpc-sec-dbcs-data-sig")
        }

        URLSession.shared.dataTaskPublisher(for: request)
          .tryMap { data, response -> Data in
            guard let httpResponse = response as? HTTPURLResponse else {
              throw NSError(
                domain: "AuthService", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Invalid response type"])
            }

            if let accelKeyId = httpResponse.value(
              forHTTPHeaderField: "x-rpc-sec-dbcs-accel-pub-id")
            {
              self.keyManager.storeAccelKeyId(accelKeyId)
            }

            if !(200...299).contains(httpResponse.statusCode) {
              throw NSError(
                domain: "AuthService", code: httpResponse.statusCode,
                userInfo: [NSLocalizedDescriptionKey: "Server error: \(httpResponse.statusCode)"])
            }

            return data
          }
          .decode(type: T.self, decoder: JSONDecoder())
          .receive(on: DispatchQueue.main)
          .sink(
            receiveCompletion: { completion in
              if case let .failure(error) = completion {
                promise(.failure(error))
              }
            },
            receiveValue: { response in
              promise(.success(response))
            }
          )
          .store(in: &self.cancellables)

      } catch {
        promise(.failure(error))
      }
    }.eraseToAnyPublisher()
  }

  private func createRequest(_ path: String, method: String, body: [String: Any]? = nil) throws
    -> URLRequest
  {
    var request = URLRequest(url: baseURL.appendingPathComponent(path))
    request.httpMethod = method
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")

    if let body = body {
      request.httpBody = try JSONSerialization.data(withJSONObject: body)
    }

    return request
  }
}

// MARK: - Response Models

struct LoginResponse: Codable {
  let token: String
}

struct AuthResponse: Codable {
  let authenticated: Bool
}

struct EmptyResponse: Codable {
  // Empty response structure for endpoints that don't return meaningful data
}
