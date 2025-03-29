import SwiftUI

struct ContentView: View {
    @State private var username = ""
    @State private var password = ""
    @State private var message = ""

    var body: some View {
        VStack(spacing: 20) {
            Text("User Authentication")
                .font(.largeTitle)
                .padding()

            TextField("Username", text: $username)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()

            SecureField("Password", text: $password)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()

            Button("Register") {
                handleRequest(endpoint: "/register", payload: ["username": username, "password": password])
            }
            .buttonStyle(.borderedProminent)

            Button("Login") {
                handleRequest(endpoint: "/login", payload: ["username": username, "password": password])
            }
            .buttonStyle(.borderedProminent)

            Button("Check Auth") {
                handleRequest(endpoint: "/authenticated", isGet: true)
            }
            .buttonStyle(.borderedProminent)

            Text(message)
                .foregroundColor(.red)
                .padding()
        }
        .padding()
        #if os(macOS)
        .frame(minWidth: 400, minHeight: 400)
        #endif
    }

    func handleRequest(endpoint: String, payload: [String: Any] = [:], isGet: Bool = false) {
        guard let url = URL(string: "https://dbcs-api.reito.fun" + endpoint) else {
            message = "Invalid URL"
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = isGet ? "GET" : "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if !isGet {
            do {
                request.httpBody = try JSONSerialization.data(withJSONObject: payload, options: [])
            } catch {
                message = "Error serializing JSON: \(error)"
                return
            }
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                DispatchQueue.main.async {
                    message = "Request failed: \(error)"
                }
                return
            }

            guard let data = data else {
                DispatchQueue.main.async {
                    message = "No data received"
                }
                return
            }

            if let responseString = String(data: data, encoding: .utf8) {
                DispatchQueue.main.async {
                    message = responseString
                }
            }
        }.resume()
    }
}

@main
struct MyApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}