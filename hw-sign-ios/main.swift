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
                sendRequest(endpoint: "/register", payload: ["username": username, "password": password])
            }
            .buttonStyle(.borderedProminent)

            Button("Login") {
                sendRequest(endpoint: "/login", payload: ["username": username, "password": password])
            }
            .buttonStyle(.borderedProminent)

            Button("Check Auth") {
                checkAuthentication()
            }
            .buttonStyle(.borderedProminent)

            Text(message)
                .foregroundColor(.red)
                .padding()
        }
        .padding()
    }

    func sendRequest(endpoint: String, payload: [String: Any]) {
        guard let url = URL(string: "https://dbcs-api.reito.fun" + endpoint) else {
            message = "Invalid URL"
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: payload, options: [])
        } catch {
            message = "Error serializing JSON: \(error)"
            return
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

    func checkAuthentication() {
        guard let url = URL(string: "https://dbcs-api.reito.fun/authenticated") else {
            message = "Invalid URL"
            return
        }

        URLSession.shared.dataTask(with: url) { data, response, error in
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