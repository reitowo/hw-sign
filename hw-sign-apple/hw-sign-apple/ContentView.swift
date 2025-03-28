import Combine
import SwiftUI

struct ContentView: View {
  @StateObject private var viewModel = AuthViewModel()
  @EnvironmentObject private var themeManager: ThemeManager

  var body: some View {
    VStack(spacing: 20) {
      Text("Hardware Secure Authentication")
        .font(.largeTitle)
        .fontWeight(.bold)
        .padding()
        .multilineTextAlignment(.center)

      if !viewModel.isAuthenticated {
        // Login/Registration Form
        loginForm
      } else {
        // Authenticated View
        authenticatedView
      }

      // Message display
      Text(viewModel.message)
        .foregroundColor(
          viewModel.message.contains("successful") || viewModel.message.contains("verified")
            ? .green : .red
        )
        .padding()
        .frame(minHeight: 60)

      Spacer()

      // Dark Mode Toggle
      Toggle("Dark Mode", isOn: $themeManager.isDarkMode)
        .padding(.horizontal)
    }
    .padding()
    .disabled(viewModel.isLoading)
  }

  private var loginForm: some View {
    Group {
      TextField("Username", text: $viewModel.username)
        .textFieldStyle(RoundedBorderTextFieldStyle())
        .disableAutocorrection(true)
        .padding(.horizontal)

      SecureField("Password", text: $viewModel.password)
        .textFieldStyle(RoundedBorderTextFieldStyle())
        .padding(.horizontal)

      HStack(spacing: 20) {
        Button("Register") {
          viewModel.handleRegister()
        }
        .buttonStyle(.borderedProminent)
        .disabled(viewModel.isLoading)

        Button("Login") {
          viewModel.handleLogin()
        }
        .buttonStyle(.borderedProminent)
        .disabled(viewModel.isLoading)
      }
    }
  }

  private var authenticatedView: some View {
    Group {
      Text("You are authenticated with hardware security!")
        .font(.headline)
        .foregroundColor(.green)
        .padding()

      Button("Check Authentication") {
        viewModel.checkAuthentication()
      }
      .buttonStyle(.borderedProminent)
      .disabled(viewModel.isLoading)

      Button("Logout") {
        viewModel.handleLogout()
      }
      .buttonStyle(.bordered)
      .foregroundColor(.red)
      .padding(.top)
      .disabled(viewModel.isLoading)
    }
  }
}

class AuthViewModel: ObservableObject {
  @Published var username = ""
  @Published var password = ""
  @Published var message = ""
  @Published var isAuthenticated = false
  @Published var isLoading = false

  private var cancellables = Set<AnyCancellable>()
  private let authService = AuthService.shared

  init() {
    // Check if user is already authenticated
    isAuthenticated = KeyManager.shared.getAuthToken() != nil
  }

  func handleRegister() {
    guard !username.isEmpty, !password.isEmpty else {
      message = "Username and password required"
      return
    }

    isLoading = true
    message = "Registering..."

    authService.register(username: username, password: password)
      .receive(on: DispatchQueue.main)
      .sink(
        receiveCompletion: { [weak self] completion in
          guard let self = self else { return }
          self.isLoading = false
          if case let .failure(error) = completion {
            self.message = "Registration failed: \(error.localizedDescription)"
          }
        },
        receiveValue: { [weak self] response in
          guard let self = self else { return }
          self.message = response
        }
      )
      .store(in: &cancellables)
  }

  func handleLogin() {
    guard !username.isEmpty, !password.isEmpty else {
      message = "Username and password required"
      return
    }

    isLoading = true
    message = "Logging in..."

    authService.login(username: username, password: password)
      .receive(on: DispatchQueue.main)
      .sink(
        receiveCompletion: { [weak self] completion in
          guard let self = self else { return }
          self.isLoading = false
          if case let .failure(error) = completion {
            self.message = "Login failed: \(error.localizedDescription)"
          }
        },
        receiveValue: { [weak self] response in
          guard let self = self else { return }
          self.isAuthenticated = true
          self.message = response
        }
      )
      .store(in: &cancellables)
  }

  func checkAuthentication() {
    isLoading = true
    message = "Checking authentication..."

    authService.checkAuthentication()
      .receive(on: DispatchQueue.main)
      .sink(
        receiveCompletion: { [weak self] completion in
          guard let self = self else { return }
          self.isLoading = false
          if case let .failure(error) = completion {
            self.message = "Authentication check failed: \(error.localizedDescription)"
          }
        },
        receiveValue: { [weak self] response in
          guard let self = self else { return }
          self.message = response
        }
      )
      .store(in: &cancellables)
  }

  func handleLogout() {
    authService.logout()
    isAuthenticated = false
    message = "Logged out successfully"
  }
}

#if DEBUG
  struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
      ContentView()
        .environmentObject(ThemeManager())
    }
  }
#endif
