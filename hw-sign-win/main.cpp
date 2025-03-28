#include <windows.h>
#include <string>
#include <cpr/cpr.h>

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

void sendRequest(const std::string& endpoint, const std::string& jsonPayload) {
    auto response = cpr::Post(cpr::Url{"https://dbcs-api.reito.fun" + endpoint},
                              cpr::Body{jsonPayload},
                              cpr::Header{{"Content-Type", "application/json"}});

    if (response.status_code == 200) {
        MessageBoxA(NULL, response.text.c_str(), "Response", MB_OK);
    } else {
        MessageBoxA(NULL, ("Request failed with status code: " + std::to_string(response.status_code)).c_str(), "Error", MB_OK);
    }
}

void checkAuthentication() {
    auto response = cpr::Get(cpr::Url{"https://dbcs-api.reito.fun/authenticated"});

    if (response.status_code == 200) {
        MessageBoxA(NULL, response.text.c_str(), "Authentication Status", MB_OK);
    } else {
        MessageBoxA(NULL, ("Request failed with status code: " + std::to_string(response.status_code)).c_str(), "Error", MB_OK);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "Sample Window Class";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        "User Authentication",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 200,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (hwnd == NULL) {
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hUsername, hPassword, hRegister, hLogin, hCheckAuth;

    switch (uMsg) {
    case WM_CREATE:
        CreateWindow("STATIC", "Username:", WS_VISIBLE | WS_CHILD, 10, 10, 80, 20, hwnd, NULL, NULL, NULL);
        hUsername = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 10, 150, 20, hwnd, NULL, NULL, NULL);

        CreateWindow("STATIC", "Password:", WS_VISIBLE | WS_CHILD, 10, 40, 80, 20, hwnd, NULL, NULL, NULL);
        hPassword = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD, 100, 40, 150, 20, hwnd, NULL, NULL, NULL);

        hRegister = CreateWindow("BUTTON", "Register", WS_VISIBLE | WS_CHILD, 10, 80, 100, 30, hwnd, (HMENU)1, NULL, NULL);
        hLogin = CreateWindow("BUTTON", "Login", WS_VISIBLE | WS_CHILD, 120, 80, 100, 30, hwnd, (HMENU)2, NULL, NULL);
        hCheckAuth = CreateWindow("BUTTON", "Check Auth", WS_VISIBLE | WS_CHILD, 10, 120, 210, 30, hwnd, (HMENU)3, NULL, NULL);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) { // Register button
            char username[100], password[100];
            GetWindowText(hUsername, username, 100);
            GetWindowText(hPassword, password, 100);

            std::string payload = "{\"username\":\"" + std::string(username) + "\",\"password\":\"" + std::string(password) + "\"}";
            sendRequest("/register", payload);
        } else if (LOWORD(wParam) == 2) { // Login button
            char username[100], password[100];
            GetWindowText(hUsername, username, 100);
            GetWindowText(hPassword, password, 100);

            std::string payload = "{\"username\":\"" + std::string(username) + "\",\"password\":\"" + std::string(password) + "\"}";
            sendRequest("/login", payload);
        } else if (LOWORD(wParam) == 3) { // Check Auth button
            checkAuthentication();
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}