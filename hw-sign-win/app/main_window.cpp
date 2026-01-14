#include "app/main_window.h"

#include <cstring>
#include <stdexcept>

MainWindow::MainWindow() : windowHandle_(nullptr), backgroundBrush_(nullptr) {}

MainWindow::~MainWindow() {
    if (backgroundBrush_) DeleteObject(backgroundBrush_);
}

LRESULT CALLBACK MainWindow::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    MainWindow* self = nullptr;
    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* create = reinterpret_cast<CREATESTRUCT*>(lParam);
        self = reinterpret_cast<MainWindow*>(create->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    if (self) return self->handleMessage(hwnd, uMsg, wParam, lParam);
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT MainWindow::handleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        backgroundBrush_ = CreateSolidBrush(BACKGROUND_COLOR);
        createControls(hwnd);
        return 0;

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLOREDIT:
        // Set the background color for all controls to match window
        SetBkColor((HDC)wParam, BACKGROUND_COLOR);
        return (LRESULT)backgroundBrush_;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case 1: // Login button
            onLogin();
            return 0;
        case 2: // Register button
            onRegister();
            return 0;
        case 3: // Logout button
            onLogout();
            return 0;
        case 4: // Check Auth button
            onCheckAuth();
            return 0;
        }
        break;

    case WM_DESTROY:
        DeleteObject(backgroundBrush_);
        backgroundBrush_ = nullptr;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void MainWindow::createControls(HWND hwnd) {
    // Create fonts with Chinese support (微软雅黑)
    HFONT hFont = CreateFontW(
        18,
        0,
        0,
        0,
        FW_NORMAL,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"微软雅黑"
    );

    // Create a smaller font for labels
    HFONT hLabelFont = CreateFontW(
        16,
        0,
        0,
        0,
        FW_NORMAL,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"微软雅黑"
    );

    // Center the controls in the window
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    int centerX = (clientRect.right - clientRect.left - 320) / 2;
    int startY = 30;

    // Create title with larger font
    HFONT hTitleFont = CreateFontW(
        24,
        0,
        0,
        0,
        FW_BOLD,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"微软雅黑"
    );

    HWND titleLabel = CreateWindowEx(
        0,
        "STATIC",
        "Hardware-Bound Authentication",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        centerX - 30,
        startY,
        380,
        30,
        hwnd,
        nullptr,
        nullptr,
        nullptr
    );
    SendMessage(titleLabel, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // Add subtitle with explanation
    HWND subtitleLabel = CreateWindowEx(
        0,
        "STATIC",
        "Login with hardware-protected security token",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        centerX,
        startY + 35,
        320,
        20,
        hwnd,
        nullptr,
        nullptr,
        nullptr
    );
    SendMessage(subtitleLabel, WM_SETFONT, (WPARAM)hLabelFont, TRUE);

    // Create username field with better spacing
    HWND usernameLabel = CreateWindowEx(
        0,
        "STATIC",
        "Username:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        centerX,
        startY + 75,
        80,
        20,
        hwnd,
        nullptr,
        nullptr,
        nullptr
    );
    SendMessage(usernameLabel, WM_SETFONT, (WPARAM)hLabelFont, TRUE);

    usernameEditHandle_ = CreateWindowEx(
        0,
        "EDIT",
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        centerX + 90,
        startY + 75,
        230,
        26,
        hwnd,
        nullptr,
        nullptr,
        nullptr
    );
    SendMessage(usernameEditHandle_, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Create password field
    HWND passwordLabel = CreateWindowEx(
        0,
        "STATIC",
        "Password:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        centerX,
        startY + 110,
        80,
        20,
        hwnd,
        nullptr,
        nullptr,
        nullptr
    );
    SendMessage(passwordLabel, WM_SETFONT, (WPARAM)hLabelFont, TRUE);

    passwordEditHandle_ = CreateWindowEx(
        0,
        "EDIT",
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
        centerX + 90,
        startY + 110,
        230,
        26,
        hwnd,
        nullptr,
        nullptr,
        nullptr
    );
    SendMessage(passwordEditHandle_, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Create buttons with modern style
    DWORD buttonStyle = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;
    int buttonWidth = 85;
    int buttonHeight = 32;
    int buttonSpacing = 5;
    int buttonsStartY = startY + 155;

    // Position buttons with better spacing
    loginButtonHandle_ = CreateWindowEx(
        0,
        "BUTTON",
        "Login",
        buttonStyle,
        centerX,
        buttonsStartY,
        buttonWidth,
        buttonHeight,
        hwnd,
        (HMENU)1,
        nullptr,
        nullptr
    );
    SendMessage(loginButtonHandle_, WM_SETFONT, (WPARAM)hFont, TRUE);

    registerButtonHandle_ = CreateWindowEx(
        0,
        "BUTTON",
        "Register",
        buttonStyle,
        centerX + buttonWidth + buttonSpacing,
        buttonsStartY,
        buttonWidth,
        buttonHeight,
        hwnd,
        (HMENU)2,
        nullptr,
        nullptr
    );
    SendMessage(registerButtonHandle_, WM_SETFONT, (WPARAM)hFont, TRUE);

    logoutButtonHandle_ = CreateWindowEx(
        0,
        "BUTTON",
        "Logout",
        buttonStyle,
        centerX + (buttonWidth + buttonSpacing) * 2,
        buttonsStartY,
        buttonWidth,
        buttonHeight,
        hwnd,
        (HMENU)3,
        nullptr,
        nullptr
    );
    SendMessage(logoutButtonHandle_, WM_SETFONT, (WPARAM)hFont, TRUE);

    checkAuthButtonHandle_ = CreateWindowEx(
        0,
        "BUTTON",
        "Check",
        buttonStyle,
        centerX + (buttonWidth + buttonSpacing) * 3,
        buttonsStartY,
        buttonWidth,
        buttonHeight,
        hwnd,
        (HMENU)4,
        nullptr,
        nullptr
    );
    SendMessage(checkAuthButtonHandle_, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Create status bar
    HWND statusBar = CreateWindowEx(
        0,
        "STATIC",
        "Ready",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        centerX,
        buttonsStartY + 50,
        320,
        20,
        hwnd,
        nullptr,
        nullptr,
        nullptr
    );
    SendMessage(statusBar, WM_SETFONT, (WPARAM)hLabelFont, TRUE);

    // Initially disable logout and check auth buttons
    EnableWindow(logoutButtonHandle_, FALSE);
    EnableWindow(checkAuthButtonHandle_, FALSE);
}

void MainWindow::onLogin() {
    char username[256], password[256];
    GetWindowText(usernameEditHandle_, username, 256);
    GetWindowText(passwordEditHandle_, password, 256);

    if (std::strlen(username) == 0 || std::strlen(password) == 0) {
        MessageBox(windowHandle_, "Please enter both username and password.", "Error", MB_OK | MB_ICONWARNING);
        return;
    }

    // Show loading cursor
    HCURSOR hOldCursor = SetCursor(LoadCursor(nullptr, IDC_WAIT));

    try {
        if (authService_.login(username, password)) {
            MessageBox(
                windowHandle_,
                "Login successful! Your session is now protected by hardware-bound authentication.",
                "Success",
                MB_OK | MB_ICONINFORMATION
            );
            // Enable/disable appropriate buttons
            EnableWindow(loginButtonHandle_, FALSE);
            EnableWindow(logoutButtonHandle_, TRUE);
            EnableWindow(checkAuthButtonHandle_, TRUE);
        }
    }
    catch (const std::exception& e) {
        MessageBox(windowHandle_, e.what(), "Login Failed", MB_OK | MB_ICONERROR);
    }

    // Restore cursor
    SetCursor(hOldCursor);
}

void MainWindow::onRegister() {
    char username[256], password[256];
    GetWindowText(usernameEditHandle_, username, 256);
    GetWindowText(passwordEditHandle_, password, 256);

    if (std::strlen(username) == 0 || std::strlen(password) == 0) {
        MessageBox(windowHandle_, "Please enter both username and password.", "Error", MB_OK | MB_ICONWARNING);
        return;
    }

    // Show loading cursor
    HCURSOR hOldCursor = SetCursor(LoadCursor(nullptr, IDC_WAIT));

    try {
        if (authService_.register_(username, password)) {
            MessageBox(windowHandle_, "Registration successful! You can now log in.", "Success",
                       MB_OK | MB_ICONINFORMATION);
        }
    }
    catch (const std::exception& e) {
        MessageBox(windowHandle_, e.what(), "Registration Failed", MB_OK | MB_ICONERROR);
    }

    // Restore cursor
    SetCursor(hOldCursor);
}

void MainWindow::onLogout() {
    authService_.logout();
    MessageBox(windowHandle_, "Logged out successfully!", "Success", MB_OK | MB_ICONINFORMATION);
    EnableWindow(loginButtonHandle_, TRUE);
    EnableWindow(logoutButtonHandle_, FALSE);
    EnableWindow(checkAuthButtonHandle_, FALSE);
}

void MainWindow::onCheckAuth() {
    if (authService_.isAuthenticated()) {
        MessageBox(windowHandle_, "Authentication valid and hardware-bound!", "Success",
                   MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBox(windowHandle_, "Not authenticated!", "Error", MB_OK | MB_ICONERROR);
    }
}

bool MainWindow::create() {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "HWSignMainWindow";
    wc.hbrBackground = CreateSolidBrush(BACKGROUND_COLOR);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassEx(&wc)) return false;

    // Create a larger window with centered position
    int windowWidth = 550;
    int windowHeight = 320;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int windowX = (screenWidth - windowWidth) / 2;
    int windowY = (screenHeight - windowHeight) / 2;

    windowHandle_ = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "HWSignMainWindow",
        "Hardware-Bound Authentication System",
        WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX),
        windowX,
        windowY,
        windowWidth,
        windowHeight,
        nullptr,
        nullptr,
        GetModuleHandle(nullptr),
        this
    );

    return windowHandle_ != nullptr;
}

void MainWindow::show(int nCmdShow) {
    ShowWindow(windowHandle_, nCmdShow);
}

