#pragma once

#include "app/auth_service.h"

#include <windows.h>

class MainWindow {
public:
    MainWindow();
    ~MainWindow();

    bool create();
    void show(int nCmdShow);
    HWND handle() const { return windowHandle_; }

private:
    HWND windowHandle_ = nullptr;
    HWND usernameEditHandle_ = nullptr;
    HWND passwordEditHandle_ = nullptr;
    HWND loginButtonHandle_ = nullptr;
    HWND registerButtonHandle_ = nullptr;
    HWND logoutButtonHandle_ = nullptr;
    HWND checkAuthButtonHandle_ = nullptr;
    AuthService authService_;
    HBRUSH backgroundBrush_ = nullptr;
    static constexpr COLORREF BACKGROUND_COLOR = RGB(240, 240, 240);

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT handleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    void createControls(HWND hwnd);
    void onLogin();
    void onRegister();
    void onLogout();
    void onCheckAuth();
};

