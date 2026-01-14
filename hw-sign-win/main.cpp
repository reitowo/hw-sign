#include <windows.h>

#include <exception>

#include "app/main_window.h"
#include "app/ncrypt_utils.h"
#include "app/openssl_demo.h"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int nCmdShow) {
    try {
        TestECDSAPlusECDH();

        // Print available algorithms at startup
        printAvailableAlgorithms();

        MainWindow mainWindow;
        if (!mainWindow.create()) {
            MessageBox(nullptr, "Failed to create window", "Error", MB_OK | MB_ICONERROR);
            return 1;
        }

        mainWindow.show(nCmdShow);

        MSG msg = {};
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        return static_cast<int>(msg.wParam);
    }
    catch (const std::exception& e) {
        MessageBoxA(nullptr, e.what(), "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
}

