# hw-sign-apple

This is a combined iOS and macOS application that provides user authentication capabilities. The application was created by merging separate iOS and macOS codebases into a unified codebase that works across both platforms.

## Features

- User registration
- User login
- Authentication status check
- Cross-platform compatibility (iOS and macOS)

## Project Structure

The project uses SwiftUI to create a common UI that adapts to both iOS and macOS. Conditional compilation is used where platform-specific code is needed.

```
hw-sign-apple/
  ├── main.swift               # Main application code (works on both platforms)
  ├── Info.plist               # Combined property list file
  └── hw-sign-apple.xcodeproj/ # Xcode project with targets for iOS and macOS
```

## Building the Project

1. Open the project in Xcode
2. Select the target you want to run (hw-sign-iOS or hw-sign-macOS)
3. Build and run the project

## Backend Connection

The app connects to a RESTful API at https://dbcs-api.reito.fun for user authentication operations.