#include "test_client/test_client.hpp"

int main(int argc, char* argv[]) {
    try {
        // Check for help or no arguments
        if (argc < 2) {
            ClientConfig::printUsage(argv[0]);
            return 1;
        }

        std::string command = argv[1];
        
        // Handle help
        if (command == "-h" || command == "--help" || command == "help") {
            ClientConfig::printUsage(argv[0]);
            return 0;
        }

        // Parse configuration from arguments
        ClientConfig config = ClientConfig::fromArgs(argc, argv);

        std::cout << "==========================================" << std::endl;
        std::cout << "Hardware-Bound Authentication Test Client" << std::endl;
        std::cout << "==========================================" << std::endl;
        std::cout << "Command: " << command << std::endl;
        std::cout << "Server:  " << config.serverUrl << std::endl;
        std::cout << "Key:     " << (config.keyType == HardwareKeyType::RSA_2048_PSS ? "RSA-2048-PSS" : "ECDSA-P256") << std::endl;
        
        // Create client
        TestClient client(config);

        // Execute command
        bool success = false;
        if (command == "auth") {
            success = client.runAuthFlow();
        }
        else if (command == "aik") {
            success = client.runAIKFlow();
        }
        else if (command == "both") {
            success = client.runBothFlows();
        }
        else if (command == "info") {
            client.showTPMInfo();
            success = true;
        }
        else {
            std::cerr << "Unknown command: " << command << std::endl;
            ClientConfig::printUsage(argv[0]);
            return 1;
        }

        std::cout << "\n==========================================" << std::endl;
        if (success) {
            std::cout << "✓ Command completed successfully!" << std::endl;
        } else {
            std::cout << "✗ Command completed with errors." << std::endl;
        }
        std::cout << "==========================================" << std::endl;

        return success ? 0 : 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
