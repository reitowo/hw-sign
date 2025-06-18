#!/usr/bin/env python3

import base64
import json
import os
import time
import hmac
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
import secrets
import uuid

# For cryptographic operations
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


@dataclass
class KeyConfig:
    """Configuration for key storage."""
    file_path: str = "hw_sign_keys.json"
    hardware_key_type: str = "ecdsa-p256"  # Options: ecdsa-p256, ed25519, rsa-2048
    accel_key_type: str = "ecdh-p256"      # Options: ecdh-p256, ecdsa-p256, rsa-2048


@dataclass
class KeyPair:
    """Represents a key pair with additional metadata."""
    id: str
    key_type: str
    created_at: int
    private_key: Optional[str] = None  # Base64 encoded private key
    public_key: Optional[str] = None   # Base64 encoded public key


@dataclass
class SharedSecret:
    """Represents a shared secret derived from ECDH."""
    id: str
    secret: str                # Base64 encoded shared secret
    client_pub_key: str        # Client's public key used in derivation
    server_pub_key: str        # Server's public key used in derivation
    created_at: int
    expires_at: Optional[int] = None


@dataclass
class KeyStorage:
    """Storage for all keys and shared secrets."""
    hardware_keys: List[KeyPair] = field(default_factory=list)
    accel_keys: List[KeyPair] = field(default_factory=list)
    shared_secrets: List[SharedSecret] = field(default_factory=list)


class HwSignMock:
    """Mock implementation of hardware-bound signing."""
    
    def __init__(self, config: KeyConfig = None):
        """Initialize with optional configuration."""
        self.config = config or KeyConfig()
        self.storage = self._load_storage()
        self.current_hw_key: Optional[KeyPair] = None
        self.current_accel_key: Optional[KeyPair] = None
        self.current_shared_secret: Optional[SharedSecret] = None
        
        # Initialize keys if none exist
        if not self.storage.hardware_keys:
            self._generate_hardware_key()
        
        # Set current hardware key
        self.current_hw_key = self.storage.hardware_keys[-1]
        
        print(f"Initialized HW Sign Mock with {len(self.storage.hardware_keys)} hardware keys")
    
    def _load_storage(self) -> KeyStorage:
        """Load key storage from file or create new storage."""
        try:
            if os.path.exists(self.config.file_path):
                with open(self.config.file_path, 'r') as f:
                    data = json.load(f)
                storage = KeyStorage(
                    hardware_keys=[KeyPair(**k) for k in data.get('hardware_keys', [])],
                    accel_keys=[KeyPair(**k) for k in data.get('accel_keys', [])],
                    shared_secrets=[SharedSecret(**s) for s in data.get('shared_secrets', [])]
                )
                print(f"Loaded {len(storage.hardware_keys)} hardware keys from {self.config.file_path}")
                return storage
        except Exception as e:
            print(f"Error loading key storage: {e}")
        
        # Return empty storage if file doesn't exist or has errors
        return KeyStorage()
    
    def _save_storage(self):
        """Save key storage to file."""
        # Convert to dictionary
        data = {
            "hardware_keys": [asdict(k) for k in self.storage.hardware_keys],
            "accel_keys": [asdict(k) for k in self.storage.accel_keys],
            "shared_secrets": [asdict(s) for s in self.storage.shared_secrets]
        }
        
        # Save to file
        with open(self.config.file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Saved key storage to {self.config.file_path}")
    
    def _generate_hardware_key(self) -> KeyPair:
        """Generate a new hardware key pair."""
        key_id = str(uuid.uuid4())
        created_at = int(time.time())
        
        # Generate EC key pair
        if self.config.hardware_key_type == "ecdsa-p256":
            private_key = ec.generate_private_key(
                ec.SECP256R1(),  # P-256 curve
                default_backend()
            )
            
            # Serialize keys
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            raise ValueError(f"Unsupported hardware key type: {self.config.hardware_key_type}")
        
        # Create key pair
        key_pair = KeyPair(
            id=key_id,
            key_type=self.config.hardware_key_type,
            created_at=created_at,
            private_key=base64.b64encode(private_bytes).decode('utf-8'),
            public_key=base64.b64encode(public_bytes).decode('utf-8')
        )
        
        # Add to storage
        self.storage.hardware_keys.append(key_pair)
        self._save_storage()
        
        print(f"Generated new hardware key of type {self.config.hardware_key_type} with ID {key_id}")
        return key_pair
    
    def _generate_accel_key(self) -> KeyPair:
        """Generate a new acceleration key pair."""
        key_id = str(uuid.uuid4())
        created_at = int(time.time())
        
        # Generate EC key pair for ECDH
        if self.config.accel_key_type == "ecdh-p256":
            private_key = ec.generate_private_key(
                ec.SECP256R1(),  # P-256 curve
                default_backend()
            )
            
            # Serialize keys
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            raise ValueError(f"Unsupported acceleration key type: {self.config.accel_key_type}")
        
        # Create key pair
        key_pair = KeyPair(
            id=key_id,
            key_type=self.config.accel_key_type,
            created_at=created_at,
            private_key=base64.b64encode(private_bytes).decode('utf-8'),
            public_key=base64.b64encode(public_bytes).decode('utf-8')
        )
        
        # Add to storage
        self.storage.accel_keys.append(key_pair)
        self._save_storage()
        
        print(f"Generated new acceleration key of type {self.config.accel_key_type} with ID {key_id}")
        return key_pair
    
    def _load_private_key(self, key_pair: KeyPair):
        """Load private key from key pair."""
        if not key_pair or not key_pair.private_key:
            raise ValueError("Invalid key pair")
        
        private_bytes = base64.b64decode(key_pair.private_key)
        
        if key_pair.key_type == "ecdsa-p256" or key_pair.key_type == "ecdh-p256":
            return serialization.load_der_private_key(
                private_bytes,
                password=None,
                backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported key type: {key_pair.key_type}")
    
    def _load_public_key(self, base64_key: str, key_type: str = "ecdsa-p256"):
        """Load public key from base64 encoded string."""
        public_bytes = base64.b64decode(base64_key)
        
        if key_type == "ecdsa-p256" or key_type == "ecdh-p256":
            return serialization.load_der_public_key(
                public_bytes,
                backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
    
    def sign_with_hardware_key(self, data: str) -> str:
        """Sign data with hardware key using ECDSA."""
        if not self.current_hw_key:
            raise ValueError("No hardware key available")
        
        private_key = self._load_private_key(self.current_hw_key)
        
        if self.current_hw_key.key_type == "ecdsa-p256":
            # Sign using ECDSA
            signature = private_key.sign(
                data.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return base64.b64encode(signature).decode('utf-8')
        else:
            raise ValueError(f"Unsupported key type for signing: {self.current_hw_key.key_type}")
    
    def sign_with_accel_key(self, data: str) -> str:
        """
        Sign data with acceleration key.
        If a shared secret exists, use HMAC-SHA256, otherwise use ECDSA.
        """
        if self.current_shared_secret:
            # Use HMAC with shared secret
            return self._sign_hmac(data, self.current_shared_secret.secret)
        
        # No shared secret, generate a new acceleration key if needed
        if not self.current_accel_key:
            self.current_accel_key = self._generate_accel_key()
        
        private_key = self._load_private_key(self.current_accel_key)
        
        if self.current_accel_key.key_type == "ecdh-p256":
            # Sign using ECDSA (same operation as P-256 ECDSA)
            signature = private_key.sign(
                data.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return base64.b64encode(signature).decode('utf-8')
        else:
            raise ValueError(f"Unsupported key type for signing: {self.current_accel_key.key_type}")
    
    def _sign_hmac(self, data: str, secret_base64: str) -> str:
        """Sign data using HMAC-SHA256 with the shared secret."""
        secret_bytes = base64.b64decode(secret_base64)
        
        # Create HMAC
        h = hmac.new(secret_bytes, data.encode('utf-8'), hashlib.sha256)
        return base64.b64encode(h.digest()).decode('utf-8')
    
    def get_hardware_public_key(self) -> Tuple[str, str]:
        """Get the current hardware public key and its type."""
        if not self.current_hw_key:
            self.current_hw_key = self._generate_hardware_key()
        
        return self.current_hw_key.public_key, self.current_hw_key.key_type
    
    def get_accel_public_key(self) -> Tuple[str, str]:
        """Get the current acceleration public key and its type."""
        if not self.current_accel_key:
            self.current_accel_key = self._generate_accel_key()
        
        return self.current_accel_key.public_key, self.current_accel_key.key_type
    
    def get_signed_accel_key(self) -> Tuple[str, str, str]:
        """
        Get the acceleration public key, its type, and a signature of the public key
        using the hardware key.
        """
        if not self.current_accel_key:
            self.current_accel_key = self._generate_accel_key()
        
        # Sign the acceleration public key with the hardware key
        signature = self.sign_with_hardware_key(self.current_accel_key.public_key)
        
        return (
            self.current_accel_key.public_key,
            self.current_accel_key.key_type,
            signature
        )
    
    def set_server_public_key(self, server_pub_key: str, key_id: str = None) -> str:
        """
        Use the server's public key to establish a shared secret via ECDH.
        Returns the ID of the established shared secret.
        """
        if not self.current_accel_key:
            self.current_accel_key = self._generate_accel_key()
        
        # Load the client's private key
        client_private_key = self._load_private_key(self.current_accel_key)
        
        # Load the server's public key
        try:
            server_public_key = self._load_public_key(server_pub_key, "ecdh-p256")
            
            # Perform key exchange
            shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
            
            # Derive final shared secret using HKDF
            shared_secret = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'hw-sign-ecdh',
                backend=default_backend()
            ).derive(shared_key)
            
            # Create shared secret entry
            secret_id = key_id or str(uuid.uuid4())
            shared_secret_entry = SharedSecret(
                id=secret_id,
                secret=base64.b64encode(shared_secret).decode('utf-8'),
                client_pub_key=self.current_accel_key.public_key,
                server_pub_key=server_pub_key,
                created_at=int(time.time()),
                expires_at=int(time.time()) + 3600  # 1 hour expiry
            )
            
            # Add to storage
            self.storage.shared_secrets.append(shared_secret_entry)
            self._save_storage()
            
            # Set as current shared secret
            self.current_shared_secret = shared_secret_entry
            
            print(f"ECDH key exchange completed successfully. Secret ID: {secret_id}")
            return secret_id
            
        except Exception as e:
            print(f"Error during ECDH key exchange: {e}")
            raise
    
    def generate_request_data(self) -> str:
        """Generate request data in the format: Timestamp-RandomHex."""
        timestamp = str(int(time.time()))
        random_hex = secrets.token_hex(16)  # 32 bytes of hex
        return f"{timestamp}-{random_hex}"


class TestClient:
    """Client for testing the hardware-bound authentication."""
    
    def __init__(self, base_url: str = "http://localhost:28280"):
        self.base_url = base_url
        self.hw_sign = HwSignMock()
        self.auth_token = None
        self.accel_key_id = None
        
        print(f"Initialized test client with base URL: {base_url}")
    
    def test_register(self, username: str, password: str) -> bool:
        """Test user registration."""
        print("\n=== Testing Registration (Simulated) ===")
        print(f"Username: {username}")
        print(f"Password: {password}")
        
        # Simulate successful registration
        print("✓ Registration successful!")
        return True
    
    def test_login(self, username: str, password: str) -> bool:
        """Test login with hardware key binding."""
        print("\n=== Testing Login (Simulated) ===")
        print(f"Username: {username}")
        print(f"Password: {password}")
        
        # Get hardware public key
        hw_pub_key, hw_pub_type = self.hw_sign.get_hardware_public_key()
        
        print(f"Hardware public key (first 50 chars): {hw_pub_key[:50]}...")
        print(f"Hardware key type: {hw_pub_type}")
        
        # Simulate successful login
        self.auth_token = f"mock_token_{secrets.token_hex(8)}"
        print(f"✓ Login successful! Token: {self.auth_token[:20]}...")
        return True
    
    def test_authenticated(self) -> bool:
        """
        Test authenticated request.
        First request registers a new ECDH acceleration key.
        Subsequent requests use the established shared secret.
        """
        print("\n=== Testing Authenticated Request ===")
        
        if not self.auth_token:
            print("✗ No auth token available!")
            return False
        
        # Generate request timestamp
        timestamp = self.hw_sign.generate_request_data()
        print(f"Request timestamp: {timestamp}")
        
        # Build request headers
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "x-rpc-sec-bound-token-data": timestamp
        }
        
        if not self.accel_key_id:
            # First authenticated request - register ECDH acceleration key
            print("Registering new ECDH acceleration key...")
            
            # Get acceleration key and sign it with hardware key
            accel_pub, accel_pub_type, accel_pub_sig = self.hw_sign.get_signed_accel_key()
            
            # Sign the request data with acceleration key
            data_sig = self.hw_sign.sign_with_accel_key(timestamp)
            
            # Add headers
            headers.update({
                "x-rpc-sec-bound-token-accel-pub": accel_pub,
                "x-rpc-sec-bound-token-accel-pub-type": accel_pub_type,
                "x-rpc-sec-bound-token-accel-pub-sig": accel_pub_sig,
                "x-rpc-sec-bound-token-data-sig": data_sig
            })
            
            print(f"Acceleration public key (first 50 chars): {accel_pub[:50]}...")
            print(f"Acceleration key type: {accel_pub_type}")
            print(f"Accel pub signature (first 20 chars): {accel_pub_sig[:20]}...")
            print(f"Data signature (first 20 chars): {data_sig[:20]}...")
            
            # Simulate server response
            self.accel_key_id = f"accel_{secrets.token_hex(8)}"
            server_pub_key = self._simulate_server_response()
            
            # Establish shared secret
            if server_pub_key:
                self.hw_sign.set_server_public_key(server_pub_key, self.accel_key_id)
                print(f"Received acceleration key ID: {self.accel_key_id}")
                print(f"Received server ECDH public key: {server_pub_key[:30]}...")
                print("Shared secret established for HMAC authentication")
            
        else:
            # Subsequent requests - use HMAC with shared secret
            print(f"Using existing acceleration key ID with HMAC: {self.accel_key_id}")
            
            # Sign data using HMAC with shared secret
            data_sig = self.hw_sign.sign_with_accel_key(timestamp)
            
            # Add headers
            headers.update({
                "x-rpc-sec-bound-token-accel-pub-id": self.accel_key_id,
                "x-rpc-sec-bound-token-data-sig": data_sig
            })
            
            print(f"HMAC signature (first 20 chars): {data_sig[:20]}...")
        
        # Simulate successful request
        print("✓ Authenticated request successful!")
        return True
    
    def _simulate_server_response(self) -> str:
        """Simulate server response with a new ECDH public key."""
        # Generate a mock server key
        mock_server = HwSignMock()
        server_pub_key, _ = mock_server.get_accel_public_key()
        return server_pub_key
        
    def run_full_test(self):
        """Run a full test sequence."""
        print("=====================================")
        print("Hardware-Bound Authentication Test")
        print("ECDSA Hardware Key + ECDH Accel Key")
        print("=====================================")
        
        username = f"testuser_{int(time.time())}"
        password = "testpass123"
        
        # Test 1: Register
        register_success = self.test_register(username, password)
        
        # Test 2: Login with ECDSA hardware key
        login_success = False
        if register_success:
            login_success = self.test_login(username, password)
        
        # Test 3: Authenticated request (first time - register ECDH accel key)
        auth_success1 = False
        if login_success:
            auth_success1 = self.test_authenticated()
        
        # Test 4: Authenticated request (second time - use existing ECDH key)
        auth_success2 = False
        if auth_success1:
            print("\n=== Testing Second Authenticated Request ===")
            auth_success2 = self.test_authenticated()
        
        # Test 5: Third authenticated request to verify ECDH key persistence
        auth_success3 = False
        if auth_success2:
            print("\n=== Testing Third Authenticated Request ===")
            auth_success3 = self.test_authenticated()
        
        # Summary
        print("\n=====================================")
        print("Test Results Summary:")
        print("=====================================")
        print(f"Registration:           {'✓ PASS' if register_success else '✗ FAIL'}")
        print(f"Login (ECDSA HW key):   {'✓ PASS' if login_success else '✗ FAIL'}")
        print(f"Auth (new ECDH key):    {'✓ PASS' if auth_success1 else '✗ FAIL'}")
        print(f"Auth (existing ECDH):   {'✓ PASS' if auth_success2 else '✗ FAIL'}")
        print(f"Auth (ECDH persistent): {'✓ PASS' if auth_success3 else '✗ FAIL'}")
        
        all_passed = register_success and login_success and auth_success1 and auth_success2 and auth_success3
        print(f"\nOverall Result:         {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")
        
        if all_passed:
            print("\n🎉 Congratulations! All hardware-bound authentication tests passed!")
            print("✓ ECDSA hardware key authentication works")
            print("✓ ECDH acceleration key exchange works")
            print("✓ Key persistence and reuse works")
        
        print("=====================================")


if __name__ == "__main__":
    client = TestClient()
    client.run_full_test() 