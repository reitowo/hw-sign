import axios, { AxiosError } from 'axios';

// Response type definitions
interface ServerResponse {
  message?: string;
}

interface LoginResponse extends ServerResponse {
  token: string;
}

interface AuthResponse extends ServerResponse {
  authenticated: boolean;
}

const apiClient = axios.create({
  baseURL: import.meta.env.DEV ? 'http://127.0.0.1:28280' : 'https://dbcs-api.ovo.fan',
  headers: { 'Content-Type': 'application/json' },
});

// Storage constants
const DB_NAME = 'DBCS';
const DB_VERSION = 1;
const STORE_NAME = 'auth_data';
const HW_KEY_ID = 'hardware_key';
const AUTH_TOKEN_ID = 'auth_token';
const ACCEL_KEY_ID_STORE = 'accel_key_id';
const PREFER_SYMMETRIC_STORE = 'prefer_symmetric';

// In-memory state
let hardwareKey: CryptoKeyPair | null = null;
let accelerationKey: CryptoKeyPair | null = null;
let accelerationKeyId: string | null = null;
let ecdhAccelerationKey: CryptoKeyPair | null = null;
let symmetricKey: CryptoKey | null = null;
let preferSymmetricEncryption = true; // Default to true for better performance

// Add debug logger
function debugLog(step: string, message: string, data?: any): void {
  const timestamp = new Date().toISOString();
  console.debug(`[${timestamp}] [DBCS] ${step}: ${message}`, data || '');
}

// IndexedDB helper functions
async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
  });
}

async function storeData(key: string, value: any): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const request = store.put(value, key);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();

    transaction.oncomplete = () => db.close();
  });
}

async function loadData(key: string): Promise<any> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);

    const request = store.get(key);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result || null);

    transaction.oncomplete = () => db.close();
  });
}

async function deleteData(key: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const request = store.delete(key);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();

    transaction.oncomplete = () => db.close();
  });
}

// Key storage wrappers
const storage = {
  hardwareKey: {
    store: (key: CryptoKeyPair) => storeData(HW_KEY_ID, key),
    load: () => loadData(HW_KEY_ID) as Promise<CryptoKeyPair | null>,
    delete: () => deleteData(HW_KEY_ID)
  },
  authToken: {
    store: (token: string) => storeData(AUTH_TOKEN_ID, token),
    load: () => loadData(AUTH_TOKEN_ID) as Promise<string | null>,
    delete: () => deleteData(AUTH_TOKEN_ID)
  },
  accelKeyId: {
    store: (id: string) => storeData(ACCEL_KEY_ID_STORE, id),
    load: () => loadData(ACCEL_KEY_ID_STORE) as Promise<string | null>,
    delete: () => deleteData(ACCEL_KEY_ID_STORE)
  },
  preferSymmetric: {
    store: (value: boolean) => storeData(PREFER_SYMMETRIC_STORE, value),
    load: async () => {
      const value = await loadData(PREFER_SYMMETRIC_STORE);
      return value !== false; // Default to true if not set
    }
  }
};

// Supported key algorithms
type KeyAlgorithm = 'Ed25519' | 'ECDSA' | 'RSA-PSS' | 'ECDH';

// Generate keys with fallback support
async function tryGenerateKey(type: KeyAlgorithm, extractable: boolean): Promise<CryptoKeyPair | null> {
  if (!window.crypto?.subtle) return null;

  try {
    debugLog('Key Generation', `Attempting to generate ${type} key, extractable: ${extractable}`);
    switch (type) {
      case 'Ed25519':
        return await window.crypto.subtle.generateKey(
          { name: 'Ed25519' },
          extractable,
          ['sign', 'verify']
        );
      case 'ECDSA':
        return await window.crypto.subtle.generateKey(
          { name: 'ECDSA', namedCurve: 'P-256' },
          extractable,
          ['sign', 'verify']
        );
      case 'RSA-PSS':
        return await window.crypto.subtle.generateKey(
          {
            name: 'RSA-PSS',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
          },
          extractable,
          ['sign', 'verify']
        );
      case 'ECDH':
        return await window.crypto.subtle.generateKey(
          { name: 'ECDH', namedCurve: 'P-256' },
          extractable,
          ['deriveKey', 'deriveBits']
        );
      default:
        return null;
    }
  } catch (e) {
    debugLog('Key Generation', `Failed to generate ${type} key:`, e);
    console.debug(`Failed to generate ${type} key:`, e);
    return null;
  }
}

async function generateKey(extractable: boolean, type?: KeyAlgorithm): Promise<CryptoKeyPair> {
  if (!window.crypto?.subtle) {
    debugLog('Key Generation', 'Web Crypto API not supported');
    throw new Error('Web Crypto API not supported');
  }

  // If a specific algorithm is requested, try it first
  if (type) {
    const key = await tryGenerateKey(type, extractable);
    if (key) {
      console.debug(`Using ${type} for key`);
      debugLog('Key Generation', `Successfully generated ${key.publicKey.algorithm.name} key`);
      return key;
    }
  }

  // Try algorithms in order of preference
  const algorithms: KeyAlgorithm[] = ['Ed25519', 'ECDSA', 'RSA-PSS'];
  for (const algo of algorithms) {
    const key = await tryGenerateKey(algo, extractable);
    if (key) {
      console.debug(`Using ${algo} for ${extractable ? 'acceleration' : 'hardware'} key`);
      debugLog('Key Generation', `Successfully generated ${key.publicKey.algorithm.name} key`);
      return key;
    }
  }
  throw new Error('No supported key algorithms available');
}

// Utility functions for data conversion and encryption
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

async function exportPublicKey(key: CryptoKey): Promise<string> {  
  // Choose export format based on algorithm
  const format = ['Ed25519', 'ECDH'].includes(key.algorithm.name) ? 'raw' : 'spki';
  const exported = await window.crypto.subtle.exportKey(format, key);
  return arrayBufferToBase64(exported);
}

// HMAC generation for ECDH-derived keys
async function generateHMAC(key: CryptoKey, data: string): Promise<string> {
  debugLog('HMAC', `Generating HMAC for data (${data.length} chars)`, { 
    dataPreview: data.substring(0, 20) + '...',
    keyAlgo: key.algorithm.name,
    keyUsages: key.usages
  });
  
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  const signature = await window.crypto.subtle.sign(
    { name: 'HMAC' },
    key,
    dataBuffer
  );

  debugLog('HMAC', `Generated HMAC: ${signature.byteLength} bytes`);
  return arrayBufferToBase64(signature);
}

// Function to derive shared secret and create HMAC key
async function deriveSharedKey(privateKey: CryptoKey, publicKeyBase64: string): Promise<CryptoKey> {
  debugLog('ECDH', 'Starting key derivation process', { 
    publicKeyLength: publicKeyBase64.length,
    privateKeyAlgo: privateKey.algorithm.name
  });
  
  try {
    // Import the server's public key
    const publicKeyData = base64ToArrayBuffer(publicKeyBase64);

    // Import the raw key data for ECDH
    const serverPublicKey = await window.crypto.subtle.importKey(
      'raw',
      publicKeyData,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Derive bits from the ECDH exchange
    const derivedBits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: serverPublicKey },
      privateKey,
      256 // 256 bits for HMAC key
    );

    debugLog('ECDH', 'Derived HMAC key successfully', {
      derivedBitsLength: derivedBits.byteLength
    });

    // Create HMAC key from the derived bits
    return await window.crypto.subtle.importKey(
      'raw',
      derivedBits,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  } catch (error) {
    debugLog('ECDH', 'Failed to derive shared key', error);
    console.error('Failed to derive shared key:', error);
    throw new Error('Failed to derive HMAC key');
  }
}

// Key management functions
async function setupECDHAccelerationKey(): Promise<{
  ecdhPubKeyBase64: string;
  ecdhPubKeySig: string;
}> {
  debugLog('ECDH Setup', 'Generating ECDH acceleration key pair');
  try {
    // Generate ECDH key pair - set extractable to FALSE for better security
    ecdhAccelerationKey = await generateKey(false, 'ECDH');
    
    // Export the public key
    const ecdhPubKeyBase64 = await exportPublicKey(ecdhAccelerationKey.publicKey);
    
    debugLog('ECDH Setup', 'ECDH key pair generated successfully', {
      publicKeyLength: ecdhPubKeyBase64.length
    });

    // Sign the public key with hardware key
    const ecdhPubKeySig = await signWithKey(hardwareKey!.privateKey, ecdhPubKeyBase64);
    
    debugLog('ECDH Setup', 'Signed ECDH public key with hardware key');
    return { ecdhPubKeyBase64, ecdhPubKeySig };
  } catch (error) {
    debugLog('ECDH Setup', 'Failed to setup ECDH key', error);
    console.error('Failed to setup ECDH key:', error);
    throw error;
  }
}

async function setupAccelerationKey(): Promise<{ accelPubKeyBase64: string; accelPubKeySig: string; keyType: string }> {
  if (accelerationKey) {
    const accelPubKeyBase64 = await exportPublicKey(accelerationKey.publicKey);
    const accelPubKeySig = await signWithKey(hardwareKey!.privateKey, accelPubKeyBase64);
    const keyType = accelerationKey.publicKey.algorithm.name.toLowerCase();
    return { accelPubKeyBase64, accelPubKeySig, keyType };
  }

  try {
    // Generate new acceleration key
    accelerationKey = await generateKey(true);

    // Export acceleration public key
    const accelPubKeyBase64 = await exportPublicKey(accelerationKey.publicKey);
    const accelPubKeySig = await signWithKey(hardwareKey!.privateKey, accelPubKeyBase64);
    const keyType = accelerationKey.publicKey.algorithm.name.toLowerCase();

    return { accelPubKeyBase64, accelPubKeySig, keyType };
  } catch (error) {
    // Reset the acceleration key on failure
    accelerationKey = null;
    accelerationKeyId = null;
    throw error;
  }
}

async function checkStorageSupport(): Promise<boolean> {
  if (!window.indexedDB) return false;

  try {
    const db = await openDB();
    db.close();
    return true;
  } catch (e) {
    console.debug('IndexedDB not available:', e);
    return false;
  }
}

async function initHardwareKey(): Promise<void> {
  debugLog('Hardware Key', 'Initializing hardware key');
  if (hardwareKey) {
    debugLog('Hardware Key', 'Hardware key already initialized');
    return; // Already initialized
  }
  
  // Check storage support first
  const hasStorage = await checkStorageSupport();
  if (!hasStorage) {
    throw new Error('Secure key storage is not available in your browser. Please enable IndexedDB or use a modern browser.');
  }

  // Try to load existing key first
  hardwareKey = await storage.hardwareKey.load();
  debugLog('Hardware Key', hardwareKey ? 'Loaded existing hardware key' : 'Generating new hardware key');
  if (!hardwareKey) {
    // Generate new key if none exists
    hardwareKey = await generateKey(false); // Ensure hardware key is non-exportable
    await storage.hardwareKey.store(hardwareKey);
  }

  debugLog('Hardware Key', 'Hardware key initialization complete');
}

async function init(): Promise<void> {
  try {
    // Load hardware key and auth token
    await initHardwareKey();
    
    // Load acceleration key ID if available
    accelerationKeyId = await storage.accelKeyId.load();
    
    // Load symmetric encryption preference
    preferSymmetricEncryption = await storage.preferSymmetric.load();
  } catch (error) {
    console.error('Failed to initialize auth service', error);
  }
}

async function signWithKey(key: CryptoKey, data: string): Promise<string> {
  const dataBuffer = new TextEncoder().encode(data);
  
  // Configure algorithm parameters based on key type
  const params = key.algorithm.name === 'RSA-PSS' 
    ? { name: 'RSA-PSS', saltLength: 32 }
    : key.algorithm.name === 'ECDSA'
      ? { name: 'ECDSA', hash: 'SHA-256' }
      : { name: key.algorithm.name };

  const signature = await window.crypto.subtle.sign(
    params,
    key,
    dataBuffer
  );
  return arrayBufferToBase64(signature);
}

// Primary authentication function
async function authenticatedRequest<T>(
  method: 'get' | 'post',
  url: string,
  data?: any
): Promise<T> {
  debugLog('Auth Request', `${method.toUpperCase()} ${url}`, data ? { dataType: typeof data } : {});
  try {
    const token = await storage.authToken.load();
    if (!token) throw new Error('Not authenticated');

    // Ensure hardware key is ready
    await initHardwareKey();

    // Prepare request data
    const timestamp = Date.now().toString();
    const requestData = data ? JSON.stringify(data) : timestamp;
    const headers: Record<string, string> = { 'Authorization': `Bearer ${token}` };

    debugLog('Auth Request', `Using ${accelerationKeyId ? 'existing' : 'new'} acceleration key`);

    // Handle different authentication methods based on available keys
    if (accelerationKeyId) {
      // Use existing acceleration key ID
      await handleExistingKeyAuth(headers, requestData);
    } else {
      // Register new acceleration key
      await handleNewKeyRegistration(headers, requestData);
    }

    // Make the authenticated request
    const response = await apiClient.request<T>({
      method,
      url,
      data,
      headers
    });

    // Process response if this was a new key registration
    if (!accelerationKeyId && response.headers['x-rpc-sec-dbcs-accel-pub-id']) {
      const headers = Object.fromEntries(
        Object.entries(response.headers).map(([key, value]) => [key, String(value)])
      );
      await processKeyRegistrationResponse(headers);
    }

    debugLog('Auth Request', 'Request completed successfully');
    return response.data;
  } catch (error) {
    debugLog('Auth Request', 'Request failed', error);
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<ServerResponse>;
      if (axiosError.response?.data?.message) {
        throw new Error(axiosError.response.data.message);
      }
    }
    throw error;
  }
}

// Helper for existing key authentication
async function handleExistingKeyAuth(headers: Record<string, string>, requestData: string): Promise<void> {
  debugLog('Existing Auth', 'Setting up authentication with existing key', { 
    keyType: symmetricKey && preferSymmetricEncryption ? 'symmetric' : 'asymmetric',
    dataLength: requestData.length,
    accelerationKeyId
  });
  
  if (symmetricKey && preferSymmetricEncryption) {
    // Use HMAC for authentication
    debugLog('Existing Auth', 'Using HMAC authentication');
    const hmac = await generateHMAC(symmetricKey, requestData);
    debugLog('Existing Auth', `Generated HMAC signature: ${hmac.substring(0, 20)}...`);

    headers['x-rpc-sec-dbcs-data'] = requestData;
    headers['x-rpc-sec-dbcs-data-sig'] = hmac; // Unified header for signature
    headers['x-rpc-sec-dbcs-accel-pub-id'] = accelerationKeyId!;
  } else if (accelerationKey) {
    // Use asymmetric signatures
    debugLog('Existing Auth', 'Using asymmetric signature authentication');
    const signature = await signWithKey(accelerationKey.privateKey, requestData);
    debugLog('Existing Auth', `Generated signature: ${signature.substring(0, 20)}...`);
    
    headers['x-rpc-sec-dbcs-data'] = requestData;
    headers['x-rpc-sec-dbcs-data-sig'] = signature; // Unified header for signature
    headers['x-rpc-sec-dbcs-accel-pub-id'] = accelerationKeyId!;
  } else {
    debugLog('Existing Auth', 'Invalid key state, forcing new registration');
    accelerationKeyId = null;
    await storage.accelKeyId.delete();
    throw new Error('Invalid key state, will register new key');
  }
}

// Helper for new key registration
async function handleNewKeyRegistration(headers: Record<string, string>, requestData: string): Promise<void> {
  debugLog('New Key Auth', 'Registering new acceleration key', {
    preferSymmetric: preferSymmetricEncryption
  });
  
  let isEcdhGenerated = false;
  
  // Try ECDH key exchange if supported and preferred
  if (window.crypto.subtle && preferSymmetricEncryption) {
    try {
      // Setup ECDH key exchange
      const { ecdhPubKeyBase64, ecdhPubKeySig } = await setupECDHAccelerationKey();
      
      // Sign request data with hardware key for this first exchange
      const dataSig = await signWithKey(hardwareKey!.privateKey, requestData);
      
      headers['x-rpc-sec-dbcs-accel-pub'] = ecdhPubKeyBase64;
      headers['x-rpc-sec-dbcs-accel-pub-type'] = 'ecdh';
      headers['x-rpc-sec-dbcs-accel-pub-sig'] = ecdhPubKeySig;
      headers['x-rpc-sec-dbcs-data'] = requestData;
      headers['x-rpc-sec-dbcs-data-sig'] = dataSig;
      isEcdhGenerated = true;
    } catch (error) {
      debugLog('New Key Auth', 'ECDH key exchange failed, falling back to asymmetric keys', error);
      console.debug('ECDH key exchange failed, falling back to asymmetric keys', error);
    }
  }
  
  // Fall back to asymmetric keys if ECDH isn't available or failed
  if (!isEcdhGenerated) {
    debugLog('New Key Auth', 'Using asymmetric key pair');
    const { accelPubKeyBase64, accelPubKeySig, keyType } = await setupAccelerationKey();
    const signature = await signWithKey(accelerationKey!.privateKey, requestData);
    
    headers['x-rpc-sec-dbcs-accel-pub'] = accelPubKeyBase64;
    headers['x-rpc-sec-dbcs-accel-pub-type'] = keyType;
    headers['x-rpc-sec-dbcs-accel-pub-sig'] = accelPubKeySig;
    headers['x-rpc-sec-dbcs-data'] = requestData;
    headers['x-rpc-sec-dbcs-data-sig'] = signature;
  }
  
  debugLog('New Key Auth', 'New key registration headers set up');
}

// Process key registration response
async function processKeyRegistrationResponse(headers: Record<string, string>): Promise<void> {
  debugLog('Key Registration', 'Processing key registration response', headers);
  
  // Store the key ID
  const keyId = headers['x-rpc-sec-dbcs-accel-pub-id'];
  if (keyId) {
    debugLog('Key Registration', `Received key ID: ${keyId}`);
    accelerationKeyId = keyId;
    await storage.accelKeyId.store(keyId);
    
    // If this was an ECDH key exchange, process server's public key
    const serverPubKey = headers['x-rpc-sec-dbcs-accel-pub'];
    if (ecdhAccelerationKey && serverPubKey && preferSymmetricEncryption) {
      debugLog('Key Registration', 'Processing ECDH server public key', {
        publicKeyLength: serverPubKey.length
      });
      
      try {
        // Derive the shared secret and create the HMAC key
        symmetricKey = await deriveSharedKey(ecdhAccelerationKey.privateKey, serverPubKey);
        debugLog('Key Registration', 'ECDH key exchange completed successfully');
        console.debug('ECDH key exchange successful, HMAC authentication enabled');
      } catch (error) {
        debugLog('Key Registration', 'Failed to establish HMAC key', error);
        console.error('Failed to establish HMAC key:', error);
      }
    }
  } else {
    debugLog('Key Registration', 'No acceleration key ID received');
  }
}

// Public API functions
export async function toggleSymmetricEncryption(): Promise<boolean> {
  debugLog('API', `Toggling symmetric encryption from ${preferSymmetricEncryption} to ${!preferSymmetricEncryption}`);
  
  // Toggle the preference
  preferSymmetricEncryption = !preferSymmetricEncryption;
  
  // Store the updated preference
  await storage.preferSymmetric.store(preferSymmetricEncryption);
  
  // If disabling, clear the symmetric key (we'll keep using asymmetric with existing key ID)
  if (!preferSymmetricEncryption) {
    symmetricKey = null;
  }
  
  // Reset key state
  accelerationKeyId = null;
  await storage.accelKeyId.delete();

  debugLog('API', `Symmetric encryption set to ${preferSymmetricEncryption}`);
  return preferSymmetricEncryption;
}

export function isSymmetricEncryptionEnabled(): boolean {
  return preferSymmetricEncryption;
}

export async function register(userData: { username: string; password: string }) {
  const response = await apiClient.post<ServerResponse>('/register', userData);
  return response.data;
}

export async function login(credentials: { username: string; password: string }) {
  debugLog('API', 'Login attempt', { username: credentials.username });
  
  // Ensure hardware key is ready for login
  await initHardwareKey();

  // Get hardware public key
  const hwPubKey = await exportPublicKey(hardwareKey!.publicKey);
  const hwKeyType = hardwareKey!.publicKey.algorithm.name.toLowerCase();

  debugLog('API', 'Hardware key prepared', {
    keyType: hwKeyType,
    publicKeyLength: hwPubKey.length
  });

  // Setup request with hardware key headers
  const response = await apiClient.post<LoginResponse>(
    '/login',
    credentials,
    {
      headers: {
        'x-rpc-sec-dbcs-hw-pub': hwPubKey,
        'x-rpc-sec-dbcs-hw-pub-type': hwKeyType,
      }
    }
  );

  // Store the auth token
  await storage.authToken.store(response.data.token);

  // Clear any existing acceleration keys when logging in
  accelerationKey = null;
  accelerationKeyId = null;
  ecdhAccelerationKey = null;
  symmetricKey = null;
  await storage.accelKeyId.delete();

  debugLog('API', 'Login successful');
  return response.data;
}

export async function isAuthenticated(): Promise<boolean> {
  debugLog('API', 'Checking authentication status');
  try {
    const token = await storage.authToken.load();
    if (!token) return false;

    // Make an authenticated request to verify the token is valid
    const response = await authenticatedRequest<AuthResponse>('get', '/authenticated');
    debugLog('API', `Authentication status: ${response.authenticated}`);
    return response.authenticated;
  } catch (error) {
    debugLog('API', 'Authentication check failed', error);
    console.debug('Authentication check failed:', error);
    return false;
  }
}

export function logout(): void {
  debugLog('API', 'Logging out, clearing all keys and tokens');
  Promise.all([
    storage.authToken.delete(),
    storage.hardwareKey.delete(),
    storage.accelKeyId.delete(),
  ]).catch(console.error);
  
  // Clear all sensitive data from memory
  hardwareKey = null;
  accelerationKey = null;
  accelerationKeyId = null;
  ecdhAccelerationKey = null;
  symmetricKey = null;
}

// Initialize the service on module load
init().catch(error => {
  debugLog('Init', 'Service initialization failed', error);
  console.error(error);
});

// Add window unload handler to clear sensitive keys from memory
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    ecdhAccelerationKey = null;
    symmetricKey = null;
  });
}