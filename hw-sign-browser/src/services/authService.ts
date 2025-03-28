import axios, { AxiosError } from 'axios';

// Add server response types
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
  baseURL: 'https://dbcs-api.ovo.fan',
  // baseURL: 'http://127.0.0.1:28280',
  headers: { 'Content-Type': 'application/json' },
});

const DB_NAME = 'DBCS';
const DB_VERSION = 1;

const STORE_NAME = 'auth_data';
const HW_KEY_ID = 'hardware_key';
const AUTH_TOKEN_ID = 'auth_token';

let hardwareKey: CryptoKeyPair | null = null;
let accelerationKey: CryptoKeyPair | null = null;
let accelerationKeyId: string | null = null;

// IndexedDB setup
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

async function storeHardwareKey(key: CryptoKeyPair): Promise<void> {
  return storeData(HW_KEY_ID, key);
}

async function loadHardwareKey(): Promise<CryptoKeyPair | null> {
  return loadData(HW_KEY_ID);
}

async function deleteHardwareKey(): Promise<void> {
  return deleteData(HW_KEY_ID);
}

async function storeAuthToken(token: string): Promise<void> {
  return storeData(AUTH_TOKEN_ID, token);
}

async function loadAuthToken(): Promise<string | null> {
  return loadData(AUTH_TOKEN_ID);
}

async function deleteAuthToken(): Promise<void> {
  return deleteData(AUTH_TOKEN_ID);
}

type KeyAlgorithm = 'Ed25519' | 'ECDSA' | 'RSA-PSS';

async function tryGenerateKey(type: KeyAlgorithm, extractable: boolean): Promise<CryptoKeyPair | null> {
  if (!window.crypto?.subtle) return null;

  try {
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
      default:
        return null;
    }
  } catch (e) {
    console.debug(`Failed to generate ${type} key:`, e);
    return null;
  }
}

async function generateKey(extractable: boolean): Promise<CryptoKeyPair> {
  if (!window.crypto?.subtle) {
    throw new Error('Web Crypto API not supported');
  }

  const algorithms: KeyAlgorithm[] = ['Ed25519', 'ECDSA', 'RSA-PSS'];
  for (const algo of algorithms) {
    const key = await tryGenerateKey(algo, extractable);
    if (key) {
      console.debug(`Using ${algo} for ${extractable ? 'acceleration' : 'hardware'} key`);
      return key;
    }
  }
  throw new Error('No supported key algorithms available');
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

async function exportPublicKey(key: CryptoKey): Promise<string> {
  const format = key.algorithm.name === 'Ed25519' ? 'raw' : 'spki';
  const exported = await window.crypto.subtle.exportKey(format, key);
  return arrayBufferToBase64(exported);
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
  // Check storage support first
  const hasStorage = await checkStorageSupport();
  if (!hasStorage) {
    throw new Error('Secure key storage is not available in your browser. Please enable IndexedDB or use a modern browser.');
  }

  if (!hardwareKey) {
    // Try to load existing key first
    hardwareKey = await loadHardwareKey();
    if (!hardwareKey) {
      // Generate new key if none exists
      hardwareKey = await generateKey(false); // Ensure hardware key is non-exportable
      await storeHardwareKey(hardwareKey);
    }
  }
}

async function signWithKey(key: CryptoKey, data: string): Promise<string> {
  const dataBuffer = new TextEncoder().encode(data);
  let params;
  switch (key.algorithm.name) {
    case 'RSA-PSS':
      params = { name: 'RSA-PSS', saltLength: 32 };
      break;
    case 'ECDSA':
      params = { name: 'ECDSA', hash: 'SHA-256' };
      break;
    default:
      params = { name: key.algorithm.name };
  }

  const signature = await window.crypto.subtle.sign(
    params,
    key,
    dataBuffer
  );
  return arrayBufferToBase64(signature);
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

async function authenticatedRequest<T>(
  method: 'get' | 'post',
  url: string,
  data?: any
): Promise<T> {
  try {
    const token = await loadAuthToken();
    if (!token) throw new Error('Not authenticated');

    // Ensure hardware key is ready
    await initHardwareKey();

    // Prepare request data
    const timestamp = Date.now().toString();
    const requestData = data ? JSON.stringify(data) : timestamp;

    // Setup headers
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${token}`,
      'x-rpc-sec-dbcs-data': requestData,
    };

    // If we have an existing acceleration key and ID, use it
    if (accelerationKey && accelerationKeyId) {
      const signature = await signWithKey(accelerationKey.privateKey, requestData);
      headers['x-rpc-sec-dbcs-data-sig'] = signature;
      headers['x-rpc-sec-dbcs-accel-pub-id'] = accelerationKeyId;
    } else {
      // Generate new acceleration key and sign request
      const { accelPubKeyBase64, accelPubKeySig, keyType } = await setupAccelerationKey();

      // Sign the request data with the new acceleration key
      const signature = await signWithKey(accelerationKey!.privateKey, requestData);

      // Add acceleration key registration headers
      headers['x-rpc-sec-dbcs-accel-pub'] = accelPubKeyBase64;
      headers['x-rpc-sec-dbcs-accel-pub-type'] = keyType;
      headers['x-rpc-sec-dbcs-accel-pub-sig'] = accelPubKeySig;
      headers['x-rpc-sec-dbcs-data-sig'] = signature;
    }

    // Make the authenticated request
    const response = await apiClient.request<T>({
      method,
      url,
      data,
      headers
    });

    // If this was a new acceleration key registration, save the key ID from response
    if (!accelerationKeyId && response.headers['x-rpc-sec-dbcs-accel-pub-id']) {
      accelerationKeyId = response.headers['x-rpc-sec-dbcs-accel-pub-id'];
    }

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<ServerResponse>;
      if (axiosError.response?.data?.message) {
        throw new Error(axiosError.response.data.message);
      }
    }
    throw error;
  }
}

export async function register(userData: { username: string; password: string }) {
  try {
    const response = await apiClient.post<ServerResponse>('/register', userData);
    if (response.status === 201) {
      return response.data;
    }
    throw new Error('Registration failed');
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<ServerResponse>;
      if (axiosError.response?.data?.message) {
        throw new Error(axiosError.response.data.message);
      }
    }
    throw error;
  }
}

export async function login(credentials: { username: string; password: string }) {
  try {
    // Clear any existing data before generating new ones
    await deleteHardwareKey();
    await deleteAuthToken();
    hardwareKey = null;

    await initHardwareKey();

    const hwPubKeyBase64 = await exportPublicKey(hardwareKey!.publicKey);
    const hwKeyType = hardwareKey!.publicKey.algorithm.name.toLowerCase();

    const response = await apiClient.post<LoginResponse>('/login', credentials, {
      headers: {
        'x-rpc-sec-dbcs-hw-pub': hwPubKeyBase64,
        'x-rpc-sec-dbcs-hw-pub-type': hwKeyType
      }
    });

    if (response.data.token) {
      await storeAuthToken(response.data.token);
    }

    return response.data;
  } catch (error) {
    // Clean up on login failure
    await deleteHardwareKey();
    await deleteAuthToken();
    hardwareKey = null;

    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<ServerResponse>;
      if (axiosError.response?.data?.message) {
        throw new Error(axiosError.response.data.message);
      }
    }
    throw error;
  }
}

export async function isAuthenticated(): Promise<boolean> {
  try {
    const result = await authenticatedRequest<AuthResponse>('get', '/authenticated');
    return result.authenticated;
  } catch {
    return false;
  }
}

export function logout(): void {
  deleteAuthToken().catch(console.error);
  deleteHardwareKey().catch(console.error);
  hardwareKey = null;
  accelerationKey = null;
  accelerationKeyId = null;
}