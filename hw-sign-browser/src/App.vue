<script setup lang="ts">
import { ref, watch, onMounted, computed } from 'vue';
import {
  register,
  login,
  logout,
  isAuthenticated as checkAuthService,
  toggleSymmetricEncryption,
  isSymmetricEncryptionEnabled
} from './services/authService';

// Reactive state
const isAuthenticated = ref(false);
const message = ref('');
const username = ref('');
const password = ref('');
const darkMode = ref(false);
const isLoading = ref(false);
const useSymmetric = ref(true);

// Computed properties for UI state
const messageClass = computed(() => ({
  'text-green-600 dark:text-green-400': message.value.includes('successful'),
  'text-red-600 dark:text-red-400': !message.value.includes('successful')
}));

const formIsValid = computed(() => username.value && password.value);

// Auth handlers
async function handleRegister() {
  if (!formIsValid.value) {
    message.value = 'Please enter both username and password';
    return;
  }

  await performAuthOperation(async () => {
    await register({ username: username.value, password: password.value });
    return 'Registration successful! Please log in.';
  });
}

async function handleLogin() {
  if (!formIsValid.value) {
    message.value = 'Please enter both username and password';
    return;
  }

  await performAuthOperation(async () => {
    await login({ username: username.value, password: password.value });
    isAuthenticated.value = true;
    return 'Login successful!';
  });
}

function handleLogout() {
  logout();
  isAuthenticated.value = false;
}

async function checkAuthentication() {
  await performAuthOperation(async () => {
    const authenticated = await checkAuthService();
    return authenticated
      ? 'You are successfully authenticated and token protected by hardware!'
      : 'You are not authenticated, something went wrong.';
  });
}

async function handleToggleEncryption() {
  try {
    useSymmetric.value = await toggleSymmetricEncryption();
    message.value = `Encryption mode changed to ${useSymmetric.value ? 'symmetric (ECDH/HMAC)' : 'asymmetric (signature-based)'}`;
  } catch (error) {
    console.error('Failed to toggle encryption mode:', error);
    message.value = 'Failed to change encryption mode';
  }
}

// Helper function to reduce repetitive code in auth operations
async function performAuthOperation(operation: () => Promise<string>) {
  isLoading.value = true;
  try {
    message.value = await operation();
  } catch (error) {
    message.value = error instanceof Error ? error.message : 'Operation failed';
    console.error('Auth operation failed:', error);
  } finally {
    isLoading.value = false;
  }
}

// Toggle dark mode
function toggleDarkMode() {
  darkMode.value = !darkMode.value;
}

// Initialization
onMounted(async () => {
  try {
    isLoading.value = true;

    // Check initial auth state and load preferences
    isAuthenticated.value = await checkAuthService();
    useSymmetric.value = isSymmetricEncryptionEnabled();

    // Setup dark mode based on saved preference or system preference
    initializeDarkMode();

    // Add cleanup handler
    window.addEventListener('unload', () => {
      if (!isAuthenticated.value) {
        logout();  // Clean up IndexedDB if not authenticated
      }
    });
  } catch (e) {
    console.debug('Initial setup failed:', e);
  } finally {
    isLoading.value = false;
  }
});

// Initialize dark mode based on saved preference or system preference
function initializeDarkMode() {
  darkMode.value = localStorage.getItem('darkMode') === 'true' ||
    (localStorage.getItem('darkMode') === null &&
      window.matchMedia('(prefers-color-scheme: dark)').matches);

  applyDarkMode();
}

// Apply dark mode to document
function applyDarkMode() {
  if (darkMode.value) {
    document.documentElement.classList.add('dark');
  } else {
    document.documentElement.classList.remove('dark');
  }
}

// Watch for dark mode changes to save preference and apply
watch(darkMode, (newValue) => {
  localStorage.setItem('darkMode', newValue.toString());
  applyDarkMode();
});
</script>

<template>
  <div class="min-h-screen w-full flex items-center justify-center bg-gray-100 dark:bg-gray-900">
    <!-- Loading overlay -->
    <div v-if="isLoading" class="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <div class="bg-white dark:bg-gray-800 rounded-lg p-4 flex flex-col items-center shadow-lg">
        <svg class="animate-spin h-8 w-8 text-indigo-600 dark:text-indigo-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
        <p class="mt-4 text-gray-700 dark:text-gray-300">Processing...</p>
      </div>
    </div>

    <div
      class="w-full max-w-lg bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8 border border-gray-200 dark:border-gray-700">
      <h1 class="text-2xl font-bold text-center mb-6 text-gray-900 dark:text-gray-100">User Authentication</h1>

      <!-- Login Form -->
      <div v-if="!isAuthenticated" class="space-y-6">
        <div>
          <label for="username" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Username</label>
          <input v-model="username" id="username" type="text" :disabled="isLoading"
            class="mt-2 block w-full rounded-lg border border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-gray-100 px-4 py-2"
            placeholder="Enter your username" />
        </div>
        <div>
          <label for="password" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Password</label>
          <input v-model="password" id="password" type="password" :disabled="isLoading"
            class="mt-2 block w-full rounded-lg border border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-gray-100 px-4 py-2"
            placeholder="Enter your password" />
        </div>
        <div class="flex justify-between">
          <button @click="handleRegister" :disabled="isLoading" class="btn-green">
            Register
          </button>
          <button @click="handleLogin" :disabled="isLoading" class="btn-primary">
            Login
          </button>
        </div>
      </div>

      <!-- Authenticated View -->
      <div v-else class="text-center">
        <p class="text-lg font-medium text-green-600 dark:text-green-400 mb-4">You are authenticated!</p>
        <div class="space-y-4">
          <button @click="checkAuthentication" :disabled="isLoading" class="btn-primary w-full">
            Check Hardware Sign Status
          </button>

          <button @click="handleToggleEncryption" class="btn-yellow w-full">
            {{ useSymmetric ? 'Using ECDH+HMAC (Faster)' : 'Using Asymmetric Signatures' }}
          </button>

          <button @click="handleLogout" class="btn-danger w-full">
            Logout
          </button>
        </div>
      </div>

      <!-- Status message -->
      <p class="mt-4 text-center text-sm" :class="messageClass">
        {{ message ?? 'Ready' }}
      </p>

      <!-- Dark mode toggle -->
      <div class="mt-6 flex justify-end">
        <button @click="toggleDarkMode"
          class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 text-2xl">
          {{ darkMode ? '☀️' : '🌙' }}
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
body {
  font-family: 'Inter', sans-serif;
}

/* Button styles */
.btn-primary {
  @apply bg-indigo-600 text-white py-2 px-4 rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900 disabled:opacity-50 disabled:cursor-not-allowed;
}

.btn-green {
  @apply bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900 disabled:opacity-50 disabled:cursor-not-allowed;
}

.btn-yellow {
  @apply bg-yellow-600 text-white py-2 px-4 rounded-lg hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900;
}

.btn-danger {
  @apply bg-red-600 text-white py-2 px-4 rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2;
}

/* Add styles for the loading overlay */
.fixed {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
}

.bg-opacity-50 {
  background-color: rgba(0, 0, 0, 0.5);
}

.z-50 {
  z-index: 50;
}
</style>
