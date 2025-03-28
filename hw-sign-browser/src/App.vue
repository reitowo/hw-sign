<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import { register, login, logout, isAuthenticated as checkAuthService } from './services/authService';

const isAuthenticated = ref(false);
const message = ref('');
const username = ref('');
const password = ref('');
const darkMode = ref(false);
const isLoading = ref(false);

async function handleRegister() {
  if (!username.value || !password.value) {
    message.value = 'Please enter both username and password';
    return;
  }

  isLoading.value = true;
  message.value = '';
  try {
    await register({ username: username.value, password: password.value });
    message.value = 'Registration successful! Please log in.';
  } catch (error) {
    message.value = error instanceof Error ? error.message : 'Registration failed';
  } finally {
    isLoading.value = false;
  }
}

async function handleLogin() {
  if (!username.value || !password.value) {
    message.value = 'Please enter both username and password';
    return;
  }

  isLoading.value = true;
  message.value = '';
  try {
    await login({ username: username.value, password: password.value });
    isAuthenticated.value = true;
    message.value = 'Login successful!';
  } catch (error) {
    message.value = error instanceof Error ? error.message : 'Login failed';
    isAuthenticated.value = false;
  } finally {
    isLoading.value = false;
  }
}

function handleLogout() {
  logout();
  isAuthenticated.value = false;
  message.value = '';
}

async function checkAuthentication() {
  isLoading.value = true;
  try {
    const authenticated = await checkAuthService();
    if (authenticated) {
      message.value = 'You are successfully authenticated and token protected by hardware!';
    } else {
      message.value = 'You are not authenticated, something went wrong.';
    }
  } catch (error) {
    message.value = error instanceof Error ? error.message : 'Error checking authentication';
    console.error('Auth check failed:', error);
  } finally {
    isLoading.value = false;
  }
}

// Move dark mode initialization to onMounted
onMounted(async () => {
  // Check initial auth state
  try {
    isAuthenticated.value = await checkAuthService();
  } catch (e) {
    console.debug('Initial auth check failed:', e);
  }

  // Setup dark mode
  darkMode.value = localStorage.getItem('darkMode') === 'true' ||
    (localStorage.getItem('darkMode') === null && window.matchMedia('(prefers-color-scheme: dark)').matches);

  // Apply initial dark mode
  if (darkMode.value) {
    document.documentElement.classList.add('dark');
  }

  // Add cleanup handler
  window.addEventListener('unload', () => {
    if (!isAuthenticated.value) {
      logout();  // This will clean up IndexedDB if not authenticated
    }
  });
});

watch(darkMode, (newValue) => {
  if (newValue) {
    document.documentElement.classList.add('dark');
  } else {
    document.documentElement.classList.remove('dark');
  }
  localStorage.setItem('darkMode', newValue.toString());
});
</script>

<template>
  <div class="min-h-screen w-full flex items-center justify-center bg-gray-100 dark:bg-gray-900">
    <div
      class="w-full max-w-lg bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8 border border-gray-200 dark:border-gray-700">
      <h1 class="text-2xl font-bold text-center mb-6 text-gray-900 dark:text-gray-100">User Authentication</h1>

      <div v-if="!isAuthenticated">
        <div class="mb-6">
          <label for="username" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Username</label>
          <input v-model="username" id="username" type="text" :disabled="isLoading"
            class="mt-2 block w-full rounded-lg border border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-gray-100 px-4 py-2"
            placeholder="Enter your username" />
        </div>
        <div class="mb-6">
          <label for="password" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Password</label>
          <input v-model="password" id="password" type="password" :disabled="isLoading"
            class="mt-2 block w-full rounded-lg border border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-gray-100 px-4 py-2"
            placeholder="Enter your password" />
        </div>
        <div class="flex justify-between">
          <button @click="handleRegister" :disabled="isLoading"
            class="bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900 disabled:opacity-50 disabled:cursor-not-allowed">
            Register
          </button>
          <button @click="handleLogin" :disabled="isLoading"
            class="bg-indigo-600 text-white py-2 px-4 rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900 disabled:opacity-50 disabled:cursor-not-allowed">
            Login
          </button>
        </div>
      </div>

      <div v-else class="text-center">
        <p class="text-lg font-medium text-green-600 dark:text-green-400 mb-4">You are authenticated!</p>
        <div class="space-y-4">
          <button @click="checkAuthentication" :disabled="isLoading"
            class="bg-indigo-600 text-white py-2 px-4 rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900 disabled:opacity-50 disabled:cursor-not-allowed w-full">
            Check Hardware Sign Status
          </button>
          <button @click="handleLogout"
            class="bg-red-600 text-white py-2 px-4 rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 w-full">
            Logout
          </button>
        </div>
      </div>

      <p v-if="message" class="mt-4 text-center text-sm" :class="{
        'text-green-600 dark:text-green-400': message.includes('successful'),
        'text-red-600 dark:text-red-400': !message.includes('successful')
      }">
        {{ message }}
      </p>

      <div class="mt-6 flex justify-end">
        <button @click="() => darkMode = !darkMode"
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
</style>
