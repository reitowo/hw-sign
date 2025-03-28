<script setup lang="ts">
import { ref, watch } from 'vue';
import { login, isAuthenticated as checkAuthService } from './services/authService';

const isAuthenticated = ref(false);
const message = ref('');
const username = ref('');
const password = ref('');
const darkMode = ref(false);

async function handleLogin() {
  try {
    const response = await login({ username: username.value, password: password.value });
    if (response.success) {
      isAuthenticated.value = true;
      message.value = 'Login successful!';
    } else {
      message.value = 'Login failed: ' + response.message;
    }
  } catch (error) {
    message.value = 'Error during login: ' + error;
  }
}

async function checkAuthentication() {
  isAuthenticated.value = await checkAuthService();
}

watch(darkMode, (newValue) => {
  if (newValue) {
    document.documentElement.classList.add('dark');
  } else {
    document.documentElement.classList.remove('dark');
  }
});
</script>

<template>
  <div class="min-h-screen w-full flex items-center justify-center bg-gray-100 dark:bg-gray-900">
    <div class="w-full max-w-lg bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8 border border-gray-200 dark:border-gray-700">
      <h1 class="text-2xl font-bold text-center mb-6 text-gray-900 dark:text-gray-100">Login</h1>
      <div v-if="!isAuthenticated">
        <div class="mb-6">
          <label for="username" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Username</label>
          <input v-model="username" id="username" type="text" class="mt-2 block w-full rounded-lg border border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-gray-100 px-4 py-2" placeholder="Enter your username" />
        </div>
        <div class="mb-6">
          <label for="password" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Password</label>
          <input v-model="password" id="password" type="password" class="mt-2 block w-full rounded-lg border border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-gray-100 px-4 py-2" placeholder="Enter your password" />
        </div>
        <button @click="handleLogin" class="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900">Login</button>
        <p class="mt-4 text-center text-sm text-gray-600 dark:text-gray-400">{{ message }}</p>
      </div>
      <div v-else>
        <p class="text-center text-lg font-medium text-green-600 dark:text-green-400">You are authenticated!</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
body {
  font-family: 'Inter', sans-serif;
}
</style>
