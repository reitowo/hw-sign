import axios from 'axios';

// Base URL for the API
const apiClient = axios.create({
  baseURL: 'https://api.example.com', // Replace with your API base URL
  headers: {
    'Content-Type': 'application/json',
  },
});

// Register method
export async function register(userData: { username: string; password: string }) {
  try {
    const response = await apiClient.post('/register', userData);
    return response.data;
  } catch (error) {
    console.error('Registration failed:', error);
    throw error;
  }
}

// Login method
export async function login(credentials: { username: string; password: string }) {
  try {
    const response = await apiClient.post('/login', credentials);
    return response.data;
  } catch (error) {
    console.error('Login failed:', error);
    throw error;
  }
}

// Dummy authenticated method
export async function isAuthenticated() {
  try {
    const response = await apiClient.get('/authenticated');
    return response.data.isAuthenticated;
  } catch (error) {
    console.error('Authentication check failed:', error);
    return false;
  }
}