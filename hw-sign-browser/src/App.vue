<script setup lang="ts">
import { ref } from 'vue';
import HelloWorld from './components/HelloWorld.vue';
import TheWelcome from './components/TheWelcome.vue';

const isAuthenticated = ref(false);
const message = ref('');

async function generateKeyPair() {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    );
    message.value = 'Key pair generated successfully!';
    console.log('Public Key:', keyPair.publicKey);
    console.log('Private Key:', keyPair.privateKey);
  } catch (error) {
    message.value = 'Error generating key pair: ' + error;
  }
}
</script>

<template>
  <header>
    <img alt="Vue logo" class="logo" src="./assets/logo.svg" width="125" height="125" />
    <div class="wrapper">
      <h1>Authentication Demo</h1>
      <HelloWorld msg="You did it!" />
    </div>
  </header>
  <main>
    <div v-if="!isAuthenticated">
      <button @click="generateKeyPair">Generate Key Pair</button>
      <p>{{ message }}</p>
    </div>
    <div v-else>
      <p>You are authenticated!</p>
    </div>
    <TheWelcome />
  </main>
</template>

<style scoped>
header {
  line-height: 1.5;
}
.logo {
  display: block;
  margin: 0 auto 2rem;
}
@media (min-width: 1024px) {
  header {
    display: flex;
    place-items: center;
    padding-right: calc(var(--section-gap) / 2);
  }
  .logo {
    margin: 0 2rem 0 0;
  }
  header .wrapper {
    display: flex;
    place-items: flex-start;
    flex-wrap: wrap;
  }
}
</style>
