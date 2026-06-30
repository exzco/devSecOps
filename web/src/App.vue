<template>
  <a-config-provider
    :theme="{
      token: {
        colorPrimary: '#09090b',
        colorBgBase: '#ffffff',
        colorTextBase: '#09090b',
        borderRadius: 6
      }
    }"
  >
    <router-view />
  </a-config-provider>
</template>

<script setup lang="ts">
</script>

<style>
#app {
  height: 100vh;
  width: 100vw;
  overflow: hidden;
}
</style>
