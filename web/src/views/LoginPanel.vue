<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { identityClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';

const emit = defineEmits<{ (e: 'loggedIn'): void }>();

const username = ref('admin');
const password = ref('');
const captchaID = ref('');
const captchaImg = ref(''); // data: URL
const captchaAnswer = ref('');
const submitting = ref(false);
const errMsg = ref('');

async function loadCaptcha() {
  errMsg.value = '';
  try {
    const r = await identityClient.getCaptcha({});
    captchaID.value = r.captchaId;
    // Uint8Array → base64 data URL
    let bin = '';
    for (const b of r.imagePng) bin += String.fromCharCode(b);
    captchaImg.value = 'data:image/png;base64,' + btoa(bin);
    captchaAnswer.value = '';
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

onMounted(loadCaptcha);

async function submit() {
  if (submitting.value) return;
  submitting.value = true;
  errMsg.value = '';
  try {
    const res = await identityClient.login({
      username: username.value,
      password: password.value,
      captchaId: captchaID.value,
      captchaAnswer: captchaAnswer.value,
    });
    if (!res.user) {
      errMsg.value = '后端未返回 user';
      return;
    }
    authStore.set({
      token: res.accessToken,
      username: res.user.username,
      role: res.user.role,
      userId: res.user.id,
      expiresAt: res.expiresAt?.toDate().toISOString(),
    });
    emit('loggedIn');
  } catch (e) {
    errMsg.value = errorMessage(e);
    // 验证码已被消费 → 刷新一张
    await loadCaptcha();
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <div class="card" style="max-width: 480px; margin: 32px auto">
    <h2>登录</h2>
    <p class="muted">
      首次启动用 ADMIN_BOOTSTRAP_PASSWORD 或 stdout 输出的随机密码登录 admin。
    </p>

    <div class="stack" style="margin-top: 12px">
      <div class="row">
        <label class="label">用户名</label>
        <input v-model="username" :disabled="submitting" />
      </div>
      <div class="row">
        <label class="label">密码</label>
        <input
          v-model="password"
          type="password"
          :disabled="submitting"
          @keyup.enter="submit"
        />
      </div>
      <div class="row">
        <label class="label">验证码</label>
        <input
          v-model="captchaAnswer"
          :disabled="submitting"
          style="width: 120px"
          @keyup.enter="submit"
        />
        <img
          v-if="captchaImg"
          :src="captchaImg"
          alt="captcha"
          class="captcha-img"
          title="点击刷新"
          @click="loadCaptcha"
        />
      </div>
      <div class="row" style="margin-top: 8px">
        <button
          class="primary"
          :disabled="submitting || !username || !password || !captchaAnswer"
          @click="submit"
        >
          {{ submitting ? '登录中…' : '登录' }}
        </button>
      </div>
      <div v-if="errMsg" class="error">{{ errMsg }}</div>
    </div>
  </div>
</template>
