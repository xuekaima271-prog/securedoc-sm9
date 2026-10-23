import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { contentSecurityPolicy, securityHeaders } from './security-policy.js';

// dev：前端 :5173 通过代理转发 /api → 后端 :8080（同源，免 CORS/Cookie 跨站问题）。
// 后端另配了 CORS 白名单（BE-5），用于前端独立部署直连后端的场景。
export default defineConfig(({ command, isPreview }) => ({
  plugins: [vue(), {
    name: 'document-security-policy',
    transformIndexHtml() {
      // Protect standalone dist hosting as well as the dev/preview HTTP response.
      return [{ tag: 'meta', attrs: {
        'http-equiv': 'Content-Security-Policy',
        content: contentSecurityPolicy(command === 'serve' && !isPreview),
      }, injectTo: 'head-prepend' }];
    },
  }],
  server: {
    host: '127.0.0.1',
    port: 5173,
    headers: securityHeaders(true),
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
  preview: {
    host: '127.0.0.1',
    headers: securityHeaders(),
    proxy: { '/api': { target: 'http://localhost:8080', changeOrigin: true } },
  },
}));
