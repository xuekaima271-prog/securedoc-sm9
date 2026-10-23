<script setup>
// 内联 SVG 线性图标（零依赖、无外链，满足 CSP）。图标集为手写 24×24 描边路径，
// 统一 stroke=currentColor，由父级 CSS 控制尺寸与颜色。
defineProps({ name: { type: String, required: true } });

const ICONS = {
  seal: {
    paths: ['M12 2.8 19.5 7v10L12 21.2 4.5 17V7L12 2.8Z', 'M10.8 10.2V8.9a1.2 1.2 0 0 1 2.4 0v1.3'],
    rects: [[9.2, 10.2, 5.6, 4.8, 1]],
  },
  send: { paths: ['M22 2 11 13', 'M22 2 15 22l-4-9-9-4Z'] },
  inbox: {
    paths: ['M22 12h-6l-2 3h-4l-2-3H2',
      'M5.5 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.7 4H7.3a2 2 0 0 0-1.8 1.1Z'],
  },
  outbox: { paths: ['M12 15V5', 'M6.8 10.2 12 5l5.2 5.2', 'M4 20h16'] },
  key: {
    circles: [[7.8, 15.8, 4.3]],
    paths: ['M11 12.6 20 3.6', 'M15.2 8.4l2.8 2.8'],
  },
  users: {
    circles: [[9, 8, 3.2]],
    paths: ['M3.5 19.5c.6-3 2.8-4.5 5.5-4.5s4.9 1.5 5.5 4.5', 'M16 5.2a3.2 3.2 0 0 1 0 6.1', 'M17.5 15.3c1.7.6 2.7 1.9 3 4.2'],
  },
  database: {
    ellipses: [[12, 5.5, 9, 2.5]],
    paths: ['M3 5.5v13c0 1.4 4 2.5 9 2.5s9-1.1 9-2.5v-13', 'M3 12c0 1.4 4 2.5 9 2.5s9-1.1 9-2.5'],
  },
  audit: {
    rects: [[5.5, 4.5, 13, 17, 2], [9.3, 2.6, 5.4, 3.6, 1]],
    paths: ['M9.3 11h5.4', 'M9.3 15h5.4'],
  },
  shield: { paths: ['M12 3l7 2.8v5.4c0 4.4-2.9 7.4-7 8.8-4.1-1.4-7-4.4-7-8.8V5.8L12 3Z', 'M12 8.5V13', 'M12 16.2h.01'] },
  flask: { paths: ['M9.5 3h5', 'M10.5 3v5.2L5 17.8A2.2 2.2 0 0 0 7.1 21h9.8A2.2 2.2 0 0 0 19 17.8L13.5 8.2V3', 'M7.5 14.5h9'] },
  file: { paths: ['M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8.5L14 3Z', 'M14 3v5.5h5'] },
  lock: { rects: [[5.5, 10.5, 13, 9.5, 2]], paths: ['M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5'] },
  unlock: { rects: [[5.5, 10.5, 13, 9.5, 2]], paths: ['M8.5 10.5V8a3.5 3.5 0 0 1 6.8-1.3'] },
  download: { paths: ['M12 4v10.5', 'M7 10.5l5 5 5-5', 'M4.5 20h15'] },
  checkCircle: { circles: [[12, 12, 8.5]], paths: ['M8.5 12.2 11 14.7 15.5 9.8'] },
  logout: { paths: ['M14 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3', 'M10 8l-4 4 4 4', 'M6 12h11'] },
  note: { paths: ['M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8.5L14 3Z', 'M14 3v5.5h5', 'M9 12.5h6', 'M9 16h4'] },
  refresh: { paths: ['M20.5 12a8.5 8.5 0 1 1-2.5-5.9', 'M21 3.5V9h-5.5'] },
};
</script>

<template>
  <svg class="ic" viewBox="0 0 24 24" width="1.15em" height="1.15em" fill="none" stroke="currentColor"
       stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path v-for="(d, i) in (ICONS[name]?.paths || [])" :key="'p' + i" :d="d" />
    <circle v-for="(c, i) in (ICONS[name]?.circles || [])" :key="'c' + i" :cx="c[0]" :cy="c[1]" :r="c[2]" />
    <ellipse v-for="(e, i) in (ICONS[name]?.ellipses || [])" :key="'e' + i" :cx="e[0]" :cy="e[1]" :rx="e[2]" :ry="e[3]" />
    <rect v-for="(r, i) in (ICONS[name]?.rects || [])" :key="'r' + i" :x="r[0]" :y="r[1]" :width="r[2]" :height="r[3]" :rx="r[4] || 0" />
  </svg>
</template>
