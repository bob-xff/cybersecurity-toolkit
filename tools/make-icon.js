#!/usr/bin/env node
'use strict';

/**
 * 生成应用图标（零依赖：手写 PNG 编码 + ICO 封装 + SVG）
 *
 * 设计说明（v2，2026-11）：
 *   旧版是 Electron 默认「原子轨道」图标的粉色改色。轨道/电子与安全评估没有关系，
 *   属于历史遗留构图。本版改为与工具定位直接对应的符号：
 *     · 盾牌   → 安全防护 / 合规基线
 *     · 放大镜 → 检测、审查、发现隐患（而不是「已通过」）
 *   配色沿用项目淡粉基调：浅粉圆角底 + 深玫瑰盾 + 近白放大镜，零渐变、扁平化，
 *   在 16px 任务栏图标下仍可辨识。
 *
 * 输出：
 *   desktop/build/icon.png   512×512
 *   desktop/build/icon.ico   16/32/48/64/128/256（PNG 载荷）
 *   desktop/build/logo.svg   矢量源文件（与 UI 内联 SVG 同一套几何常量）
 *   ui/logo.svg              共享前端使用的同一矢量文件
 *
 * electron-builder 会优先读取 build/icon.ico，其次 build/icon.png。
 *
 * 用法: node tools/make-icon.js
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const OUT_DIR = path.resolve(__dirname, '..', 'desktop', 'build');
const UI_DIR = path.resolve(__dirname, '..', 'ui');

/* ---------- 配色 ---------- */
const C_BG = [249, 168, 212];     // #F9A8D4 浅粉
const C_MARK = [190, 24, 93];     // #BE185D 深玫瑰（盾）
const C_PAPER = [255, 247, 251];  // #FFF7FB 近白（放大镜）

/* ---------- 几何常量（归一化到 size，PNG 与 SVG 同源） ---------- */
const SHIELD = [
  [0.20, 0.17], [0.50, 0.13], [0.80, 0.17], [0.80, 0.50],
  [0.74, 0.68], [0.50, 0.87], [0.26, 0.68], [0.20, 0.50],
];
const LENS = { cx: 0.46, cy: 0.43, r: 0.135, w: 0.024 };  // w = 圆环线半宽
const HANDLE = { x1: 0.56, y1: 0.53, x2: 0.66, y2: 0.63, w: 0.028 };

function inRoundRect(x, y, size, radius) {
  const r = radius;
  if (x >= r && x <= size - r) return y >= 0 && y <= size;
  if (y >= r && y <= size - r) return x >= 0 && x <= size;
  const cx = Math.min(Math.max(x, r), size - r);
  const cy = Math.min(Math.max(y, r), size - r);
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

function segDist(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const denom = dx * dx + dy * dy || 1e-9;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / denom));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

/** 点是否在多边形内（射线法）。盾形用多边形而非椭圆，边界更利落 */
function inPolygon(x, y, pts) {
  let inside = false;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
    const xi = pts[i][0], yi = pts[i][1];
    const xj = pts[j][0], yj = pts[j][1];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function inCircle(x, y, cx, cy, r) {
  const dx = x - cx, dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

/* ---------- 单像素采样（返回 RGBA） ---------- */
function sample(x, y, size) {
  if (!inRoundRect(x, y, size, size * 0.22)) return [0, 0, 0, 0];
  const nx = x / size, ny = y / size;

  if (inPolygon(nx, ny, SHIELD)) {
    const d = Math.hypot(nx - LENS.cx, ny - LENS.cy);
    // 放大镜圆环
    if (Math.abs(d - LENS.r) <= LENS.w) return [...C_PAPER, 255];
    // 放大镜手柄（线段 + 圆头）
    if (segDist(nx, ny, HANDLE.x1, HANDLE.y1, HANDLE.x2, HANDLE.y2) <= HANDLE.w) return [...C_PAPER, 255];
    return [...C_MARK, 255];
  }
  return [...C_BG, 255];
}

/* ---------- 超采样渲染 ---------- */
function render(size, ss = 3) {
  const out = Buffer.alloc(size * size * 4);
  const n = ss * ss;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const c = sample((x * ss + sx + 0.5) / ss, (y * ss + sy + 0.5) / ss, size);
          const af = c[3] / 255;
          r += c[0] * af; g += c[1] * af; b += c[2] * af; a += c[3];
        }
      }
      const avgA = a / n;
      const i = (y * size + x) * 4;
      if (avgA === 0) { out[i] = out[i + 1] = out[i + 2] = out[i + 3] = 0; continue; }
      const alphaSum = a / 255;   // 预乘还原
      out[i] = Math.round(r / alphaSum);
      out[i + 1] = Math.round(g / alphaSum);
      out[i + 2] = Math.round(b / alphaSum);
      out[i + 3] = Math.round(avgA);
    }
  }
  return out;
}

/* ---------- PNG 编码 ---------- */
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // color type RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0; // filter: none
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/* ---------- ICO 封装（PNG 载荷） ---------- */
function encodeIco(entries) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);            // type: icon
  header.writeUInt16LE(entries.length, 4);

  const dir = Buffer.alloc(16 * entries.length);
  let offset = 6 + dir.length;
  const blobs = [];
  entries.forEach((e, i) => {
    const o = i * 16;
    dir[o] = e.size >= 256 ? 0 : e.size;
    dir[o + 1] = e.size >= 256 ? 0 : e.size;
    dir[o + 2] = 0; dir[o + 3] = 0;
    dir.writeUInt16LE(1, o + 4);         // planes
    dir.writeUInt16LE(32, o + 6);        // bpp
    dir.writeUInt32LE(e.png.length, o + 8);
    dir.writeUInt32LE(offset, o + 12);
    offset += e.png.length;
    blobs.push(e.png);
  });
  return Buffer.concat([header, dir, ...blobs]);
}

/* ---------- SVG（与 PNG 共用 SHIELD / LENS / HANDLE 常量） ---------- */
function buildSvg() {
  const pts = SHIELD.map(([x, y]) => (x * 64).toFixed(2) + ' ' + (y * 64).toFixed(2)).join(' L');
  const cx = (LENS.cx * 64).toFixed(2), cy = (LENS.cy * 64).toFixed(2);
  const r = (LENS.r * 64).toFixed(2), lensW = (LENS.w * 2 * 64).toFixed(2);
  const hx1 = (HANDLE.x1 * 64).toFixed(2), hy1 = (HANDLE.y1 * 64).toFixed(2);
  const hx2 = (HANDLE.x2 * 64).toFixed(2), hy2 = (HANDLE.y2 * 64).toFixed(2);
  const handleW = (HANDLE.w * 2 * 64).toFixed(2);
  return [
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="网站安全评估工具">',
    '  <rect width="64" height="64" rx="14" fill="#F9A8D4"/>',
    '  <path d="M' + pts + ' Z" fill="#BE185D"/>',
    '  <circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="#FFF7FB" stroke-width="' + lensW + '"/>',
    '  <path d="M' + hx1 + ' ' + hy1 + ' L' + hx2 + ' ' + hy2 + '" stroke="#FFF7FB" stroke-width="' + handleW + '" stroke-linecap="round"/>',
    '</svg>',
    '',
  ].join('\n');
}

/* ---------- 主流程 ---------- */
fs.mkdirSync(OUT_DIR, { recursive: true });
fs.mkdirSync(UI_DIR, { recursive: true });

const sizes = [256, 128, 64, 48, 32, 16];
const rendered = new Map();
for (const s of [...sizes, 512]) rendered.set(s, render(s));

const png512 = encodePng(512, rendered.get(512));
fs.writeFileSync(path.join(OUT_DIR, 'icon.png'), png512);

const ico = encodeIco(sizes.map((s) => ({ size: s, png: encodePng(s, rendered.get(s)) })));
fs.writeFileSync(path.join(OUT_DIR, 'icon.ico'), ico);

const svg = buildSvg();
fs.writeFileSync(path.join(OUT_DIR, 'logo.svg'), svg);
fs.writeFileSync(path.join(UI_DIR, 'logo.svg'), svg);

process.stdout.write(
  `[make-icon] icon.png 512×512 (${png512.length} B)\n` +
  `[make-icon] icon.ico ${sizes.join('/')} (${ico.length} B)\n` +
  `[make-icon] logo.svg → desktop/build/ 与 ui/\n`
);
