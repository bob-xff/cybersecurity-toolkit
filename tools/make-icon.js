#!/usr/bin/env node
'use strict';

/**
 * 生成应用图标（零依赖：手写 PNG 编码 + ICO 封装）
 *
 * 设计：简约 · 淡粉 · 无渐变 —— 圆角方形浅粉底 + 深玫瑰色「轨道 / 电子」标志。
 * （沿用 Electron 默认图标「原子轨道」的构图，整体改造为粉色系。）
 *
 * 输出：
 *   desktop/build/icon.png  512×512
 *   desktop/build/icon.ico  16/32/48/64/128/256（PNG 载荷）
 *
 * electron-builder 会优先读取 build/icon.ico，其次 build/icon.png。
 *
 * 用法: node tools/make-icon.js
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const OUT_DIR = path.resolve(__dirname, '..', 'desktop', 'build');

/* ---------- 配色（RGB） ---------- */
const C_BG = [249, 168, 212];    // #F9A8D4 浅粉
const C_MARK = [190, 24, 93];    // #BE185D 深玫瑰（轨道 / 核 / 电子）

/* ---------- 几何工具 ---------- */
/** 圆角方形命中判定 */
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

/** 点到「旋转椭圆轮廓」的近似带符号距离（负=内侧，0=线上）
 *  在半轴端点处精确，中间区段为视觉可接受的一阶近似。 */
function ellipseRingDist(x, y, cx, cy, a, b, theta) {
  const dx = x - cx;
  const dy = y - cy;
  const ct = Math.cos(theta);
  const st = Math.sin(theta);
  const u = dx * ct + dy * st;   // 旋转 -theta
  const v = -dx * st + dy * ct;
  const f = (u * u) / (a * a) + (v * v) / (b * b);
  const rl = Math.sqrt(u * u + v * v) || 1e-9;
  return (Math.sqrt(f) - 1) * rl;
}

function inCircle(x, y, cx, cy, r) {
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

/* ---------- 单像素采样（返回 RGBA） ---------- */
/* 构图（按 size 归一化）：
 *   三条约 0° / 60° / 120° 的椭圆轨道 + 中心核 + 三条轨道远端的电子点 */
const ORBITS = [0, Math.PI / 3, (2 * Math.PI) / 3];

function sample(x, y, size) {
  if (!inRoundRect(x, y, size, size * 0.22)) return [0, 0, 0, 0];

  const cx = size / 2;
  const cy = size / 2;
  const a = size * 0.355;          // 轨道长半轴
  const b = size * 0.118;          // 轨道短半轴
  const halfW = size * 0.022;      // 轨道线半宽
  const rNucleus = size * 0.058;   // 中心核半径
  const rDot = size * 0.042;       // 电子点半径

  // 中心核优先（盖住轨道交叉处的杂乱）
  if (inCircle(x, y, cx, cy, rNucleus)) return [...C_MARK, 255];

  // 电子点
  for (const th of ORBITS) {
    const px = cx + a * Math.cos(th);
    const py = cy + a * Math.sin(th);
    if (inCircle(x, y, px, py, rDot)) return [...C_MARK, 255];
  }

  // 轨道线
  for (const th of ORBITS) {
    if (Math.abs(ellipseRingDist(x, y, cx, cy, a, b, th)) <= halfW) return [...C_MARK, 255];
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

/* ---------- 主流程 ---------- */
fs.mkdirSync(OUT_DIR, { recursive: true });

const sizes = [256, 128, 64, 48, 32, 16];
const rendered = new Map();
for (const s of [...sizes, 512]) rendered.set(s, render(s));

const png512 = encodePng(512, rendered.get(512));
fs.writeFileSync(path.join(OUT_DIR, 'icon.png'), png512);

const ico = encodeIco(sizes.map((s) => ({ size: s, png: encodePng(s, rendered.get(s)) })));
fs.writeFileSync(path.join(OUT_DIR, 'icon.ico'), ico);

process.stdout.write(
  `[make-icon] icon.png 512×512 (${png512.length} B)\n` +
  `[make-icon] icon.ico ${sizes.join('/')} (${ico.length} B)\n`
);
