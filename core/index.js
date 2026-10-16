'use strict';

/**
 * 共享评估引擎入口（网页版与桌面版共用）
 */
const { assess, TOOL_VERSION } = require('./engine');
const { buildMarkdown } = require('./report');
const { CHECKS, CATEGORIES } = require('./standards');

module.exports = { assess, buildMarkdown, CHECKS, CATEGORIES, TOOL_VERSION };
