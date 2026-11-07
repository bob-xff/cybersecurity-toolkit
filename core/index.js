'use strict';

/**
 * 共享评估引擎入口（网页版与桌面版共用）
 *
 * 模块边界：
 *   engine    编排与评分（唯一对外评估入口）
 *   standards 标准与检查项定义
 *   report    Markdown 报告渲染
 *   config    集中配置（超时 / 上限 / 并发）
 *   logger    结构化日志
 *   errors    统一错误模型
 * 其余 fetcher/tls/dnschk/content/libcheck/exposure 为内部采集模块，
 * 外部代码不应直接依赖，以免绕过引擎的前置条件与警告汇总。
 */
const { assess, TOOL_VERSION } = require('./engine');
const { buildMarkdown } = require('./report');
const { CHECKS, CATEGORIES } = require('./standards');
const CONFIG = require('./config');
const logger = require('./logger');
const errors = require('./errors');

module.exports = { assess, buildMarkdown, CHECKS, CATEGORIES, TOOL_VERSION, CONFIG, logger, errors };
