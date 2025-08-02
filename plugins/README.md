# DFS2 插件开发指南

DFS2 支持基于 JavaScript 的插件系统，允许开发者使用 JavaScript 代码扩展系统功能。本指南将详细介绍如何开发、部署和调试 DFS2 插件。

## 目录

- [插件类型](#插件类型)
- [开发环境设置](#开发环境设置)
- [插件API参考](#插件api参考)
- [开发示例](#开发示例)
- [最佳实践](#最佳实践)
- [调试和测试](#调试和测试)
- [部署指南](#部署指南)

## 插件类型

DFS2 支持两种主要的插件类型：

### 1. 流控制插件 (Flow Control Plugins)

流控制插件在资源请求流程中执行，用于服务器选择、负载均衡和路由决策。

**文件命名**: 任意有效JavaScript文件名 (例如: `load_balancer.js`, `geo_router.js`)

**触发时机**: 在处理资源请求时，按照配置的flow顺序执行

### 2. 挑战验证插件 (Challenge Plugins)

挑战验证插件处理用户身份验证和人机验证，支持第三方服务集成。

**文件命名**: 必须以 `web_challenge_` 开头 (例如: `web_challenge_recaptcha.js`)

**触发时机**: 在需要验证用户挑战响应时执行

## 开发环境设置

### 1. 目录结构

```
plugins/
├── README.md                    # 本文档
├── load_balancer.js            # 流控制插件示例
├── web_challenge_recaptcha.js  # reCAPTCHA验证插件
├── web_challenge_turnstile.js  # Cloudflare Turnstile插件
├── web_challenge_math.js       # 数学验证插件
├── private_custom_plugin.js    # 私有插件 (不会被git跟踪)
└── test_*.js                   # 测试插件
```

### 2. 私有插件

以 `private_` 开头的插件文件会被 `.gitignore` 排除，适合存放包含敏感信息的插件：

```javascript
// private_production_secrets.js
exports = async function(context, challengeData, options, extras) {
    const secretKey = "your-secret-api-key"; // 不会被提交到git
    // 实现逻辑...
}
```

### 3. 配置插件

在 `config.yaml` 中配置插件参数：

```yaml
plugins:
  web_challenge_recaptcha:
    recaptcha_site_key: "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
    recaptcha_secret_key: "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
    verification_base_url: "https://your-verification-server.com"
  
  load_balancer:
    prefer_region: "us-east-1"
    max_retries: 3
```

## 插件API参考

### 流控制插件API

```javascript
/**
 * 流控制插件入口函数
 * @param {Array} pool - 当前服务器池 [[server_name, weight], ...]
 * @param {boolean} indirect - 是否为间接访问
 * @param {Object} options - 插件配置选项
 * @param {Object} extras - 额外的请求上下文信息
 * @returns {Array} [should_break: boolean, new_pool: Array]
 */
exports = async function(pool, indirect, options, extras) {
    // 返回 [是否中断后续插件执行, 新的服务器池]
    return [false, pool];
}
```

**参数说明**:
- `pool`: 二维数组，每个元素为 `[服务器名称, 权重]`
- `indirect`: 布尔值，表示是否为间接访问
- `options`: 从 `config.yaml` 中对应插件的配置对象
- `extras`: 包含请求IP、用户代理、时间戳等额外信息

**返回值**:
- `should_break`: 是否停止执行后续插件
- `new_pool`: 修改后的服务器池

### 挑战验证插件API

```javascript
/**
 * 挑战验证插件入口函数
 * @param {string} context - 执行上下文: "generate" 或 "verify"
 * @param {Object} challengeData - 挑战数据
 * @param {Object} options - 插件配置选项
 * @param {Object} extras - 额外的请求上下文信息
 * @returns {Object} 生成结果或验证结果
 */
exports = async function(context, challengeData, options, extras) {
    if (context === "generate") {
        // 生成阶段：创建验证挑战
        return {
            url: "https://verification-server.com/verify?token=...",
            token: "verification_token",
            expires_in: 300,
            additional_data: { /* 自定义数据 */ }
        };
    } else if (context === "verify") {
        // 验证阶段：验证用户提交的响应
        return {
            success: true,    // 或 false
            error: null       // 错误信息 (可选)
        };
    }
}
```

### 内置函数API

DFS2 为插件提供了以下内置函数：

#### 1. 存储操作

```javascript
// 读取存储的数据
const value = await _dfs_storage_read("key");

// 写入数据到存储 (可选过期时间，秒)
await _dfs_storage_write("key", "value", 3600);
```

#### 2. 签名生成

```javascript
// 生成S3签名
const signedUrl = await _dfs_s3sign(baseUrl, filePath, headers);

// 生成DFS节点签名
const signedUrl = await _dfs_dfsnodesign(baseUrl, filePath, uuid, ranges);
```

#### 3. HTTP请求

```javascript
// 标准fetch API可用
const response = await fetch("https://api.example.com/data", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: "value" })
});
const data = await response.json();
```

#### 4. 日志输出

```javascript
// 控制台输出 (会被记录到DFS2日志系统)
console.log("插件执行信息");
console.error("错误信息");
```

## 开发示例

### 1. 简单负载均衡插件

```javascript
// simple_load_balancer.js
exports = async function(pool, indirect, options, extras) {
    // 过滤掉权重为0的服务器
    const activePool = pool.filter(([name, weight]) => weight > 0);
    
    // 如果有首选区域配置，优先选择该区域的服务器
    if (options.prefer_region) {
        const preferredServers = activePool.filter(([name, weight]) => 
            name.includes(options.prefer_region)
        );
        if (preferredServers.length > 0) {
            return [false, preferredServers];
        }
    }
    
    return [false, activePool];
}
```

### 2. 地理位置路由插件

```javascript
// geo_router.js
exports = async function(pool, indirect, options, extras) {
    const clientIP = extras.client_ip;
    
    // 使用简单的IP前缀判断地区 (生产环境建议使用更精确的GeoIP库)
    const isChinaIP = clientIP.startsWith("117.") || 
                      clientIP.startsWith("118.") ||
                      clientIP.startsWith("119.");
    
    // 根据地理位置选择服务器
    const filteredPool = pool.filter(([name, weight]) => {
        if (isChinaIP) {
            return name.includes("china") || name.includes("asia");
        } else {
            return name.includes("global") || name.includes("us");
        }
    });
    
    return [false, filteredPool.length > 0 ? filteredPool : pool];
}
```

### 3. reCAPTCHA验证插件

```javascript
// web_challenge_recaptcha.js
exports = async function(context, challengeData, options, extras) {
    if (context === "generate") {
        // 生成reCAPTCHA验证页面URL
        const token = generateRandomToken();
        await _dfs_storage_write(`recaptcha_${token}`, JSON.stringify({
            ip: extras.client_ip,
            timestamp: Date.now()
        }), 600); // 10分钟过期
        
        return {
            url: `${options.verification_base_url}/recaptcha?token=${token}&site_key=${options.recaptcha_site_key}`,
            token: token,
            expires_in: 600
        };
    } else if (context === "verify") {
        // 验证reCAPTCHA响应
        const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `secret=${options.recaptcha_secret_key}&response=${challengeData.response}&remoteip=${extras.client_ip}`
        });
        
        const result = await response.json();
        return {
            success: result.success,
            error: result.success ? null : "reCAPTCHA验证失败"
        };
    }
}

function generateRandomToken() {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
}
```

### 4. 缓存和性能优化插件

```javascript
// intelligent_cache.js
exports = async function(pool, indirect, options, extras) {
    const cacheKey = `server_health_${Date.now().toString().slice(0, -4)}`; // 10秒精度
    
    // 尝试从缓存获取服务器健康状态
    let healthData = await _dfs_storage_read(cacheKey);
    
    if (!healthData) {
        // 缓存未命中，检查服务器健康状态
        healthData = {};
        for (const [serverName, weight] of pool) {
            try {
                const startTime = Date.now();
                const response = await fetch(`http://${serverName}/health`, { 
                    timeout: 3000 
                });
                healthData[serverName] = {
                    healthy: response.ok,
                    latency: Date.now() - startTime
                };
            } catch (error) {
                healthData[serverName] = {
                    healthy: false,
                    latency: 9999
                };
            }
        }
        
        // 缓存结果
        await _dfs_storage_write(cacheKey, JSON.stringify(healthData), 10);
    } else {
        healthData = JSON.parse(healthData);
    }
    
    // 根据健康状态和延迟调整权重
    const optimizedPool = pool.map(([name, weight]) => {
        const health = healthData[name];
        if (!health || !health.healthy) {
            return [name, 0]; // 不健康的服务器权重设为0
        }
        
        // 根据延迟调整权重
        const latencyFactor = Math.max(0.1, 1 - (health.latency / 1000));
        return [name, Math.floor(weight * latencyFactor)];
    });
    
    return [false, optimizedPool];
}
```

## 最佳实践

### 1. 错误处理

```javascript
exports = async function(pool, indirect, options, extras) {
    try {
        // 主要逻辑
        return [false, modifiedPool];
    } catch (error) {
        console.error(`插件执行错误: ${error.message}`);
        // 出错时返回原始pool，确保服务可用性
        return [false, pool];
    }
}
```

### 2. 性能优化

```javascript
// 使用缓存减少重复计算
const CACHE_TTL = 60; // 缓存60秒

exports = async function(pool, indirect, options, extras) {
    const cacheKey = `plugin_result_${hashInputs(pool, extras)}`;
    
    // 尝试获取缓存结果
    const cached = await _dfs_storage_read(cacheKey);
    if (cached) {
        return JSON.parse(cached);
    }
    
    // 执行实际逻辑
    const result = await computeResult(pool, options, extras);
    
    // 缓存结果
    await _dfs_storage_write(cacheKey, JSON.stringify(result), CACHE_TTL);
    
    return result;
}
```

### 3. 配置验证

```javascript
exports = async function(pool, indirect, options, extras) {
    // 验证必需的配置项
    if (!options.api_key) {
        console.error("缺少必需的api_key配置");
        return [false, pool];
    }
    
    if (!options.endpoint_url) {
        console.error("缺少必需的endpoint_url配置");
        return [false, pool];
    }
    
    // 继续执行插件逻辑...
}
```

### 4. 安全考虑

```javascript
// 避免在日志中输出敏感信息
exports = async function(context, challengeData, options, extras) {
    // ❌ 错误：可能泄露敏感信息
    // console.log("配置:", options);
    
    // ✅ 正确：仅记录必要信息
    console.log(`插件执行: context=${context}, timestamp=${Date.now()}`);
    
    // 验证输入参数
    if (typeof challengeData !== 'object' || !challengeData) {
        return { success: false, error: "无效的挑战数据" };
    }
    
    // 限制API调用频率
    const rateLimitKey = `rate_limit_${extras.client_ip}`;
    const callCount = await _dfs_storage_read(rateLimitKey) || 0;
    if (callCount > 10) {
        return { success: false, error: "请求过于频繁" };
    }
    await _dfs_storage_write(rateLimitKey, callCount + 1, 60);
    
    // 继续执行...
}
```

## 调试和测试

### 1. 本地测试

创建测试插件文件 `test_my_plugin.js`：

```javascript
// test_my_plugin.js
exports = async function(pool, indirect, options, extras) {
    console.log("=== 插件调试信息 ===");
    console.log("输入pool:", JSON.stringify(pool));
    console.log("indirect:", indirect);
    console.log("options:", JSON.stringify(options));
    console.log("extras:", JSON.stringify(extras));
    
    // 测试存储功能
    await _dfs_storage_write("test_key", "test_value", 10);
    const stored = await _dfs_storage_read("test_key");
    console.log("存储测试 - 写入: test_value, 读取:", stored);
    
    // 返回修改后的pool
    const testPool = pool.map(([name, weight]) => [name, weight + 1]);
    console.log("输出pool:", JSON.stringify(testPool));
    
    return [false, testPool];
}
```

### 2. 查看日志

启动DFS2时设置详细日志级别：

```bash
RUST_LOG=debug cargo run
```

### 3. 单元测试

DFS2提供了插件测试框架：

```bash
# 运行所有测试，包括插件测试
cargo test

# 运行特定的插件测试
cargo test test_javascript_plugin
```

### 4. 在线调试

在配置文件中启用debug模式：

```yaml
debug_mode: true  # 开发环境中启用
```

Debug模式下，系统会输出更多插件执行信息。

## 部署指南

### 1. 生产环境部署

```bash
# 1. 将插件文件复制到生产服务器
scp plugins/*.js production-server:/opt/dfs2/plugins/

# 2. 更新配置文件
scp config.yaml production-server:/opt/dfs2/config.yaml

# 3. 重启DFS2服务
ssh production-server "systemctl restart dfs2"

# 4. 验证插件加载
ssh production-server "journalctl -u dfs2 -n 20 | grep 'Loaded plugin'"
```

### 2. 热重载配置

```bash
# 重新加载配置和插件 (无需重启服务)
curl http://your-dfs2-server:3000/reload-config
```

### 3. 监控插件性能

使用Prometheus指标监控插件执行：

```bash
# 查看插件执行指标
curl http://your-dfs2-server:3000/metrics | grep dfs_plugin
```

### 4. 配置管理

生产环境建议：

1. **版本控制**: 使用git管理插件代码
2. **敏感信息**: 使用`private_`前缀的文件存放API密钥
3. **测试验证**: 在staging环境充分测试后再部署到生产
4. **监控告警**: 设置插件错误率和性能监控

## 常见问题

### Q: 插件修改后需要重启服务器吗？

A: 是的，目前插件在服务器启动时加载。可以使用 `/reload-config` 端点热重载配置，但插件代码修改需要重启。

### Q: 插件可以访问文件系统吗？

A: 不可以。出于安全考虑，插件运行在沙箱环境中，只能使用提供的API函数。

### Q: 如何处理插件执行超时？

A: DFS2会自动处理插件超时，超时的插件会被跳过。建议在插件中设置合理的超时时间，避免阻塞请求。

### Q: 插件可以访问数据库吗？

A: 插件可以通过HTTP API访问外部服务，包括数据库。也可以使用内置的存储API进行简单的键值存储。

### Q: 如何在插件间共享数据？

A: 使用 `_dfs_storage_read` 和 `_dfs_storage_write` 函数，不同插件可以通过约定的键名共享数据。

---

更多问题请参考 [DFS2项目文档](../README.md) 或提交issue到项目仓库。