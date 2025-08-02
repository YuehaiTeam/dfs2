# DFS2 - 分布式文件系统服务器

DFS2 是一个基于 Rust 的分布式文件系统中间件，支持多存储后端和 JavaScript 插件系统。提供智能路由、会话管理、挑战验证等功能。

## 快速开始

### 安装依赖

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆项目
git clone <repository-url>
cd dfs2

# 构建项目
cargo build --release
```

### 基本配置

创建 `config.yaml` 配置文件：

```yaml
# 调试模式（生产环境设为 false）
debug_mode: false

# 服务器后端配置
servers:
  example_s3:
    id: example_s3
    type: s3
    url: 'https://access_key:secret_key@endpoint:port?region=us-east-1&bucket=mybucket&expires=600'
  
  example_direct:
    id: example_direct
    type: direct
    url: 'https://cdn.example.com/files'

# 资源配置
resources:
  myapp:
    latest: '1.0.0'
    versions:
      '1.0.0':
        default: '/myapp/installer-1.0.0.exe'
    tries: ['example_s3', 'example_direct']
    server: ['example_s3', 'example_direct']

# 挑战验证配置
challenge:
  challenge_type: 'md5'  # 可选: md5, sha256, web

# 插件配置（可选）
plugins: {}
```

### 启动服务

```bash
# 开发模式（使用文件存储）
cargo run

# 生产模式（使用 Redis）
DATA_STORE_TYPE=redis REDIS_URL=redis://127.0.0.1:6379 cargo run

# 配置验证
cargo run -- --validate-only
```

## 环境变量配置

### 核心配置
- `CONFIG_PATH`: 配置文件路径（默认: config.yaml）
- `BIND_ADDRESS`: 服务绑定地址（默认: 0.0.0.0:3000）
- `PLUGIN_PATH`: 插件目录路径（默认: plugins/）
- `STATIC_DIR`: 静态文件目录（默认: static/）

### 存储后端
- `DATA_STORE_TYPE`: 存储类型 file/redis（默认: file）
- `REDIS_URL`: Redis 连接地址（默认: redis://127.0.0.1/）
- `REDIS_PREFIX`: Redis 键前缀（可选）

### 挑战系统
- `CHALLENGE_DEFAULT_TYPE`: 挑战类型 md5/sha256/web/random（默认: random）
- `CHALLENGE_SHA256_DIFFICULTY`: SHA256 难度 1-4字节（默认: 2）
- `CHALLENGE_WEB_PLUGIN`: Web 挑战插件（默认: web_challenge_recaptcha）

### 监控和日志
- `RUST_LOG`: 日志级别（默认: info）
- `ENABLE_OPENAPI_DOCS`: 启用 API 文档（默认: false）

### 地理位置和时区
- `GEOLITE2_PATH`: GeoLite2 数据库路径（默认: GeoLite2-City.mmdb）
- `TZ`: 时区配置（默认: 系统时区）

## 存储后端类型

DFS2 支持四种存储后端类型：

### S3 兼容存储
AWS S3 或兼容的对象存储服务，支持预签名URL和认证。

```yaml
servers:
  s3_example:
    id: s3_example
    type: s3
    url: 'https://access_key:secret_key@endpoint:port?region=us-east-1&bucket=mybucket&path_mode=true&expires=600'
```

**参数说明：**
- `access_key`: S3访问密钥
- `secret_key`: S3秘密密钥
- `region`: AWS区域
- `bucket`: 存储桶名称
- `path_mode`: 使用路径风格URL（默认false）
- `expires`: 预签名URL过期时间（秒）

### 直连 HTTP/HTTPS
直接访问公开的HTTP/HTTPS端点，适用于CDN或公开文件服务器。

```yaml
servers:
  cdn_example:
    id: cdn_example
    type: direct
    url: 'https://cdn.example.com/path/prefix'
```

### DFS 节点
支持HMAC签名认证的DFS节点，提供安全的分布式访问。

```yaml
servers:
  dfs_example:
    id: dfs_example
    type: dfs_node
    url: 'https://username:signature_token@dfs.example.com:port/path?expire_seconds=3600'
```

**参数说明：**
- `signature_token`: HMAC签名密钥
- `expire_seconds`: 默认过期时间（秒）

### Git LFS 存储
通过Git LFS协议访问Git仓库中的大文件，支持缓存优化。

```yaml
servers:
  git_lfs_example:
    id: git_lfs_example
    type: git_lfs
    url: 'https://gitlab.example.com/user/repo.git?raw=https://gitlab.example.com/user/repo/-/git/raw/main/&file_cache=300&url_cache=300'
```

**参数说明：**
- 基础URL：Git仓库地址
- `raw`: 原始文件访问URL模板
- `file_cache`: 文件缓存时间（秒）
- `url_cache`: URL缓存时间（秒）

**使用场景：**
- 存储在GitLab/GitHub LFS中的大文件
- 版本控制的资源文件分发
- 开源项目的文件托管

## 流程控制和路由

DFS2 支持基于规则的智能路由：

```yaml
resources:
  example:
    flow:
      - rules:
          - cnip false           # 非中国IP
          - ipversion 4          # IPv4
          - size > 100MB         # 大文件
          - bw_daily < 5GB       # 用户日带宽限制
        mode: and               # 所有条件必须满足
        use:
          - server cdn_global 10
      
      - rules:
          - cnip true            # 中国IP
        use:
          - server cdn_china 5
```

### 支持的规则类型
- `cnip <bool>`: 中国IP过滤
- `ipversion <4|6>`: IP协议版本
- `cidr <range>`: 网络范围匹配
- `size <op> <size>`: 文件大小比较
- `bw_daily <op> <limit>`: 用户日带宽限制
- `server_bw_daily <server> <op> <limit>`: 服务器日带宽限制
- `time <op> <time>`: 时间条件
- `extras <key>`: 自定义条件

## API 接口

### 资源管理

#### 获取资源元数据
```http
GET /resource/{resource_id}?version={version}
```

#### 创建会话
```http
POST /resource/{resource_id}/session
Content-Type: application/json

{
    "version": "1.0.0",
    "verify": "challenge_response"
}
```

#### 获取 CDN URL
```http
POST /resource/{resource_id}/cdn
Content-Type: application/json

{
    "session_id": "session_uuid",
    "range": "bytes=0-1023"
}
```

#### 删除会话
```http
DELETE /resource/{resource_id}/session/{session_id}
```

### 前缀资源（目录）

#### 创建前缀会话
```http
POST /resource/{resource_id}/prefix/session
```

#### 获取前缀 CDN URL
```http
POST /resource/{resource_id}/prefix/cdn
Content-Type: application/json

{
    "session_id": "session_uuid",
    "path": "subfolder/file.txt",
    "range": "bytes=0-1023"
}
```

### 系统接口

#### 健康检查
```http
GET /ping
GET /health
```

#### 配置重载
```http
GET /reload-config
```

#### Prometheus 指标
```http
GET /metrics
```

#### API 文档（开发环境）
```http
GET /docs                    # Swagger UI
GET /api-docs/openapi.json   # OpenAPI 规范
```

## 插件系统

DFS2 支持 JavaScript 插件扩展功能。详细信息请参考 [`plugins/README.md`](plugins/README.md)。

### 基本用法

创建插件文件 `plugins/my_plugin.js`：

```javascript
exports = async function(pool, indirect, options, extras) {
    // 处理服务器池
    return [false, pool];
}
```

在配置文件中配置插件：

```yaml
plugins:
  my_plugin:
    option1: "value1"
    option2: "value2"
```

## 部署

### 开发环境
```bash
# 使用文件存储
DATA_STORE_TYPE=file ENABLE_OPENAPI_DOCS=true cargo run

# 访问 API 文档
open http://localhost:3000/docs
```

### 生产环境
```bash
# 使用 Redis 存储
export DATA_STORE_TYPE=redis
export REDIS_URL=redis://prod-redis:6379/0
export REDIS_PREFIX=dfs2_prod
export ENABLE_OPENAPI_DOCS=false
export RUST_LOG=info
export TZ=Asia/Shanghai

# 验证配置
cargo run --release -- --validate-only

# 启动服务
cargo run --release
```

### 配置验证

```bash
# 验证配置文件、服务器连通性和插件语法
cargo run -- --validate-only

# 输出示例
Config validation passed
Server connectivity test passed (5/5 servers healthy)
Plugin syntax validation passed (3 plugins loaded)
All validations completed successfully
```

## 监控

### Prometheus 指标

访问 `/metrics` 端点获取监控指标：

- `dfs_requests_total`: 请求总数
- `dfs_request_duration_seconds`: 请求持续时间
- `dfs_active_sessions`: 活跃会话数
- `dfs_redis_operations_total`: Redis 操作总数
- `dfs_bandwidth_usage_bytes`: 带宽使用量

### 日志

```bash
# 设置日志级别
export RUST_LOG=info

# 模块特定日志
export RUST_LOG=dfs2=debug,tower_http=info
```

## 开发

### 构建和测试
```bash
cargo build                    # 构建项目
cargo test                     # 运行测试
cargo clippy                   # 代码检查
cargo fmt                      # 代码格式化
```

### 项目结构
```
src/
├── main.rs                    # 主入口
├── config.rs                  # 配置管理
├── routes/                    # API 路由
├── modules/                   # 核心模块
│   ├── flow/                  # 流程控制
│   ├── server/                # 存储后端
│   └── qjs.rs                 # JavaScript 运行时
├── models.rs                  # 数据模型
└── responses.rs               # API 响应
```

## 许可证

MIT License