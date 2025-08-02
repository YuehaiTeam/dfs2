# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DFS2 is a Rust-based distributed file system server with JavaScript plugin support. It acts as a middleware for file distribution across multiple storage backends (S3, direct URLs, DFS nodes) with configurable routing flows and CDN optimization.

**Current Status**: Production Ready (v0.3.0)
- **Core Features**: Session management, challenge verification, flow control, multiple storage backends
- **Monitoring**: Prometheus metrics (`/metrics`), structured logging, health checks  
- **Documentation**: OpenAPI docs at `/docs`, configuration validation with `--validate-only`
- **Plugin System**: JavaScript runtime with Redis storage integration

## Development Approach

The project follows production-first development with comprehensive error handling, structured logging, and safety guarantees. All core functionality is implemented and tested.

## Common Development Commands

```bash
# Build the project
cargo build

# Run the application
cargo run

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy for linting
cargo clippy

# Build for release
cargo build --release
```

## Environment Variables

### Core Configuration
- `CONFIG_PATH`: Path to config.yaml file (default: "config.yaml")
- `PLUGIN_PATH`: Path to plugins directory (default: "plugins/")
- `STATIC_DIR`: Directory for static file serving (default: "static/")
- `BIND_ADDRESS`: Server bind address (default: "0.0.0.0:3000")

### Data Store Configuration
- `DATA_STORE_TYPE`: Storage backend type - "file" or "redis" (default: "file")
  - `file`: Uses local file-based storage, no external dependencies
  - `redis`: Uses Redis for production scalability and clustering
- `REDIS_URL`: Redis connection string (default: "redis://127.0.0.1/")
  - Only used when `DATA_STORE_TYPE=redis`
  - Format: `redis://[username:password@]host:port[/database_number]`
- `REDIS_PREFIX`: Optional prefix for all Redis keys (default: none)
  - Format: `{prefix}:{namespace}:{key}` when set, `{namespace}:{key}` when empty
  - Useful for multi-instance deployments or namespace isolation
  - Example: Setting `REDIS_PREFIX=dfs2_prod` will transform `session:abc123` to `dfs2_prod:session:abc123`

### Challenge System Configuration
- `CHALLENGE_DEFAULT_TYPE`: Default challenge type - "md5", "sha256", "web", or "random" (default: "random")
  - `md5`: Fast MD5-based proof-of-work challenge (fixed 2-byte difficulty)
  - `sha256`: SHA256-based challenge with configurable difficulty (1-4 bytes)
  - `web`: Plugin-driven web challenges (reCAPTCHA, Turnstile, math, etc.)
  - `random`: Randomly select challenge type for each request
- `CHALLENGE_SHA256_DIFFICULTY`: SHA256 challenge difficulty in bytes (default: "2")
  - Range: 1-4 bytes (higher = more difficult)
  - Affects computation time: 1 byte ≈ milliseconds, 4 bytes ≈ minutes
- `CHALLENGE_WEB_PLUGIN`: Default web challenge plugin (default: "web_challenge_recaptcha")
  - Available plugins: `web_challenge_recaptcha`, `web_challenge_turnstile`, `web_challenge_math`, `web_challenge_geetest`
### Security and API Configuration
- `ENABLE_OPENAPI_DOCS`: Enable OpenAPI documentation endpoints (default: "false")
  - Set to "true" to enable `/docs` Swagger UI and `/api-docs/openapi.json`
  - Disable in production to prevent API discovery and reduce attack surface
  - Example: `ENABLE_OPENAPI_DOCS=true` for development, `ENABLE_OPENAPI_DOCS=false` for production

### Geolocation and IP Processing
- `GEOLITE2_PATH`: Path to MaxMind GeoLite2-City.mmdb database file (default: "GeoLite2-City.mmdb")
  - Used for IP geolocation in flow rule engine
  - Download from MaxMind: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  - If file not found, geolocation features gracefully degrade (all IPs treated as global)

### Logging and Monitoring
- `RUST_LOG`: Log level configuration (default: "info")
  - Supports: `error`, `warn`, `info`, `debug`, `trace`
  - Module-specific: `RUST_LOG=dfs2=debug,tower_http=info`
  - Production recommendation: `info` or `warn`

### Time Zone Configuration
- `TZ`: System timezone configuration for daily bandwidth limits and time-based conditions
  - Examples: `TZ=Asia/Shanghai`, `TZ=America/New_York`, `TZ=UTC`
  - All daily bandwidth limits (`bw_daily`, `server_bw_daily`) reset at midnight in the specified timezone
  - Time conditions (`time >= 09:00:00`) also use this timezone for consistency
  - Default: Uses system local timezone if not specified

### Session Analytics and Logging
- `SESSION_LOG_ENABLED`: Enable session analytics logging (default: "true")
  - Set to "false" to disable structured session logging
  - When enabled, generates JSON logs for offline analysis
- `SESSION_LOG_PATH`: Directory for session log files (default: "logs/sessions")
  - Logs are automatically rotated daily (sessions.YYYY-MM-DD.log format)
  - Each line contains a complete JSON record for one session
- `SESSION_CLEANUP_ENABLED`: Enable automatic session cleanup task (default: "true")
  - Background task that processes expired sessions
  - Records timeout events and cleans up abandoned sessions
- `SESSION_CLEANUP_INTERVAL_MIN`: Cleanup task interval in minutes (default: "5")
  - How often to scan for expired sessions
- `SESSION_TIMEOUT_HOURS`: Session timeout duration in hours (default: "2")
  - Sessions older than this are considered expired

### Example Production Configuration
```bash
# Production deployment with Redis and security hardening
export DATA_STORE_TYPE=redis
export REDIS_URL=redis://prod-redis.internal:6379/0
export REDIS_PREFIX=dfs2_prod
export ENABLE_OPENAPI_DOCS=false
export CHALLENGE_DEFAULT_TYPE=sha256
export CHALLENGE_SHA256_DIFFICULTY=3
export CHALLENGE_WEB_PLUGIN=web_challenge_turnstile
export RUST_LOG=info
export BIND_ADDRESS=0.0.0.0:3000
export CONFIG_PATH=/etc/dfs2/config.yaml
export GEOLITE2_PATH=/var/lib/dfs2/GeoLite2-City.mmdb
export TZ=Asia/Shanghai

# Session analytics configuration
export SESSION_LOG_ENABLED=true
export SESSION_LOG_PATH=/var/log/dfs2/sessions
export SESSION_CLEANUP_ENABLED=true
export SESSION_CLEANUP_INTERVAL_MIN=5
export SESSION_TIMEOUT_HOURS=2
```

### Example Development Configuration
```bash
# Development setup with file storage and API docs
export DATA_STORE_TYPE=file
export ENABLE_OPENAPI_DOCS=true
export CHALLENGE_DEFAULT_TYPE=md5
export CHALLENGE_SHA256_DIFFICULTY=1
export RUST_LOG=debug
export BIND_ADDRESS=127.0.0.1:3000

# Session analytics for development
export SESSION_LOG_ENABLED=true
export SESSION_LOG_PATH=./logs/sessions
export SESSION_CLEANUP_ENABLED=true
export SESSION_CLEANUP_INTERVAL_MIN=1
export SESSION_TIMEOUT_HOURS=1
```

## Supported Storage Backends

DFS2 supports three types of storage backends, each with specific URL format and capabilities:

### 1. S3 Compatible Storage (`type: s3`)

Full S3-compatible storage with presigned URL generation and AWS4 signature authentication.

**URL Format:**
```
https://access_key:secret_key@endpoint:port?region=us-east-1&bucket=my-bucket&path_mode=true&expires=600
```

**Parameters:**
- `access_key`: S3 access key ID
- `secret_key`: S3 secret access key  
- `region`: AWS region (required)
- `bucket`: S3 bucket name
- `path_mode`: Use path-style URLs instead of virtual-hosted style (default: false)
- `expires`: Presigned URL expiration in seconds (default: 600)

**Features:**
- AWS Signature Version 4 authentication
- Presigned URL generation with custom headers
- Support for byte range requests
- Automatic health checks via partial content requests

### 2. Direct HTTP/HTTPS (`type: direct`)

Simple direct URL access without authentication, suitable for public endpoints or CDNs.

**URL Format:**
```
https://cdn.example.com/path/prefix
```

**Features:**
- No authentication required
- Simple URL concatenation (base_url + file_path)
- Health checks via HTTP HEAD/GET requests
- Suitable for GitHub releases, public CDNs, etc.

### 3. DFS Node (`type: dfs_node`)

Custom DFS node with HMAC-SHA256 signature authentication for secure access.

**URL Format:**
```
https://username:signature_token@dfs.example.com:port/path?expire_seconds=3600
```

**Parameters:**
- `signature_token`: HMAC signing key for authentication
- `expire_seconds`: Default expiration time (default: 3600)

**Features:**
- HMAC-SHA256 signature authentication
- UUID-based session tracking
- Support for byte range requests in signatures
- Custom signature format: `{uuid}{expire_time}{hmac}{ranges...}`
- Automatic signature generation with expiration

## Architecture Overview

### Core Components

1. **Main Server** (`src/main.rs`): Axum-based HTTP server on port 3000
2. **Configuration System** (`src/config.rs`): YAML-based config with servers, resources, and plugins
3. **Flow Runner** (`src/modules/flow/runner.rs`): Executes routing flows with weighted pooling
4. **JavaScript Runtime** (`src/modules/qjs.rs`): QuickJS-based plugin execution environment
5. **Storage Backends** (`src/modules/server/`): S3, direct, and DFS node implementations

### Key Modules

- **Routes** (`src/routes/`): API endpoints for resource metadata and status
- **Models** (`src/models.rs`): Data structures for sessions and requests
- **App State** (`src/app_state.rs`): Redis-backed session management
- **Responses** (`src/responses.rs`): Standardized API response formats

### Flow System

The flow system processes requests through configurable steps with comprehensive rule-based routing:

#### Core Flow Processing
- **Server selection**: Choose from configured backends based on rules and health status
- **Poolization**: Weighted random selection of endpoints with health checks
- **Plugin execution**: JavaScript plugins can modify URL pools
- **Rule-based routing**: Advanced conditional execution based on multiple criteria

#### Flow Rule Engine (`src/modules/flow/runner.rs`, `src/modules/geolocation.rs`)

The flow rule engine supports sophisticated request routing based on various conditions:

**Supported Rule Types:**
- **`cnip <bool>`**: Geographic IP filtering (China vs Global IPs)
  - Uses MaxMind GeoLite2 database for IP geolocation
  - Example: `cnip true` matches Chinese IPs, `cnip false` matches non-Chinese IPs
- **`ipversion <4|6>`**: IP protocol version filtering
  - Example: `ipversion 4` matches IPv4 addresses, `ipversion 6` matches IPv6 addresses
- **`cidr <cidr_range>`**: Network range matching
  - Example: `cidr 192.168.1.0/24` matches local network IPs
- **`size <op> <size>`**: File size comparisons
  - Operators: `==`, `!=`, `>`, `>=`, `<`, `<=`
  - Example: `size > 10MB` for large files
- **`bw_daily <op> <limit>`**: Daily bandwidth usage limits (session-level)
  - Tracks usage per session via Redis with automatic 24-hour expiration
  - Example: `bw_daily < 1GB` for user bandwidth throttling
  - Updated in real-time for both direct downloads and session-based downloads
- **`server_bw_daily <server_id> <op> <limit>`**: Daily bandwidth usage limits (server-level)
  - Tracks usage per specified server via Redis with automatic 24-hour expiration  
  - Example: `server_bw_daily cdn_server1 < 100GB` for server load balancing
  - Useful for CDN cost control and traffic distribution
  - Must specify server_id to avoid ambiguity
- **`time <op> <time>`**: Time-based conditions
  - Example: `time >= 09:00:00` for business hours
- **`extras <key>`**: Custom condition flags
  - Checks for boolean values in extras JSON object

**Rule Evaluation Modes:**
- **AND mode**: All rules must match (`mode: and`)
- **OR mode**: Any rule can match (`mode: or`, default)

**Configuration Example:**
```yaml
resources:
  example:
    # Content caching configuration
    cache_enabled: true
    cache_subpaths: ["*.json", "images/*"]  # Only for prefix resources
    cache_max_age: 300  # 5 minutes default
    
    flow:
      - rules:
          - cnip false                    # Global users only
          - ipversion 4                   # IPv4 connections only
          - size > 100MB                  # Large files
          - time >= 09:00:00              # Business hours
          - bw_daily < 5GB                # User daily limit
          - server_bw_daily cdn_global < 100GB  # Server daily limit
        mode: and                        # All conditions must match
        use:
          - server cdn_global 10
      - rules:
          - cnip true                     # Chinese users
          - server_bw_daily cdn_china < 50GB  # Lower limit for China servers
        use:
          - server cdn_china 5
      - rules:
          - ipversion 4                   # IPv4 fallback
        use:
          - server cdn_fallback 3
```

**Advanced Features:**
- **Client IP Detection**: Automatically extracts real client IP from proxy headers
- **Health Check Integration**: Rules consider server health status from Redis cache
- **File Size Detection**: Automatically obtains file sizes from health checks for Size conditions
- **Bandwidth Tracking**: Real-time bandwidth usage tracking for both session and server levels
- **Content Caching**: Files <100KB cached in Redis with xxhash ETags and proper Cache-Control headers
- **Async Processing**: All rule evaluation is non-blocking
- **Fallback Strategy**: Graceful degradation when GeoLite2 database unavailable

## Plugin System

DFS2 使用 QuickJS 运行时执行 JavaScript 插件，支持两种插件类型：

### 1. 流控制插件 (Flow Control Plugins)
- **位置**: `plugins/` 目录
- **用途**: 在资源请求流程中进行服务器选择和负载均衡
- **API**: 
  ```javascript
  exports = async function(pool, indirect, options, extras) {
      // 返回 [should_break: boolean, new_pool: Array<[string, number]>]
      return [false, pool];
  }
  ```

### 2. 挑战验证插件 (Challenge Plugins) 
- **位置**: `plugins/` 目录
- **用途**: 处理 Web 人机验证挑战的生成和验证
- **API**:
  ```javascript
  exports = async function(context, challengeData, options, extras) {
      if (context === "generate") {
          // 生成阶段：返回验证 URL 和相关数据
          return {
              url: "https://verification-server.com/verify?token=...",
              token: "verification_token",
              expires_in: 300
          };
      } else if (context === "verify") {
          // 验证阶段：验证用户提交的响应
          return {
              success: true,  // 或 false
              error: "error message"  // 可选
          };
      }
  }
  ```

### 插件环境
- **JavaScript 运行时**: QuickJS with async/await support
- **可用 API**: fetch, console.log, 标准 JavaScript API
- **内置函数**: 
  - `_dfs_s3sign(url, path, headers)`: S3 签名
  - `_dfs_dfsnodesign(url, path, uuid, ranges)`: DFS 节点签名
  - `_dfs_storage_read(key)`: Redis 存储读取
  - `_dfs_storage_write(key, value, expires)`: Redis 存储写入

### 插件配置
插件通过 `config.yaml` 中的 `plugins` 部分进行配置：
```yaml
plugins:
  web_challenge_recaptcha:
    recaptcha_site_key: "your_site_key"
    recaptcha_secret_key: "your_secret_key"
    verification_base_url: "https://your-verification-server.com"
```

**Plugin Types:**
- **Public plugins**: Regular plugin files that are tracked in git
- **Private plugins**: Files with `private_` prefix are excluded from git and contain sensitive configurations

### Configuration Structure

The `config.yaml` file defines:
- **servers**: Backend storage endpoints (S3, direct, DFS node)
- **resources**: Available files with version management
- **plugins**: Plugin configurations and parameters

Each resource has:
- Version mappings to different server paths
- Fallback server priority lists
- Custom flow definitions for request processing

### Static File Service

DFS2 includes a built-in static file server for hosting challenge verification pages:

- **Routes**: `/static/*` for general static files, `/challenge/{type}` for challenge pages
- **Template System**: Automatic placeholder replacement in HTML templates
- **Directory**: Static files served from `static/` directory (configurable via `STATIC_DIR` env var)
- **Challenge Templates**: Pre-built HTML templates for reCAPTCHA, Turnstile, and math challenges
- **Client Communication**: Pages use `window._dfsc_submit_challenge()` callback with postMessage fallback

### Session Management

Redis-backed sessions provide intelligent server selection and tracking:

#### Session Creation (`src/routes/resource.rs:30-95`)
- **Smart Server Selection**: Automatically generates `tries` list from resource configuration
  - Primary: Uses resource's `tries` array if configured
  - Fallback: Uses resource's `server` array as candidates
  - Validation: Ensures all servers exist in global server configuration
- **Health-Based Prioritization**: 
  - Healthy servers listed first for optimal performance
  - Unhealthy servers included as fallback options
  - Real-time health checks with Redis caching (5-minute TTL)
- **Automatic Path Resolution**: Determines appropriate file paths for health checks

#### Session Tracking
- File chunk information and download progress
- CDN URL mappings per chunk with performance analytics
- Session lifecycle management with automatic expiration
- Download count tracking with Redis backend

## Development Patterns

- Use `Arc<RwLock<>>` for shared mutable state across async contexts
- Implement `IntoJs` trait for Rust types exposed to JavaScript
- Handle errors with comprehensive `DfsError` enum and proper HTTP mapping
- Use Axum extractors for request handling and dependency injection
- Plugin code is loaded dynamically from the filesystem at startup
- All backend implementations provide health check capabilities via `is_alive()` method

### Code Quality Standards
```bash
# Before committing any changes:
cargo fmt --check        # Ensure consistent formatting
cargo clippy -- -D warnings  # Fix all clippy warnings
cargo test              # All tests must pass
cargo doc --no-deps     # Documentation must build
```

### Error Handling Philosophy
- Never use `unwrap()` in production code - use explicit error handling
- Use unified `DfsError` type for application logic with HTTP status mapping
- Use `thiserror` for custom error types with clear user messages
- Log errors before returning them for production debugging

### Testing Requirements
- **Unit tests required for all new functions** - Maintain high test coverage
- **Integration tests for API endpoints** - Ensure correct request/response handling
- **Performance tests for critical paths** - Prevent regressions in hot code

## Important Implementation Notes

### Key Features
- **Session Management**: Intelligent server selection with health-based prioritization
- **Challenge System**: MD5/SHA256/Web challenges with debug mode support
- **Static File Service**: Self-hosted challenge pages with JavaScript parameter extraction
- **Flow Control**: Advanced rule engine with geolocation, bandwidth limiting, and time-based conditions
- **Configuration Hot Reload**: Manual reload via `GET /reload-config` endpoint

## Challenge System Implementation

The project implements a multi-type challenge verification system for client authentication:

### Challenge Types
- **MD5 Challenge**: Fixed 2-byte difficulty, returns `hash/partial_data` format
- **SHA256 Challenge**: Dynamic difficulty (1-3 bytes), supports configurable complexity
- **Web Challenge** (planned): Plugin-based integration with third-party services like reCAPTCHA

### Debug Mode Support
- Automatically enabled in debug builds via `debug_mode` config parameter
- Debug mode allows challenge verification bypass with detailed logging
- Console output includes challenge type, submitted value, expected value, and hash information

### Plugin Integration for Web Challenges
- Web challenges will use existing plugin system with extended return types
- Static HTML pages are deployed independently on dedicated servers
- Plugins handle both generation (create verification URLs with parameters) and verification phases
- Direct integration with third-party APIs (e.g., reCAPTCHA) without standardized protocols