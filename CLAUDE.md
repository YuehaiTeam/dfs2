# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DFS2 is a production-ready Rust-based distributed file system server with JavaScript plugin support. It acts as middleware for file distribution across multiple storage backends (S3, direct URLs, DFS nodes) with advanced configurable routing flows, challenge verification, and CDN optimization.

**Current Status**: Production Ready (v0.3.0)
- **Core Features**: Session management, multi-type challenge verification, advanced flow control, multiple storage backends
- **Architecture**: Service-oriented with clean separation of concerns
- **Monitoring**: Prometheus metrics (`/metrics`), structured logging, health checks  
- **Documentation**: OpenAPI docs at `/docs`, configuration validation with `--validate-only`
- **Plugin System**: JavaScript runtime with Redis storage integration and version providers

## Development Commands

```bash
# Development
cargo build                  # Build project
cargo run                   # Run development server
cargo test                  # Run test suite
cargo fmt --check           # Check formatting
cargo clippy -- -D warnings # Lint with warnings as errors

# Production
cargo build --release       # Release build
cargo doc --no-deps         # Generate documentation
```

## Architecture Overview

The project follows a clean, service-oriented architecture with clear separation of concerns:

### Core Architecture (src/)

```
src/
├── main.rs                 # Application entry point
├── lib.rs                  # Public module exports
├── config.rs               # Configuration management with ArcSwap
├── container.rs            # Dependency injection container (AppContext)
├── error.rs                # Unified error handling (DfsError)
├── metrics.rs              # Prometheus metrics collection
├── models.rs               # Core data structures
├── responses.rs            # Standardized API responses
├── validation.rs           # Input validation utilities
├── services/               # Business logic layer
├── routes/                 # HTTP API layer
└── modules/                # Feature modules
```

### Services Layer (src/services/)

**Service-Oriented Business Logic**
- `SessionService`: Session lifecycle management and statistics
- `ResourceService`: Resource validation, version management, and path resolution
- `FlowService`: Server selection and flow execution engine
- `ChallengeService`: Multi-type challenge generation and verification

### Routes Layer (src/routes/)

**Clean API Structure**
- `resource/`: Resource-related endpoints split by functionality
  - `metadata.rs`: Resource metadata and KachinaInstaller parsing
  - `sessions.rs`: Session creation and management
  - `downloads.rs`: File download and redirect handling
  - `chunk.rs`: CDN chunk management
- `mgmt.rs`: Management and health check endpoints
- `static_files.rs`: Static file serving with challenge templates

### Modules Layer (src/modules/)

**Feature-Based Organization**
- `analytics/`: Session logging and analytics
- `auth/`: Challenge verification and legacy client support
- `external/`: Third-party integrations (geolocation, KachinaInstaller)
- `flow/`: Flow execution configuration and rules
- `network/`: Network utilities and IP handling
- `qjs.rs`: JavaScript runtime for plugins
- `server/`: Storage backend implementations (S3, DFS, direct)
- `storage/`: Data persistence and caching layer
- `version_provider/`: Dynamic version management system

## Key Features

### 1. Advanced Flow Control System

**Rule-Based Server Selection** (`src/modules/flow/`, `src/services/flow_service.rs`)
- Geographic routing (China IP detection, geolocation keywords)
- Bandwidth limiting (resource-level and server-level daily limits)
- File size conditions, time-based routing, IP version filtering
- CIDR range matching and custom condition flags

**Supported Flow Rules:**
```yaml
flow:
  - rules:
      - cnip true                     # Chinese IPs only
      - geoip telecom                 # Telecom ISP users
      - size > 100MB                  # Large files
      - bw_daily $ < 5GB              # Current resource daily limit
      - server_bw_daily cdn1 < 100GB  # Server daily bandwidth limit
      - time >= 09:00:00              # Business hours only
    mode: and                         # All rules must match
    use:
      - server cdn_china 10
```

### 2. Multi-Type Challenge System

**Challenge Types** (`src/modules/auth/challenge.rs`, `src/services/challenge_service.rs`)
- **MD5 Challenge**: Fast proof-of-work (2-byte difficulty)
- **SHA256 Challenge**: Configurable difficulty (1-4 bytes)
- **Web Challenge**: Plugin-driven (reCAPTCHA, Turnstile, math, GeeTest)
- **Debug Mode**: Bypass for development with detailed logging

### 3. Version Provider System

**Dynamic Version Management** (`src/modules/version_provider/`)
- **Plugin-Based**: GitHub, GitLab, CNB, and custom providers
- **Caching**: TTL-based caching with manual refresh via webhooks
- **Fallback**: Static configuration fallback when plugins fail
- **Changelog Integration**: Automatic changelog retrieval and caching

### 4. Storage Backend Abstraction

**Multi-Backend Support** (`src/modules/server/`)
- **S3 Compatible**: AWS S3, MinIO with presigned URLs
- **Direct HTTP**: CDNs, GitHub releases, public endpoints
- **DFS Node**: Custom protocol with HMAC-SHA256 signatures

### 5. Session Management

**Intelligent Session Handling** (`src/services/session_service.rs`)
- **Smart Server Selection**: Health-based prioritization with fallbacks
- **Chunk Tracking**: Download progress and CDN performance metrics
- **Analytics**: Structured session logging with bandwidth tracking
- **Automatic Cleanup**: Background cleanup with timeout detection

## Configuration System

### Environment Variables

**Core Configuration**
- `CONFIG_PATH`: Configuration file path (default: "config.yaml")
- `PLUGIN_PATH`: Plugin directory (default: "plugins/")
- `STATIC_DIR`: Static files directory (default: "static/")
- `BIND_ADDRESS`: Server bind address (default: "0.0.0.0:3000")

**Data Store Configuration**
- `DATA_STORE_TYPE`: "file" (development) or "redis" (production)
- `REDIS_URL`: Redis connection string
- `REDIS_PREFIX`: Key prefix for multi-instance deployments

**Challenge System Configuration**
- `CHALLENGE_DEFAULT_TYPE`: "md5", "sha256", "web", or "random"
- `CHALLENGE_SHA256_DIFFICULTY`: Difficulty in bytes (1-4)
- `CHALLENGE_WEB_PLUGIN`: Default web challenge plugin

**Security Configuration**
- `ENABLE_OPENAPI_DOCS`: Enable API documentation (default: false)
- `IPDB_PATH`: IPIP database file for geolocation (default: "ipipfree.ipdb")

**Session Analytics**
- `SESSION_LOG_ENABLED`: Enable session logging (default: true)
- `SESSION_LOG_PATH`: Log directory (default: "logs/sessions")
- `SESSION_CLEANUP_ENABLED`: Enable cleanup task (default: true)
- `SESSION_CLEANUP_INTERVAL_MIN`: Cleanup interval (default: 5)
- `SESSION_TIMEOUT_HOURS`: Session timeout (default: 2)

### Resource Configuration Structure

```yaml
resources:
  myapp:
    latest: "1.5.0"
    resource_type: "file"  # or "prefix"
    
    # Version management
    versions:
      "1.5.0":
        server1: "path/to/v1.5.0/file"
        default: "default/path/${version}"
      default:
        default: "fallback/path/${version}"
    
    # Storage backends
    server: ["cdn_global", "cdn_china"]
    
    # Download policies
    download: "enabled"  # "enabled", "free", or "disabled"
    
    # Challenge configuration
    challenge_type: "sha256"
    challenge_difficulty: 2
    
    # Content caching
    cache_enabled: true
    cache_subpaths: ["*.json", "images/*"]  # For prefix resources
    cache_max_age: 300
    
    # Legacy client support
    legacy_client_support: false
    legacy_client_full_range: false
    
    # Dynamic version provider
    version_provider:
      type: plugin
      plugin_name: version_provider_github
      cache_ttl: 300
      webhook_token: "secure_token"
      options:
        repo: "owner/repository"
        include_prerelease: false
        asset_filter: "*.exe"
    
    # Static changelog (fallback)
    changelog: |
      ## Version 1.5.0
      ### New Features
      - Added new dashboard
      ### Bug Fixes
      - Fixed memory issues
    
    # Advanced flow control
    flow:
      - rules:
          - cnip false
          - size > 100MB
          - bw_daily $ < 5GB
        use:
          - server cdn_global 10
      - use:
          - server cdn_fallback 5
```

## Plugin System

### Plugin Types

**1. Flow Control Plugins**
- **Purpose**: Server selection and load balancing
- **Location**: `plugins/flow_*.js`
- **API**: `async function(pool, indirect, options, extras) -> [should_break, new_pool]`

**2. Challenge Plugins**
- **Purpose**: Web-based human verification
- **Location**: `plugins/web_challenge_*.js`
- **API**: Context-based (generate/verify)

**3. Version Provider Plugins**
- **Purpose**: Dynamic version and changelog retrieval
- **Location**: `plugins/version_provider_*.js`
- **API**: `async function(options, resourceId, extras) -> {version, changelog, metadata}`

### Plugin Environment

**JavaScript Runtime**: QuickJS with async/await support
**Built-in Functions**:
- `_dfs_s3sign(url, path, headers)`: S3 URL signing
- `_dfs_dfsnodesign(url, path, uuid, ranges)`: DFS node signing
- `_dfs_storage_read(key)`: Redis storage read
- `_dfs_storage_write(key, value, expires)`: Redis storage write

## Development Guidelines

### Code Quality Standards
```bash
# Pre-commit checklist
cargo fmt --check           # Formatting
cargo clippy -- -D warnings # Linting (warnings as errors)
cargo test                  # All tests pass
cargo doc --no-deps         # Documentation builds
```

### Architecture Principles
- **Service Layer**: All business logic in services, routes are thin adapters
- **Error Handling**: Use `DfsError` enum with proper HTTP status mapping
- **Async Operations**: Prefer async/await, use `Arc<RwLock<>>` for shared state
- **Configuration**: Use `ArcSwap` for lock-free configuration access
- **Testing**: Unit tests for services, integration tests for API endpoints

### Security Guidelines
- **No unwrap()**: Use explicit error handling in production code
- **Input Validation**: Validate all external inputs at service boundaries
- **Path Security**: Prevent directory traversal in file operations
- **Secret Management**: Never commit secrets, use environment variables

## Common Development Tasks

### Adding New Storage Backend
1. Implement `ServerBackend` trait in `src/modules/server/`
2. Add configuration parsing in `src/config.rs`
3. Register in server factory method
4. Add health check implementation

### Adding New Challenge Type
1. Extend `ChallengeType` enum in `src/modules/auth/challenge.rs`
2. Implement generation and verification logic in `ChallengeService`
3. Add configuration options and environment variables
4. Update documentation and examples

### Adding New Flow Rule
1. Extend `FlowCond` enum in `src/modules/flow/config.rs`
2. Add evaluation logic in `FlowService::evaluate_condition`
3. Add configuration parsing and validation
4. Write tests for new rule behavior

### Creating Version Provider Plugin
1. Create plugin file: `plugins/version_provider_name.js`
2. Implement required API: `async function(options, resourceId, extras)`
3. Return object with `version`, optional `changelog` and `metadata`
4. Add plugin configuration in `config.yaml`

## Important Implementation Details

### Session Flow
1. Client requests session via `POST /resource/{resid}`
2. Challenge generated and stored with TTL
3. Client solves challenge and resubmits
4. Session created with server tries list
5. Client requests CDN URLs via `GET /session/{sid}/{resid}`
6. Session deleted with statistics on completion

### Flow Execution
1. Parse flow rules and evaluate conditions
2. Build server pool based on matching rules
3. Apply penalties to recently failed servers
4. Perform weighted random selection
5. Health check selected server
6. Generate signed URL for client

### Version Management
1. Check version provider cache first
2. If cache miss, execute plugin to fetch latest
3. Fall back to static configuration if plugin fails
4. Cache result with configurable TTL
5. Support manual cache refresh via webhooks

## Monitoring and Observability

### Metrics (Prometheus)
- Request counts and durations
- Flow execution success/failure rates
- Challenge generation and verification rates
- Session creation and completion statistics
- Server health check results
- Bandwidth usage by resource and server

### Logging (Structured JSON)
- Session lifecycle events with client IP and user agent
- Download events with server selection and performance
- Error events with detailed context
- Challenge verification attempts
- Plugin execution results

### Health Checks
- Server backend availability via partial content requests
- Redis connectivity and performance
- Plugin execution health
- Configuration validation status

## Troubleshooting

### Common Issues
- **Version Provider Failures**: Check plugin logs, verify external API access
- **Flow Rule Issues**: Use debug logs to trace rule evaluation
- **Challenge Problems**: Check debug mode settings and plugin configuration
- **Performance Issues**: Monitor metrics for bottlenecks and server health
- **Cache Problems**: Verify Redis connectivity and key prefix configuration

### Debug Mode
- Set `debug_mode: true` in configuration
- Enables challenge bypass with detailed logging
- Adds verbose flow execution traces
- Includes plugin execution debug information