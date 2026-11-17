//! 进程内只读 MCP 端点：凭据代理、目录与查询转发。

mod handler;
mod oauth;
pub mod settings;

pub use handler::router;
pub use settings::{McpEnv, McpSettings, load};

use crate::container::AppContext;
use axum::Router;
use tracing::info;

/// 两项门控齐全时挂载 `/{prefix}/mcp`；另设了 `MCP_PUBLIC_URL` 时再挂 `/{prefix}/oauth/*` 与带前缀的发现端点。否则不挂路径。配置不完整返回错误。
pub fn maybe_router(ctx: AppContext) -> Result<Option<Router>, Vec<String>> {
    match load() {
        Ok(McpEnv::Enabled(settings)) => Ok(Some(mount(std::sync::Arc::new(*settings), ctx))),
        Ok(McpEnv::Disabled) => {
            info!("MCP disabled: MCP_TOKEN and MCP_PREFIX are not both set");
            Ok(None)
        }
        Err(errors) => Err(errors),
    }
}

/// 根路径的 `/.well-known/...` 发现端点只在设了 `MCP_PUBLIC_URL` 时挂载。
fn mount(settings: std::sync::Arc<McpSettings>, ctx: AppContext) -> Router {
    let oauth_state = oauth::OAuthState::new(settings.clone(), ctx.data_store.clone());
    let mounted = Router::new().nest(&format!("/{}", settings.prefix), router(settings, ctx));
    match oauth_state {
        Some(state) => mounted.merge(oauth::well_known_router(state)),
        None => mounted,
    }
}
