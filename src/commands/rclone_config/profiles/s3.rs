use anyhow::Result;
use std::fmt::Write;

use crate::config::ServerConfig;
use crate::modules::server::s3::S3Signer;

pub fn generate_s3_section(server_id: &str, server_config: &ServerConfig) -> Result<String> {
    // 确保这是S3类型的服务器
    if server_config.r#type != "s3" {
        return Err(anyhow::anyhow!("Server {} is not S3 type", server_id));
    }

    // 解析S3配置
    let s3_signer = S3Signer::from_url(&server_config.url)?;

    let mut section = String::new();

    // 生成rclone配置节
    writeln!(&mut section, "[dfs-{}]", server_id)?;
    writeln!(&mut section, "type = s3")?;

    // 只有当profile为minio时才添加provider行
    if let Some(ref profile) = server_config.profile {
        if profile == "minio" {
            writeln!(&mut section, "provider = Minio")?;
        }
    }

    writeln!(&mut section, "access_key_id = {}", s3_signer.access_key())?;
    writeln!(
        &mut section,
        "secret_access_key = {}",
        s3_signer.secret_key()
    )?;
    writeln!(&mut section, "endpoint = {}", s3_signer.endpoint())?;

    Ok(section)
}
