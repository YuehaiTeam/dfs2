use anyhow::Result;

use crate::config::AppConfig;

pub mod profiles;

pub fn generate_rclone_config(config: &AppConfig, profile_filter: Option<&str>) -> Result<String> {
    let mut sections = Vec::new();

    for (server_id, server_config) in &config.servers {
        // 如果指定了profile过滤器，则只处理匹配的服务器
        if let Some(filter) = profile_filter {
            match &server_config.profile {
                Some(profile) if profile == filter => {}
                _ => continue,
            }
        }

        // 根据服务器类型生成相应的配置
        if server_config.r#type == "s3" {
            if let Ok(section) = profiles::s3::generate_s3_section(server_id, server_config) {
                sections.push(section);
            }
        }
    }

    Ok(sections.join("\n"))
}
