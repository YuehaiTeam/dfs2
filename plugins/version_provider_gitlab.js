/**
 * GitLab版本提供者插件
 * 通过GitLab Releases API获取项目的最新版本
 * 
 * 配置选项:
 * - project_id: GitLab项目ID (数字) 或 项目路径 (如: "group/project")
 * - gitlab_url: GitLab实例URL (默认: "https://gitlab.com")
 * - access_token: GitLab访问令牌 (可选，用于私有项目)
 * - include_prerelease: 是否包含预发布版本 (默认: false)
 * - tag_filter: 标签过滤正则表达式 (可选)
 * 
 * 返回格式:
 * {
 *   version: "1.2.3",
 *   changelog: "Release description and changelog",
 *   metadata: {
 *     created_at: "2024-01-01T00:00:00Z",
 *     tag_name: "v1.2.3",
 *     name: "Release Name",
 *     description: "Release description",
 *     author: { ... },
 *     web_url: "https://gitlab.com/group/project/-/releases/v1.2.3"
 *   }
 * }
 */

exports = async function(options, resourceId, extras) {
    const { 
        project_id,
        gitlab_url = 'https://gitlab.com',
        access_token,
        include_prerelease = false,
        tag_filter 
    } = options;
    
    // 验证必需参数
    if (!project_id) {
        throw new Error('project_id parameter is required (project ID number or "group/project" path)');
    }
    
    // 验证GitLab URL
    let baseUrl;
    try {
        baseUrl = new URL(gitlab_url);
        if (!baseUrl.protocol.startsWith('http')) {
            throw new Error('GitLab URL must use http or https protocol');
        }
    } catch (e) {
        throw new Error(`Invalid gitlab_url: ${e.message}`);
    }
    
    // URL编码项目ID (处理group/project格式)
    const encodedProjectId = encodeURIComponent(project_id);
    
    // 构建API URL
    const apiUrl = `${gitlab_url.replace(/\/$/, '')}/api/v4/projects/${encodedProjectId}/releases`;
    
    // 准备请求头
    const headers = {
        'User-Agent': 'DFS2-VersionProvider/1.0',
        'Accept': 'application/json',
    };
    
    if (access_token) {
        headers['Authorization'] = `Bearer ${access_token}`;
    }
    
    console.log(`Fetching GitLab releases for project ${project_id}...`);
    
    try {
        // 请求GitLab API
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: headers,
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            
            if (response.status === 404) {
                throw new Error(`Project ${project_id} not found or not accessible`);
            } else if (response.status === 401) {
                throw new Error('Unauthorized: Invalid access token or insufficient permissions');
            } else if (response.status === 403) {
                throw new Error('Forbidden: Access denied to project or API rate limit exceeded');
            }
            
            throw new Error(`GitLab API error ${response.status}: ${errorText}`);
        }
        
        const releases = await response.json();
        
        if (!Array.isArray(releases) || releases.length === 0) {
            throw new Error('No releases found for project');
        }
        
        // 过滤预发布版本
        let filteredReleases = releases;
        if (!include_prerelease) {
            // GitLab没有明确的prerelease字段，根据标签名判断
            filteredReleases = releases.filter(release => {
                const tagName = release.tag_name?.toLowerCase() || '';
                return !tagName.includes('alpha') && 
                       !tagName.includes('beta') && 
                       !tagName.includes('rc') && 
                       !tagName.includes('pre');
            });
        }
        
        // 应用标签过滤器
        if (tag_filter) {
            try {
                const regex = new RegExp(tag_filter);
                filteredReleases = filteredReleases.filter(release => 
                    regex.test(release.tag_name)
                );
            } catch (e) {
                throw new Error(`Invalid tag_filter regex: ${e.message}`);
            }
        }
        
        if (filteredReleases.length === 0) {
            throw new Error('No releases found matching the specified criteria');
        }
        
        // 获取最新的release (GitLab API按创建时间排序)
        const latestRelease = filteredReleases[0];
        
        // 提取版本号 (移除v前缀)
        let version = latestRelease.tag_name;
        if (version && (version.startsWith('v') || version.startsWith('V'))) {
            version = version.substring(1);
        }
        
        // 验证版本格式
        if (!version || version.trim() === '') {
            throw new Error(`Invalid version format: ${latestRelease.tag_name}`);
        }
        
        // 构建返回结果
        const result = {
            version: version,
            changelog: latestRelease.description || null,
            metadata: {
                tag_name: latestRelease.tag_name,
                name: latestRelease.name || '',
                description: latestRelease.description || '',
                created_at: latestRelease.created_at,
                released_at: latestRelease.released_at,
                author: {
                    id: latestRelease.author?.id,
                    username: latestRelease.author?.username,
                    name: latestRelease.author?.name,
                    avatar_url: latestRelease.author?.avatar_url,
                },
                commit: {
                    id: latestRelease.commit?.id,
                    short_id: latestRelease.commit?.short_id,
                    title: latestRelease.commit?.title,
                },
                milestones: latestRelease.milestones || [],
                evidences: latestRelease.evidences || [],
                assets: {
                    count: latestRelease.assets?.count || 0,
                    sources: latestRelease.assets?.sources || [],
                    links: latestRelease.assets?.links || [],
                },
                _links: latestRelease._links || {},
                total_releases: releases.length,
                filtered_releases: filteredReleases.length,
                gitlab_instance: baseUrl.origin,
                project_id: project_id,
            }
        };
        
        // 构建web URL
        if (latestRelease._links?.self) {
            result.metadata.web_url = latestRelease._links.self.replace('/api/v4/projects/', '/-/releases/');
        }
        
        console.log(`Successfully fetched GitLab version for project ${project_id}: ${version}`);
        
        return result;
        
    } catch (error) {
        console.error(`GitLab version provider error for project ${project_id}:`, error.message);
        
        // 提供更详细的错误信息
        if (error.message.includes('ENOTFOUND') || error.message.includes('network')) {
            throw new Error(`Network error accessing GitLab API at ${gitlab_url}: ${error.message}`);
        }
        
        throw error;
    }
};