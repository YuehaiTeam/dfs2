/**
 * CNB 平台版本提供者插件
 * 从 腾讯云 CNB.cool 平台获取项目的最新 release 版本信息
 * 
 * 配置选项 (options):
 * - repository: 仓库路径，格式为 "owner/repository" (必需)
 * - authorization: CNB API 访问令牌 (必需，需要 repo-code:r 权限)
 * - include_prerelease: 是否包含预发布版本 (默认: false)
 * 
 * 返回格式:
 * {
 *   version: "1.2.3",
 *   changelog: "Release notes and changelog",
 *   metadata: {
 *     tag_name: "v1.2.3",
 *     published_at: "2024-01-01T00:00:00Z",
 *     prerelease: false,
 *     api_source: "cnb"
 *   }
 * }
 */

exports = async function(options, resourceId, extras) {
    const { 
        repository, 
        authorization, 
        include_prerelease = false 
    } = options;
    
    // 验证必需参数
    if (!repository || typeof repository !== 'string') {
        throw new Error('repository parameter is required and must be a string (format: owner/repository)');
    }
    
    if (!repository.includes('/') || repository.split('/').length !== 2) {
        throw new Error('repository must be in format "owner/repository"');
    }
    
    const [owner, repo] = repository.split('/');
    if (!owner || !repo) {
        throw new Error('Invalid repository format, both owner and repository must be non-empty');
    }
    
    if (!authorization || typeof authorization !== 'string') {
        throw new Error('authorization parameter is required and must be a string (CNB API access token)');
    }

    console.log(`Fetching CNB releases for ${repository}...`);

    // CNB API endpoint
    const apiUrl = `https://api.cnb.cool/${repository}/-/releases?page=1&page_size=20`;

    try {
        // 发起 API 请求
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'User-Agent': 'DFS2-VersionProvider/1.0',
                'Accept': 'application/json',
                'Authorization': authorization
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            if (response.status === 401) {
                throw new Error(`CNB API authentication failed: Please check if the access token is valid and has repo-code:r permission`);
            } else if (response.status === 404) {
                throw new Error(`Repository ${repository} not found or not accessible. Check repository name and access permissions.`);
            } else {
                throw new Error(`CNB API error ${response.status}: ${errorText}`);
            }
        }

        const releases = await response.json();

        if (!Array.isArray(releases) || releases.length === 0) {
            throw new Error('No releases found for repository');
        }

        // 过滤releases
        let filteredReleases = releases.filter(release => {
            // 跳过草稿版本
            if (release.draft) {
                return false;
            }
            
            // 根据预发布设置过滤
            if (release.prerelease && !include_prerelease) {
                return false;
            }
            
            return true;
        });

        if (filteredReleases.length === 0) {
            throw new Error('No releases found matching the specified criteria');
        }

        // 获取最新的release (CNB API 返回的列表已按时间排序)
        const latestRelease = filteredReleases[0];

        // 提取版本号 (移除v前缀)
        let version = latestRelease.tag_name;
        if (version.startsWith('v') || version.startsWith('V')) {
            version = version.substring(1);
        }

        // 验证版本格式
        if (!version || version.trim() === '') {
            throw new Error(`Invalid version format: ${latestRelease.tag_name}`);
        }

        // 构建返回结果
        const result = {
            version: version,
            changelog: latestRelease.body || null,
            metadata: {
                tag_name: latestRelease.tag_name,
                name: latestRelease.name || '',
                published_at: latestRelease.published_at,
                created_at: latestRelease.created_at,
                prerelease: latestRelease.prerelease || false,
                draft: latestRelease.draft || false,
                is_latest: latestRelease.is_latest || false,
                author: latestRelease.author?.username || null,
                body: latestRelease.body || '',
                assets_count: latestRelease.assets?.length || 0,
                total_releases: releases.length,
                filtered_releases: filteredReleases.length,
                api_source: "cnb"
            }
        };

        console.log(`Successfully fetched version for ${repository}: ${version}`);

        return result;

    } catch (error) {
        console.error(`CNB version provider error for ${repository}:`, error.message);
        
        // 提供更详细的错误信息
        if (error.message.includes('ENOTFOUND') || error.message.includes('network')) {
            throw new Error(`Network error accessing CNB API: ${error.message}`);
        }
        
        throw error;
    }
};