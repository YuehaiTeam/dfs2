/**
 * GitHub版本提供者插件
 * 通过GitHub Releases API获取仓库的最新版本
 * 
 * 配置选项:
 * - repository: GitHub仓库路径 (格式: owner/repo)
 * - auth_token: GitHub API Token (可选，用于提高API限制)
 * - include_prerelease: 是否包含预发布版本 (默认: false)
 * - tag_filter: 标签过滤正则表达式 (可选)
 * 
 * 返回格式:
 * {
 *   version: "1.2.3",
 *   changelog: "Release notes and changelog",
 *   metadata: {
 *     published_at: "2024-01-01T00:00:00Z",
 *     html_url: "https://github.com/owner/repo/releases/tag/v1.2.3",
 *     name: "Release Name",
 *     prerelease: false,
 *     tag_name: "v1.2.3",
 *     author: "username"
 *   }
 * }
 */

exports = async function(options, resourceId, extras) {
    const { 
        repository, 
        auth_token, 
        include_prerelease = false,
        tag_filter 
    } = options;
    
    // 验证必需参数
    if (!repository || typeof repository !== 'string') {
        throw new Error('repository parameter is required and must be a string (format: owner/repo)');
    }
    
    if (!repository.includes('/') || repository.split('/').length !== 2) {
        throw new Error('repository must be in format "owner/repo"');
    }
    
    const [owner, repo] = repository.split('/');
    if (!owner || !repo) {
        throw new Error('Invalid repository format, both owner and repo must be non-empty');
    }
    
    // 构建API URL
    const apiUrl = `https://api.github.com/repos/${repository}/releases`;
    
    // 准备请求头
    const headers = {
        'User-Agent': 'DFS2-VersionProvider/1.0',
        'Accept': 'application/vnd.github.v3+json',
    };
    
    if (auth_token) {
        headers['Authorization'] = `token ${auth_token}`;
    }
    
    console.log(`Fetching GitHub releases for ${repository}...`);
    
    try {
        // 请求GitHub API
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: headers,
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`GitHub API error ${response.status}: ${errorText}`);
        }
        
        const releases = await response.json();
        
        if (!Array.isArray(releases) || releases.length === 0) {
            throw new Error('No releases found for repository');
        }
        
        // 过滤预发布版本
        let filteredReleases = releases;
        if (!include_prerelease) {
            filteredReleases = releases.filter(release => !release.prerelease);
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
        
        // 获取最新的release (GitHub API默认按时间排序)
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
                html_url: latestRelease.html_url,
                prerelease: latestRelease.prerelease || false,
                draft: latestRelease.draft || false,
                author: latestRelease.author?.login || null,
                body: latestRelease.body || '',
                assets_count: latestRelease.assets?.length || 0,
                total_releases: releases.length,
                filtered_releases: filteredReleases.length,
                api_rate_limit: {
                    remaining: response.headers.get('x-ratelimit-remaining'),
                    reset: response.headers.get('x-ratelimit-reset'),
                }
            }
        };
        
        console.log(`Successfully fetched version for ${repository}: ${version}`);
        
        return result;
        
    } catch (error) {
        console.error(`GitHub version provider error for ${repository}:`, error.message);
        
        // 提供更详细的错误信息
        if (error.message.includes('404')) {
            throw new Error(`Repository ${repository} not found or not accessible. Check repository name and access permissions.`);
        } else if (error.message.includes('403')) {
            throw new Error(`GitHub API rate limit exceeded or access denied. Consider adding an auth_token.`);
        } else if (error.message.includes('ENOTFOUND') || error.message.includes('network')) {
            throw new Error(`Network error accessing GitHub API: ${error.message}`);
        }
        
        throw error;
    }
};