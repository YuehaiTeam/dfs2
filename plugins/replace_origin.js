/**
 * DFS2 Plugin Demo: replace_origin
 * @description This plugin replaces [source] with [target] in all urls in the pool.
 * @param {[string, number][]} pool [url, weight][]
 * @param {string} indirect 'from to'
 * @param {never} options
 * @returns {Promise<bool|undefined>} whether to break the loop
 */
async function replace_origin(pool, indirect, options) {
    const [source, target] = indirect.split(' ');
    for (let i = 0; i < pool.length; i++) {
        const [url, weight] = pool[i];
        if (url.includes(source)) {
            pool[i][0] = url.replace(source, target);
        }
    }
}

exports = replace_origin;
