// craco.config.js

const CracoWorkboxPlugin = require('craco-workbox');
const path = require('path');

module.exports = {
    plugins: [{
        plugin: CracoWorkboxPlugin
    }],
    webpack: {
        alias: {
            '@routes': path.resolve(__dirname, 'src/routes'),
            '@components': path.resolve(__dirname, 'src/components'),
            '@images': path.resolve(__dirname, 'src/images'),
        },
    },
}