// craco.config.js

const CracoWorkboxPlugin = require('craco-workbox');
const path = require('path');

module.exports = {
    plugins: [{
        plugin: CracoWorkboxPlugin
    }],
    webpack: {
        // TODO: this is because of a bug in CRA, hopefully we can remove in the future
        // https://github.com/facebook/create-react-app/pull/11752
        configure: {
            ignoreWarnings: [
                function ignoreSourcemapsloaderWarnings(warning) {
                    return (
                        warning.module &&
                        warning.module.resource.includes("node_modules") &&
                        warning.details &&
                        warning.details.includes("source-map-loader")
                    );
                },
            ],
        },
        alias: {
            '@routes': path.resolve(__dirname, 'src/routes'),
            '@components': path.resolve(__dirname, 'src/components'),
            '@images': path.resolve(__dirname, 'src/images'),
            '@util': path.resolve(__dirname, 'src/utility'),
        },
    },
}