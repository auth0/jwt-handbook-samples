module.exports = {
    entry: {
        'coding': './coding.js',
        'signing_and_validating': './signing_and_validating.js',
        'encryption': './encryption.js',
        'base64': ['./base64.js'],
        'sha256': ['./sha256.js'],
        'hmac': ['./hmac.js'],
        'hs256': './hs256.js',
        'rsassa': ['./rsassa.js'],
        'rs256': './rs256.js',
        'ps256': './ps256.js',
        'es256': './es256.js'
    },
    output: {
        path: __dirname + '/dist/',
        filename: "[name].js",
        devtoolModuleFilenameTemplate: "[absolute-resource-path]",
        devtoolFallbackModuleFilenameTemplate: "[absolute-resource-path]?[hash]" 
    },
    module: {
        loaders: [
            {
                test: /\.js$/,
                exclude: /(node_modules|bower_components)/,
                loader: 'babel', // 'babel-loader' is also a legal name to reference
                query: {
                    presets: ['es2015']
                }
            }
        ]
    },
    target: 'node',
    devtool: "source-map"
};
