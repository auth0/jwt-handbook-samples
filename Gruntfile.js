module.exports = function(grunt) {

    grunt.initConfig({
        webpack: {
            build: require('./webpack.config.js')
        }
    });

    grunt.loadNpmTasks('grunt-webpack');

    grunt.registerTask('build', ['webpack']);
};
