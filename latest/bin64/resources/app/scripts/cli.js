/*
 * Copyright (C) 2019 Intel Corporation
 *
 * This software and the related documents are Intel copyrighted materials, and your use of them
 * is governed by the express license under which they were provided to you ("License"). Unless
 * the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
 * or transmit this software or the related documents without Intel's prior written permission.
 *
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
*/

// This module is responsible for parsing command line arguments
const { resolve } = require('path');
module.exports = require('yargs')
    .usage('$0 [resultOrProjectPath] [result2Path]', '', yargs => {
        yargs.positional('resultOrProjectPath', {
            describe: 'Result Or Project Path',
            conflicts: ['app-path', 'target-process', 'target-pid', 'project-path']
        })
            .positional('result2Path', {
                describe: 'Path to the second result'
            });
    })
    .options({
        'project-path': {
            describe: 'Path to open or create project.'
        },
        'app-path': {
            describe: 'Path to the application to be profiled',
            conflicts: ['target-pid', 'target-process'],
            implies: 'project-path',
            group: 'Target type'
        },
        'app-args': {
            describe: 'Application arguments',
            group: 'Application options',
            implies: 'app-path',
            type: 'array'
        },
        'app-working-dir': {
            describe: 'Directory from which the application will be run',
            group: 'Application options',
            implies: 'app-path'
        },
        'app-env-var': {
            describe: 'Application environmental variables',
            group: 'Application options',
            implies: 'app-path',
            type: 'array'
        },
        'app-env-vars-file': {
            describe: 'File path to stored application environmental variables',
            group: 'Application options',
            implies: 'app-path'
        },
        'target-pid': {
            describe: 'Process Id to be attached for profiling',
            type: 'number',
            conflicts: ['app-path', 'target-process'],
            implies: 'project-path',
            group: 'Target type'
        },
        'target-process': {
            describe: 'Process name to be attached for profiling',
            conflicts: ['app-path', 'target-pid'],
            implies: 'project-path',
            group: 'Target type'
        },
        'search-dir': {
            describe: 'Search directories for binary and symbol files',
            implies: 'project-path',
            type: 'array'
        },
        'source-search-dir': {
            describe: 'Search directories for binary and symbol files',
            implies: 'project-path',
            type: 'array'
        },
        'target-system': {
            describe: 'Target system network and user name: ssh:user@target',
            implies: 'project-path'
        },
        'usage-statistics-opt-in': {
            describe: 'Allow to collect information for Intel Software Improvement Program',
            conflicts: ['usage-statistics-opt-out'],
            group: 'Usage statistics'
        },
        'usage-statistics-opt-out': {
            describe: 'Do not allow to collect information for Intel Software Improvement Program',
            conflicts: ['usage-statistics-opt-in'],
            group: 'Usage statistics'
        },
        'print-usage-statistics-agreement': {
            describe: 'Print agreement text for Intel Software Improvement Program',
            group: 'Usage statistics'
        },
        'integration-mode': {
            describe: 'IDE the product is integrated into',
            group: 'Internal options',
            hidden: true
        },
        'web-port': {
            describe: 'HTTP/HTTPS port for web UI and data APIs',
            group: 'Internal options',
            hidden: true
        },
        'log-level': {
            describe: 'Log level (debug, info, warn, error)',
            group: 'Internal options',
            choices: ['debug', 'info', 'warn', 'error'],
            hidden: true
        },
        'log-to-console': {
            describe: 'Output log messages to console',
            group: 'Internal options',
            hidden: true
        },
        'debug-nodejs': {
            describe: 'run Node.js middleware in debug mode',
            group: 'Internal options',
            hidden: true
        },
        'open-cdt': {
            describe: 'open embedded Chrome Developing tool',
            group: 'Internal options',
            hidden: true
        },
        'force-maximize': {
            describe: 'maximize main window, used for ST/IT GUI tests',
            group: 'Internal options',
            hidden: true
        },
        'frontend-service-socket-port': {
            describe: 'TCP Socket port that frontend listens to for initialization parameters and lifetime tracking',
            group: 'Internal options',
            hidden: true
        },
        'no-sandbox': {
            describe: 'Disable Sandbox',
            group: 'Internal options',
            hidden: true
        },
        'chrome-version': {
            describe: 'Print Chrome version',
            group: 'Internal options',
            hidden: true
        },
        'remote-debugging-port': {
            describe: 'Use port for remote debugging',
            group: 'Internal options',
            hidden: true
        },
        'suppress-automatic-help-tours': {
            describe: 'Suppress automatic help tours'
        }
    })
    .version('chrome-version', String(process.versions.chrome))
    .help('h')
    .alias('h', 'help')
    .strict(true)
    .coerce('app-env-vars-file', filePath => require('fs').readFileSync(filePath, 'utf8'))
    .coerce(['resultOrProjectPath', 'result2Path', 'project-path'], value => resolve(value))
    .parserConfiguration({ 'boolean-negation': false })
    .parse(process.argv.slice(1));
