/*
 * Copyright (C) 2018 Intel Corporation
 *
 * This software and the related documents are Intel copyrighted materials, and your use of them
 * is governed by the express license under which they were provided to you ("License"). Unless
 * the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
 * or transmit this software or the related documents without Intel's prior written permission.
 *
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
*/

const { app } = require('electron');
const fs = require('fs');
const path = require('path');
let appDir, logsDir;

module.exports = {
    getAppDir() { return appDir; },
    getLogsDir() { return logsDir; },
    init() {
        if (process.platform === 'win32') {
            appDir = app.getPath('userData'); // Will return %APPDATA%/<product_name> folder under current user

            return createLogsDir();
        } else {
            const userHomeDir = process.env.HOME || '.';
            const productUserConfigDir = path.join(userHomeDir, '.intel');
            const productLegalShortNameSubDir = 'vtune';
            const productLegalShortNameSubDirFallback = 'amplxe-frontend'; // Is used in case we don't have access to 'amplxe' directory

            const unixAppDir = path.join(productUserConfigDir, productLegalShortNameSubDir);
            const unixAppDirFallback =
                path.join(productUserConfigDir, productLegalShortNameSubDirFallback);

            return createDirectoryIfNotExists(unixAppDir)
                .catch(() => createDirectoryIfNotExists(unixAppDirFallback))
                .then(resolvedUnixAppDir => {
                    appDir = resolvedUnixAppDir;

                    return createLogsDir();
                })
                .catch(err => Promise.reject(new Error('Failed to create app directory: ' + err)));
        }

        function createDirectoryIfNotExists(dirPath) {
            return new Promise((resolve, reject) => {
                fs.access(dirPath, fs.constants.F_OK | fs.constants.W_OK, checkError => {
                    if (checkError) {
                        if (checkError.code === 'ENOENT') { // Directory doesn't exist
                            mkdirRecursive(dirPath, mkdirError => {
                                if (mkdirError) reject(mkdirError.message);
                                else resolve(dirPath);
                            });
                        } else { // No write access to the current directory
                            reject(checkError.message);
                        }
                    } else resolve(dirPath);
                });
            });
        }

        function createLogsDir() {
            return createDirectoryIfNotExists(path.join(appDir, 'logs'))
                .then(resolvedDir => { logsDir = resolvedDir; })
                .catch(err => {
                    // Let's just use appDir in this case.
                    // Please note that GUI won't start if we failed to create appDir
                    logsDir = appDir;
                    console.error('Failed to create logs directory: ' + err);
                });
        }

        function mkdirRecursive(dirPath, callback) {
            const parentDir = path.dirname(dirPath);

            fs.access(parentDir, fs.constants.F_OK, checkError => {
                if (checkError) {
                    mkdirRecursive(parentDir, mkdirError => {
                        mkdirError ? callback(mkdirError) : createDir(dirPath, callback);
                    });
                } else createDir(dirPath, callback);
            });
        }

        function createDir(path, callback) {
            fs.mkdir(path, { mode: 0o777 }, callback);
        }
    }
};
