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

const appdirs = require('./appdirs');
const logging = require('./logging');

class Settings {
    constructor(opts) {
        opts = opts || { defaults: {} };
        const userAppDir = appdirs.getAppDir();

        this.dataFilePath = path.join(userAppDir, opts.configName || ('user-preferences' + '.json'));

        const stat = fs.existsSync(this.dataFilePath) ? fs.lstatSync(this.dataFilePath)
            : undefined;
        if (stat && stat.isSymbolicLink()) {
            this.dataFilePath = '';
            logging.report('Failed to process data file: symlink detected');
        }
        this.data = parseDataFile(this.dataFilePath, opts.defaults);

        app.on('quit', () => {
            try {
                fs.writeFileSync(this.dataFilePath, JSON.stringify(this.data));
            } catch (err) {
                logging.report('Failed to save user settings: ' + err.message);
            }
        });
    }

    get(key) {
        return this.data[key];
    }

    set(key, val) {
        this.data[key] = val;
    }
}

function parseDataFile(filePath, defaults) {
    try {
        return JSON.parse(fs.readFileSync(filePath));
    } catch (err) {
        return defaults;
    }
}

module.exports = Settings;
