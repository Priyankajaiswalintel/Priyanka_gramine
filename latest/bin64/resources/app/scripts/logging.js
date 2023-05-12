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

const appdirs = require('./appdirs');
const fs = require('fs');
const os = require('os');
const path = require('path');

class Logger {
    constructor() {
        this._directory = undefined;
        this._stream = undefined;

        this._testingMode = !!process.env.TS_SESSION_WORK_DIR;
    }

    init() {
        this._directory = appdirs.getLogsDir();
        this._stream = this.createNewWritableStream('amplxe-frontend.log');
    }

    createNewWritableStream(fileName) {
        if (!this._directory) return;
        const filePath = path.join(this._directory, fileName);
        const stat = fs.existsSync(filePath) ? fs.lstatSync(filePath)
            : undefined;
        if (stat && stat.isSymbolicLink()) return;

        return fs.createWriteStream(filePath);
    }

    log(message) {
        if (!this._stream) return;
        this._stream.write(`${this._date()} ${message.toString()}` + os.EOL);
    }

    _date() {
        return `[${new Date().toISOString()}]`;
    }

    _print(msg) {
        return typeof (msg) === 'string' ? msg : JSON.stringify(msg);
    }

    _twoWayLog(enableConsole, level, ...messages) {
        if (enableConsole) {
            console.log(this._date(), ...messages);
        }
        this.log([level, ...messages.map(this._print)].join(' '));
    }

    report(...messages) {
        this._twoWayLog(this._testingMode, 'REPORT:', ...messages);
    }

    error(...messages) {
        this._twoWayLog(true, 'ERROR:', ...messages);
    }
}

module.exports = new Logger();
