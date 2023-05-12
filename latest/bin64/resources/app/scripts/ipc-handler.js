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

const logging = require('./logging');
const request = require('./request');
const cliParams = require('./cli');
const { dialog, shell, clipboard } = require('electron');

module.exports = {
    init(mainWindow) {
        const { ipcMain } = require('electron');

        ipcMain.handle('dialog:open-file', async (_, params) => {
            const result = await dialog.showOpenDialog(mainWindow, params);
            return result.filePaths;
        });

        ipcMain.handle('dialog:save-file', async (_, params) => {
            const result = await dialog.showSaveDialog(mainWindow, params);
            return result.filePath;
        });

        ipcMain.handle('window:show', () => mainWindow.show());
        ipcMain.handle('window:close', () => mainWindow.close());
        ipcMain.handle('window:dev-tools:toggle', () => mainWindow.toggleDevTools());
        ipcMain.handle('window:title:set', (_, title) => mainWindow.setTitle(title));

        ipcMain.on('link:open', (event, params) => {
            shell.openExternal(params.url, { activate: true });
        });

        ipcMain.on('request:send', function sendRequest(event, params) {
            return request.send(params)
                .then(data => {
                    event.sender.send('request:response', { url: params.url, data });
                })
                .catch(error => {
                    event.sender.send('request:error', { url: params.url, error });
                });
        });

        ipcMain.on('logging:log', function logMessage(event, params) {
            if (!params.message) return;

            logging.log(params.message);
        });

        ipcMain.on('startUpParams', function getStartupOptions(event) {
            event.sender.send('startUpParams:response', cliParams);
        });

        ipcMain.on('clipboard:writeText', (event, params) => clipboard.writeText(params.text));
    }
};
