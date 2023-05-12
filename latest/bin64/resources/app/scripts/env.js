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

// This script is loaded within Electron app before all other scripts from web page
// It sets all necessary variables/modules for proper working/launching of
// VTune GUI inside Electron framework

const { ipcRenderer, contextBridge } = require('electron');

contextBridge.exposeInMainWorld('el', {
    clipboard: {
        writeText: text => ipcRenderer.send('clipboard:writeText', { text })
    },
    dialog: {
        async showOpenDialog(params, callback) {
            const filePaths = await ipcRenderer.invoke('dialog:open-file', params);
            callback && callback(filePaths);
            return filePaths;
        },
        async showSaveDialog(params, callback) {
            const filePath = await ipcRenderer.invoke('dialog:save-file', params);
            console.log('filePath', filePath);
            callback && callback(filePath);
            return filePath;
        }
    },
    externalRequest(params) {
        return new Promise((resolve, reject) => {
            ipcRenderer.on('request:response', onResponse);
            ipcRenderer.on('request:error', onError);
            ipcRenderer.send('request:send', params);

            function onResponse(event, response) {
                if (response.url === params.url) {
                    ipcRenderer.removeListener('request:response', onResponse);
                    ipcRenderer.removeListener('request:error', onError);

                    resolve(response.data);
                }
            }

            function onError(event, response) {
                if (response.url === params.url) {
                    ipcRenderer.removeListener('request:response', onResponse);
                    ipcRenderer.removeListener('request:error', onError);

                    reject(response.error);
                }
            }
        });
    },
    log(message) {
        ipcRenderer.send('logging:log', { message });
    },
    getStartupParams() {
        return new Promise(resolve => {
            ipcRenderer.once('startUpParams:response', (event, response) => resolve(response));
            ipcRenderer.send('startUpParams', {});
        });
    },
    openUrlExternal: url => ipcRenderer.send('link:open', { url }),
    window: {
        close: () => ipcRenderer.invoke('window:close'),
        setTitle: title => ipcRenderer.invoke('window:title:set', title),
        show: () => ipcRenderer.invoke('window:show')
    },
    toggleDevTools: () => ipcRenderer.invoke('window:dev-tools:toggle'),
    logError: (message, source, lineNumber) => {
        ipcRenderer.send('logging:log', {
            message: `[JS EXCEPTION]: ${message}; src: ${source}:${lineNumber}`
        });
    }

});
