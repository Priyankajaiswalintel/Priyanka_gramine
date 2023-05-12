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

const { Menu } = require('electron');
const os = require('os');

module.exports = {
    setAppMenu() {
        // Copy, Paste, SelectAll and other 'Edit' commands ain't enabled in Electron
        // on MacOS by default. The only way to provide that functional to users is to
        // add Application Menu
        if (os.type() === 'Darwin') {
            const osxMenu = Menu.buildFromTemplate([
                {
                    label: 'Edit',
                    submenu: [
                        { role: 'undo' },
                        { role: 'redo' },
                        { type: 'separator' },
                        { role: 'cut' },
                        { role: 'copy' },
                        { role: 'paste' },
                        { role: 'pasteandmatchstyle' },
                        { role: 'delete' },
                        { role: 'selectall' }
                    ]
                }
            ]);

            Menu.setApplicationMenu(osxMenu);
        } else {
            Menu.setApplicationMenu(null); // Fully remove standard menu bar
        }
    }
};
