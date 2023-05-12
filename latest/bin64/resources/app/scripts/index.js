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

const { app, BrowserWindow } = require('electron');

const os = require('os');
const path = require('path');

const appdirs = require('./appdirs');
const appmenu = require('./appmenu');
const backend = require('./backend');
const ipcHandler = require('./ipc-handler');
const logging = require('./logging');
const request = require('./request');
const Settings = require('./settings');
const processArguments = require('./cli');

const appIcons = {
    'Linux': path.join(__dirname, '../icons/VTune.png'),
    'Darwin': path.join(__dirname, '../icons/VTune.icns'),
    'Windows_NT': path.join(__dirname, '../icons/VTune.ico'),
    'default': path.join(__dirname, '../icons/VTune.png')
};

const defaultSettings = {
    defaults: {
        windowState: {
            bounds: { width: 1280, height: 720 }
        }
    }
};

// Keep a global reference of the VTune window object, if you don't, the window will
// be closed automatically when the JavaScript object is garbage collected.
let mainWindow, splashScreenWindow;

let appSettings;
let isShuttingDown = false;

if (!['debug', 'info', 'warn'].includes(processArguments.logLevel)) {
    app.commandLine.appendSwitch('ignore-certificate-errors');
}
app.commandLine.appendSwitch('no-sandbox');
app.commandLine.appendSwitch('disable-http-cache');
app.commandLine.appendSwitch('no-xshm');
app.commandLine.appendSwitch('disable-gpu');

logging.report('Launching VTune Profiler GUI...');

const electronReady = new Promise(resolve => {
    // This method will be called when Electron has finished
    // initialization and is ready to create browser windows.
    // Some APIs can only be used after this event occurs.
    app.on('ready', () => {
        if (processArguments.printUsageStatisticsAgreement) {
            clearTimeout(launchTimeout);
            resolve();
        } else {
            logging.report('Electron shell is ready');

            appmenu.setAppMenu();

            createSplashScreenWindow();
            resolve();
        }
    });
});

const launchTimeout = setTimeout(() => {
    logging.error('Failed to launch VTune Amplifier GUI...');
    return shutdown();
}, 60000);

backend.onClose = shutdown;

appdirs.init()
    .then(() => {
        appSettings = new Settings(defaultSettings);
        logging.init();

        return Promise.all([
            backend.start(processArguments.frontendServiceSocketPort),
            electronReady
        ]);
    })
    .then(parameters => {
        const [ backendParams ] = parameters;
        const {
            webServerPort,
            passphrase,
            webServerCertificate
        } = backendParams;

        if (!webServerPort) return Promise.reject(new Error('No HTTP port has been provided!'));
        else {
            clearTimeout(launchTimeout);

            request.init(webServerCertificate);

            createMainWindow({
                certificate: webServerCertificate,
                passphrase,
                port: webServerPort
            });

            ipcHandler.init(mainWindow);
        }
    })
    .catch(error => {
        logging.error(error);
        shutdown();
    });

function createSplashScreenWindow() {
    splashScreenWindow = new BrowserWindow({
        width: 650,
        height: 400,
        transparent: true,
        frame: false,
        alwaysOnTop: true,
        icon: appIcons[os.type()] || appIcons['default'],

        webPreferences: {
            nativeWindowOpen: true
        }
    });
    splashScreenWindow.loadURL(`file://${path.join(__dirname, '../splashscreen/index.html')}`);

    splashScreenWindow.on('closed', () => {
        // Dereference the window object
        splashScreenWindow = null;
    });
}

function createMainWindow(webServerParams) {
    const windowState = appSettings.get('windowState');

    // Set minimum window size to 400x200px to prevent 'bugs' with invisible window
    // (for instance, on MacOS it's possible to shrink window to 1x1px size)
    const minWidth = 400;
    const minHeight = 200;

    let windowBounds = applyMinWindowSize(windowState.bounds);

    mainWindow = new BrowserWindow({
        // Restore previous window bounds/position or set defaults
        x: windowBounds.x,
        y: windowBounds.y,
        width: windowBounds.width,
        height: windowBounds.height,

        // Set minimum window dimensions for user resize
        minWidth,
        minHeight,

        // Hide window till it finished loading of page files/scripts
        show: false,

        // Set product icon for window and taskbars
        icon: appIcons[os.type()] || appIcons['default'],

        webPreferences: {
            // It's not recommended to turn on node integration due to security reasons.
            // Instead of this, all useful modules (like fs/clipboard) are passed to
            // global window object in env.js
            nodeIntegration: false,
            // We have to set partition to create separate session for mainWindow,
            // so that default session proxy settings won't be overridden.
            // (Workaround for bug in Electron setProxy API)
            partition: 'MainWindow',
            preload: path.resolve(`${__dirname}/env.js`),
            enableRemoteModule: true,
            nativeWindowOpen: true,
            contextIsolation: true,
            sandbox: true
        }
    });

    if (!!processArguments && processArguments.openCdt) mainWindow.openDevTools();

    mainWindow.on('closed', () => {
        // Dereference the window object
        mainWindow = null;
    });

    mainWindow.webContents.on('will-navigate', event => {
        // Preventing all navigations within main window, cause we mustn't leave main
        // page of our application in any case
        event.preventDefault();
    });

    mainWindow.once('ready-to-show', () => {
        // If you dive into Electron documentation, you'll find that maximize() call also must
        // show the window, along with that show() call also gives focus to the window and so on.
        // However, sometimes maximize() doesn't bring the window to a visible state and this is a
        // known Chromium bug. So, let's just don't rely on documentation and how it 'must' work
        // and call show() and focus() manually to ensure we get what we want
        mainWindow.show();
        mainWindow.focus();
        if (splashScreenWindow) splashScreenWindow.close();

        if (windowState.fullscreen) mainWindow.setFullScreen(true);
        if (windowState.maximized ||
            (!!processArguments && processArguments.forceMaximize)) {
            mainWindow.maximize();
        }
    });

    ['resize', 'move', 'close'].forEach(eventName => {
        mainWindow.on(eventName, function saveWindowBounds() {
            const currentWindowState = {
                maximized: mainWindow.isMaximized(),
                fullscreen: mainWindow.isFullScreen()
            };

            if (!currentWindowState.maximized &&
                !currentWindowState.fullscreen &&
                !mainWindow.isMinimized()) {
                windowBounds = applyMinWindowSize(mainWindow.getBounds());
            }

            currentWindowState.bounds = windowBounds;

            appSettings.set('windowState', currentWindowState);
        });
    });

    // We have to bypass the proxy settings for localhost connections to workaround
    // not bypassed localhost in internet settings on a user machine to get local
    // requests(and GUI) working.
    function startVTuneGui() {
        const webServerUrl = `${webServerParams.certificate ? 'https' : 'http'}://127.0.0.1:${webServerParams.port}`;
        const uiUrl = `${webServerUrl}/ui?passphrase=${webServerParams.passphrase || ''}`;

        logging.report('Starting VTune GUI with url:', uiUrl);
        mainWindow.loadURL(uiUrl);
    }

    const res = mainWindow.webContents.session.setProxy({ proxyBypassRules: '<local>' }, startVTuneGui);
    if (res != null && typeof res.then === 'function') {
        res.then(startVTuneGui);
    }

    // Under some uncertain conditions we get tiny window dimensions on MacOS sometimes, which make
    // main window shrink to a size of 1px-width titlebar. We failed to investigate what brings
    // such behavior, so let's just prevent setting of that sizes anywhen
    function applyMinWindowSize(bounds) {
        bounds.width = Math.max(bounds.width, minWidth);
        bounds.height = Math.max(bounds.height, minHeight);

        return bounds;
    }
}

// Quit when all windows are closed.
app.on('window-all-closed', () => shutdown());

function shutdown() {
    if (isShuttingDown) return;
    isShuttingDown = true;

    if (splashScreenWindow) splashScreenWindow.destroy();
    if (mainWindow) mainWindow.destroy();

    return app.quit();
}
