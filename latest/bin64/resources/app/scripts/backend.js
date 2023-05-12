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
const childProcess = require('child_process');

const fs = require('fs');
const net = require('net');
const path = require('path');

const logging = require('./logging');
const frontendParams = require('./cli');

module.exports = {
    async start(serviceSocketPort) {
        const serviceSocket = await startServiceSocket(serviceSocketPort);
        return startBackend(serviceSocket);
    },
    onClose: () => {}
};

function startBackend(serviceSocket) {
    const backendParamsPromise = new Promise((resolve, reject) => {
        serviceSocket.once('connection', backendSocket => {
            logging.report('vtune-backend connected to service socket...');
            let buffer = Buffer.from('');

            backendSocket.on('data', onData);
            backendSocket.on('error', error => {
                logging.report('startBackend-serviceSocket-error, error: ' + error);
                reject(error);
            });
            backendSocket.on('close', () => {
                logging.report('startBackend-serviceSocket-close');
                module.exports.onClose();
            });

            function onData(data) {
                buffer = Buffer.concat([buffer, data]);
                logging.report('startBackend-onData, data: ' + data);
                let message;
                try {
                    message = JSON.parse(buffer.toString());
                } catch (err) {
                    return;
                }

                // Assuming a single message from backend for now
                backendSocket.removeListener('data', onData);

                onBackendParamsReceived(message);
            }

            function onBackendParamsReceived(backendParameters) {
                logging.report('Received backend parameters:', backendParameters);

                loadCertificatesAndPassphrase(backendParameters)
                    .then(resolve)
                    .catch(reject);
            }
        });
    });

    spawnBackendProcess(serviceSocket.address().port);

    return backendParamsPromise;
}

function startServiceSocket(serviceSocketPort) {
    logging.report('Starting service socket...');

    const serviceSocket = net.createServer();
    serviceSocket.on('error', err => {
        logging.report('Service server error:', err);
    });

    app.on('quit', () => serviceSocket.close());

    return new Promise((resolve, reject) => {
        serviceSocket.listen(serviceSocketPort, '127.0.0.1', err => {
            if (err) reject(err);
            else {
                logging.report('Service socket was started successfully on port:', serviceSocket.address().port);
                resolve(serviceSocket);
            }
        });
    });
}

function spawnBackendProcess(serviceSocketPort) {
    // We have to wrap the path with quotes because otherwise it won't start vtune-backend
    // if the path contains spaces
    const backendBinaryPath = `"${path.join(getBackendBinaryDir(), 'vtune-backend')}"`;

    logging.report('Spawning vtune-backend process with path:', backendBinaryPath);
    const backendParams = ['--frontend-service-socket-port', serviceSocketPort];
    if (frontendParams.integrationMode) backendParams.push('--integration-mode', frontendParams.integrationMode);
    if (frontendParams.webPort) backendParams.push('--web-port', frontendParams.webPort);
    if (frontendParams.logLevel) backendParams.push('--log-level', frontendParams.logLevel);
    if (frontendParams.debugNodejs) backendParams.push('--debug-nodejs');
    if (frontendParams.logToConsole) backendParams.push('--log-to-console');
    if (frontendParams.suppressAutomaticHelpTours) backendParams.push('--suppress-automatic-help-tours');
    if (frontendParams.usageStatisticsOptIn) backendParams.push('--usage-statistics-opt-in');
    if (frontendParams.usageStatisticsOptOut) backendParams.push('--usage-statistics-opt-out');
    if (frontendParams.printUsageStatisticsAgreement) backendParams.push('--print-usage-statistics-agreement');

    const backendProcess = childProcess.spawn(backendBinaryPath, backendParams,
        {
            shell: true // This option is required so that crash handler could launch debugger when user chooses to debug the crashed process
        });

    backendProcess.stdout.pipe(process.stdout);
    backendProcess.stderr.pipe(process.stderr);

    backendProcess.on('close', () => module.exports.onClose());

    logging.report('vtune-backend process was spawned successfully');
}

async function loadCertificatesAndPassphrase(backendParameters) {
    if (backendParameters.webServerCertificatePath) {
        logging.report('Reading SSL data...');

        const [webServerCertificate, passphrase] = await Promise.all([
            loadFile(backendParameters.webServerCertificatePath),
            loadFile(backendParameters.passphrasePath)
        ]);

        logging.report('Successfully loaded SSL data:', { webServerCertificate, passphrase });

        return {
            ...backendParameters,
            webServerCertificate,
            passphrase
        };
    } else {
        return backendParameters;
    }
}

function loadFile(path) {
    return new Promise((resolve, reject) => {
        if (!path) return resolve('');

        fs.lstat(path, (err, stat) => {
            if (err) {
                reject(err);
            }
            if (!stat.isSymbolicLink()) {
                fs.readFile(path, (err, data) => {
                    if (err) return reject(err);

                    return resolve(data.toString());
                });
            } else reject(new Error('File is a symbolic link'));
        });
    });
}

function getBackendBinaryDir() {
    // vtune-backend binary is located in the same directory as Electron binary
    return path.dirname(app.getPath('exe'));
}
