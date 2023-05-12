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

const { app, session } = require('electron');

class NetRequest {
    constructor() {
        this._serverCertificateFingerprint = undefined;
        this._serverCertificate = undefined;
    }

    init(certificate) {
        this._serverCertificate = certificate;

        // net.request doesn't raise app certificate-error event - https://github.com/electron/electron/issues/8074
        // thus need to validate self-signed middleware certificate separately for internal requests
        // to amplxe-backend's web server
        session.defaultSession.setCertificateVerifyProc((request, callback) => {
            const { hostname, certificate } = request;
            if (hostname === '127.0.0.1' && this.validateMiddlewareCertificate(certificate)) {
                callback(0); // Indicates success and disables Certificate Transparency verification
            } else {
                callback(-3); // Uses the verification result from Chromium
            }
        });

        app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
            // Since our middleware SSL certificate is self-signed, Chromium won't trust it by
            // default and throw a certificate error. Therefore, we must check certificate manually
            // and allow connection to NodeJS server.
            if (this.validateMiddlewareCertificate(certificate)) {
                event.preventDefault();
                callback(true);
            } else callback(false);
        });
    }

    send(params) {
        return new Promise((resolve, reject) => {
            const { net } = require('electron');
            if (!net) reject(new Error('Failed to get \'net\' module'));

            if (!(params && params.url)) reject(new Error('Failed to get request URL from params'));

            const request = net.request(params);
            request.on('response', response => {
                const chunks = [];

                response.on('data', chunk => {
                    chunks.push(chunk);
                });

                response.on('end', () => {
                    resolve(Buffer.concat(chunks));
                });

                response.on('error', reject);
            });

            request.on('error', reject);
            request.end();
        });
    }

    validateMiddlewareCertificate(certificate) {
        if (!!certificate.fingerprint &&
            certificate.fingerprint === this._serverCertificateFingerprint) {
            return true;
        } else if (areSame(this._serverCertificate, certificate.data)) {
            this._serverCertificateFingerprint = certificate.fingerprint;
            return true;
        }
        return false;

        function areSame(lhs, rhs) {
            return lhs.replace(/\s/g, '') === rhs.replace(/\s/g, '');
        }
    }
}

module.exports = new NetRequest();
