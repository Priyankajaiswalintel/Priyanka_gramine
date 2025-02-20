#!/bin/bash
#
# Copyright (C) 2014 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#

# this script needs to be run as root/sudoer.

abspath="$(cd "${0%/*}" 2>/dev/null; echo "$PWD"/"${0##*/}")"
orig_dir=`dirname "$abspath"`

"${orig_dir}/sep_micboot_uninstall.sh" $*

MIC_DIR=/amplxe
NAME=amplxe
if [ -r "${orig_dir}/../../config/product_info.cfg" ] ; then
    MIC_DIR_TMP=`cat "${orig_dir}/../../config/product_info.cfg" | grep defaultTargetInstallPath_mic | cut -d "=" -f 2 | sed -e 's/^"//'  -e 's/"$//'`
    if [ "${MIC_DIR_TMP}" != "" ]; then
        MIC_DIR=$MIC_DIR_TMP
        NAME=`echo "$MIC_DIR_TMP" | sed -r 's/\//_/g'`
    fi
fi

INSTALL_ROOT=/opt/intel/mic
if [ -r "/etc/mpss/conf.d" ] ; then
    INSTALL_ROOT=/var/mpss
fi
    
NAME=$NAME INSTALL_DIR=$INSTALL_ROOT/$MIC_DIR "${orig_dir}/runtime/itt_micboot_uninstall.sh"
NAME=$NAME MIC_DIR=$MIC_DIR INSTALL_DIR=$INSTALL_ROOT/$MIC_DIR "${orig_dir}/uninstall_mic.sh"

