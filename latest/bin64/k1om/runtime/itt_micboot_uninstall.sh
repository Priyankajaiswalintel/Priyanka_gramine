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

ITT_NAME="${NAME:=}"_itt_lib
ITT_CONF="${NAME:=}"_itt

# file mapping
conf_dir1="/etc/sysconfig/mic/conf.d"
filesys_dir1="/opt/intel/mic"
# file mapping in YOCTO build
conf_dir2="/etc/mpss/conf.d"
filesys_dir2="/var/mpss"

if [ -r ${conf_dir2} ] ; then
    conf_dir=${conf_dir2}
    itt_file_dir=${filesys_dir2}/${ITT_NAME}
else
    conf_dir=${conf_dir1}
    itt_file_dir=${filesys_dir1}/${ITT_NAME}
fi

INSTALL_DIR="${INSTALL_DIR:=$itt_file_dir}"

rm -rf "${conf_dir}/${ITT_CONF}.conf"
rm -rf "${INSTALL_DIR}"
