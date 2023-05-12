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
DRYRUN="${DRYRUN:=no}"

abspath="$(cd "${0%/*}" 2>/dev/null; echo "$PWD"/"${0##*/}")"
orig_dir=`dirname "$abspath"`

if [ "${DRYRUN}" = "yes" ] ;  then
    echo "${orig_dir}/libittnotify_collector.so" "/usr/lib64/libittnotify.so"
    exit 0;
fi


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

"${orig_dir}/itt_micboot_uninstall.sh"

rm -rf ${ITT_CONF}.conf
echo "Overlay Filelist ${INSTALL_DIR} ${INSTALL_DIR}/itt.filelist on" >> ${ITT_CONF}.conf
rm -rf ${conf_dir}/*itt*.conf
mv -f ${ITT_CONF}.conf "${conf_dir}/${ITT_CONF}.conf"

if [ ! -d ${INSTALL_DIR} ]; then
    mkdir -p ${INSTALL_DIR}
fi

rm  -rf itt.filelist
echo "file /usr/lib64/libittnotify.so libittnotify.so 755 0 0"  >> itt.filelist
mv -f itt.filelist "${INSTALL_DIR}/itt.filelist"
cp -f "${orig_dir}/libittnotify_collector.so" "${INSTALL_DIR}/libittnotify.so"

echo "itt successfully installed."
echo "Please restart mpss service."
