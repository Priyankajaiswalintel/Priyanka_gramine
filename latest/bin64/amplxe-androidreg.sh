#!/bin/sh
#
# Copyright (C) 2017 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#

export AMPLXE_INSTALL_DEVICE_PACKAGE=1
BIN_DIR=${0%/*}
"${BIN_DIR}/amplxe-python" "${BIN_DIR}/amplxe-runss.py" $*
ERROR_LEVEL=$?
export AMPLXE_INSTALL_DEVICE_PACKAGE=
exit $ERROR_LEVEL
