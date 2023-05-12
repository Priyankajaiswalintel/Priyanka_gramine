#!/bin/sh
#
# Copyright (C) 2019 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#

VTUNE_SCRIPT_PATH=$(dirname "$0")
VTUNE_SCRIPT_PATH=$(cd "${VTUNE_SCRIPT_PATH}"; pwd -P)

path_to_module="${VTUNE_SCRIPT_PATH}/self_check.py"
path_to_python="${VTUNE_SCRIPT_PATH}/amplxe-python"

"${path_to_python}" "${path_to_module}" "$@"