#
# Copyright (C) 2021 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#


import sys, os
import inspect
import traceback
DISABLE_PRINT = False

def info_p(string):
    if DISABLE_PRINT: return
    caller = inspect.getframeinfo(inspect.stack()[1][0])
    print('[INFO] : {}'.format(str(string).replace('\\nl\\', '\n\t')))

def warning_p(string):
    if DISABLE_PRINT: return
    caller = inspect.getframeinfo(inspect.stack()[1][0])
    print('[WARNING] #{} : {}'.format(caller.lineno,str(string).replace('\\nl\\', '\n\t')))

def error_p(string):
    if DISABLE_PRINT: return
    caller = inspect.getframeinfo(inspect.stack()[1][0])
    print('[ERROR] #{} : {}'.format(caller.lineno,str(string).replace('\\nl\\', '\n\t')))

def exception_p(string):
    if DISABLE_PRINT: return
    caller = inspect.getframeinfo(inspect.stack()[1][0])
    print('[EXCEPTION] #{} : {}\t{}\t{}\n\t{}\n{}\n'.format(caller.lineno,str(sys.exc_info()[0]), os.path.split(sys.exc_info()[2].tb_frame.f_code.co_filename)[1], str(sys.exc_info()[2].tb_lineno ),str(string).replace('\\nl\\', '\n\t'),traceback.format_exc()))

def disablePrint():
    global DISABLE_PRINT
    DISABLE_PRINT = True

def enablePrint():
    global DISABLE_PRINT
    DISABLE_PRINT = False
