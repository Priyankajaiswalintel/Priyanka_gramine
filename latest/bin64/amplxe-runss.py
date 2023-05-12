#!/usr/bin/env python
#
# Copyright (C) 2013 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#


import os
import sys
import time
import string
import posixpath

SCRIPT_DIR = os.path.abspath(os.path.dirname(sys.argv[0]))
PRODUCT_PREFIX = os.path.basename(sys.argv[0]).split('-')[0]

if sys.hexversion < 0x02050000:
    sys.stderr.write("Python %d.%d is not supported...\n" %
        (sys.version_info.major, sys.version_info.minor))
    os._exit(2)

if sys.hexversion < 0x02060000:
    _sentinel = object()
    def next(iterable, default=_sentinel):
        try:
            return next(iterable)
        except StopIteration:
            if default is _sentinel:
                raise
            return default

if sys.hexversion < 0x03030000:
    def b(x):
        return x
    def decode(x):
        return x
    def encode(x):
        return x
else:
    import codecs
    def b(x):
        return codecs.latin_1_encode(x)[0]
    def decode(x):
        return x.decode()
    def encode(x):
        return x.encode()

import glob
import re
import shutil
import subprocess
import tempfile
import signal
from optparse import OptionParser, OptionGroup
import logging
import threading
import getpass
import zipfile
import socket

CREATE_NEW_PROCESS_GROUP=0x00000200
DETACHED_PROCESS = 0x00000008

PRODUCT_VERSION='5'
PRODUCT_DIR='android_v5'
PRODUCT_BACK_VERSION='4_1'
PRODUCT_BACK_DIR='android_v5'
PRODUCT_SOFIA_VERSION='3_16'

DEFAULT_PACKAGE_NAME='com.intel.vtune'
DEFAULT_JIT_MODE = 'src'

ENCODING = 'utf8'

def get_product_info_path():
    product_info_file = None
    script_dir = SCRIPT_DIR
    product_info_file_dirs = [
                        os.path.join(script_dir, '..', 'config'),
                        os.path.join(script_dir, '..', '..', 'config'),
                    ]
    for product_info_file_dir in product_info_file_dirs:
        product_info_file_tmp = os.path.join(product_info_file_dir, 'product_info.cfg')
        if os.path.isfile(product_info_file_tmp):
            product_info_file = product_info_file_tmp
            break
    return product_info_file

PRODUCT_INFO_FILE = get_product_info_path()
PACKAGE_NAME=DEFAULT_PACKAGE_NAME
AUTOMATIC_ENABLE_JAVA_PROF=True
SIMPLE_APK_INSTALL=False
TARGET_PACKAGE_PREFIX='vtune_profiler_target'
if PRODUCT_INFO_FILE:
   for line in open(PRODUCT_INFO_FILE, 'r', encoding=ENCODING).readlines():
       if 'defaultTargetInstallPath_adb' in line:
           default_install_dir = line.strip().split("=")[1].replace('"', '')
           PACKAGE_NAME = default_install_dir.replace('/data/data/', '')
       elif 'allowAutomaticEnableJavaProfiling_adb' in line and not 'yes' in line:
           AUTOMATIC_ENABLE_JAVA_PROF=False
       elif 'allowApkInstallationOnly_adb' in line and 'yes' in line:
           SIMPLE_APK_INSTALL=True
       elif 'targetPackagePrefix' in line:
           TARGET_PACKAGE_PREFIX = line.strip().split("=")[1].replace('"', '')

#Ignore SIGINT signal by setting the handler to SIG_IGN
def preexec_signal_function():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def kill(pid):
    if sys.platform == 'win32':
        subprocess.Popen("taskkill /F /T /PID %s" % pid, stdout=subprocess.PIPE)
    else:
        os.kill(pid, signal.SIGTERM)

class ProgressBar:
    def __init__(self, message):
        self.message = message
        self.slash = ["-", "\\", "|", "/"]
        self.state = 0
        sys.stdout.write(message + ' ' + self.slash[self.state])
        sys.stdout.flush()
        self.timer = None

    def start(self):
        self.timer = threading.Timer(1, self._update)
        self.timer.daemon = True
        self.timer.start()

    def stop(self):
        self.timer.cancel()
        sys.stdout.write("\n")

    def _update(self):
        self.state = (self.state + 1) % len(self.slash)
        sys.stdout.write("\b" + self.slash[self.state])
        sys.stdout.flush()
        self.start()

class EmptyProgressBar:
    def __init__(self, message):
        self.empty = None

    def start(self):
        self.empty = None

    def stop(self):
        self.empty = None

    def _update(self):
        self.empty = None

def patchFeedbackLine(line):
    #need to remove feedback and xml to have one session per PRODUCT_PREFIX-runss.py run
    line = line.replace('<?xml version=\"1.0\" encoding=\"UTF-8\"?>', '')
    line = line.replace('<feedback>', '')
    line = line.replace('<feedback/>', '')
    line = line.replace('</feedback>', '')
    line = line.replace('<feedback', '')
    line = line.replace('</feedback', '')
    return line

# This values is taken from collection_state_t enum from msngr.headers component
# and should be always synchronized with it.
CS_STARTED  = 1 # csStarted
CS_STOPPED  = 3 # csStopped
CS_CANCELED = 7 # csCanceled
CS_FAILED   = 8 # csFailed
CS_DETACHED = 9 # csDetached

def collectionStateToStr(state):
    return 'state="%d"' % state

class MessageWriter:
    def __init__(self, xml = False):
        self.xml = xml
        self.delayed_stop = ''

        if self.xml:
            message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            message += "<feedback>"
            self._dump(message)

    def finalize(self):
        message = ''
        if self.xml:
            self._dump(self.delayed_stop)
            self._dump("</feedback>")

    def severitywrite(self, message, severity="error"):
        if not self.xml:
            self._dump(severity.upper() + ": " + message + "\n")
        else:
            message = message.replace('<', '&lt;')
            message = message.replace('>', '&gt;')
            message = message.replace('&', '&amp;')
            message = message.replace('"', '&quot;')
            message = message.replace("'", '&apos;')
            self._dump("<message severity=\""+ severity + "\">%s</message>\n<nop/>" % message.strip())

    def failwrite(self, data):
        if self.xml:
            self._dump('<state_changed %s data="%s"/>' % (collectionStateToStr(CS_FAILED), data))

    def write(self, message):
        if not self.xml:
            self._dump(message)
        else:
            self._dump(message.strip())

    def _dump(self, message):
        sys.stderr.write(message)
        sys.stderr.flush()

#this messenger stores all data inside
class InternalMessenger(MessageWriter):
    def __init__(self, nextMessenger = None):
        self.message = ""
        self.nextMessenger = nextMessenger
        MessageWriter.__init__(self, True)

    def severitywrite(self, message, severity="error"):
        if self.nextMessenger:
            self.nextMessenger.severitywrite(message, severity)
        else:
            MessageWriter.severitywrite(self, message, severity)

    def _dump(self, message):
        self.message += message

class ProductLayout:
    def __init__(self, install_dir, project_dir, tmp_dir):
        self.install_dir = os.environ.get(PRODUCT_PREFIX.upper() + "_TARGET_PRODUCT_DIR", install_dir)
        if self.install_dir[-1] != '/': self.install_dir += '/'

        self.tmp_dir = os.environ.get(PRODUCT_PREFIX.upper() + "_TARGET_TMP_DIR", tmp_dir)
        if self.tmp_dir[-1] != '/': self.tmp_dir += '/'

        self.project_dir = project_dir
        if self.project_dir[-1] != '/': self.project_dir += '/'

        self.lib32_dir = self.install_dir + "lib32/"
        self.bin32_dir = self.install_dir + "bin32/"
        self.bin_dir = self.install_dir + "bin/"
        self.drv_dir   = self.install_dir + "drv/"
        self.lib64_dir = self.install_dir + "lib64/"
        self.bin64_dir = self.install_dir + "bin64/"
        self.prefix = PRODUCT_PREFIX

    def get_bin32_dir(self):
        return self.bin32_dir

    def get_lib32_dir(self):
        return self.lib32_dir

    def get_drv_dir(self):
        return self.drv_dir

    def get_bin64_dir(self):
        return self.bin64_dir

    def get_lib64_dir(self):
        return self.lib64_dir

    def get_tmp_dir(self):
        return self.tmp_dir

    def get_project_dir(self):
        return self.project_dir

    def get_install_dir(self):
        return self.install_dir

    def get_driver_path(self, name):
        return self.drv_dir + name + '.ko'

class LinuxProductLayout(ProductLayout):
    def __init__(self, options):
        install_dir = options.install_dir if options.install_dir else self._get_default_install_dir()
        tmp_dir = options.target_tmp_dir if options.target_tmp_dir else "/tmp/"
        project_dir = tmp_dir + "/" + PRODUCT_PREFIX + "-results-" + options.target.split('@')[0] + "/"
        ProductLayout.__init__(self, install_dir, project_dir, tmp_dir)
        self.user_install_dir = self.install_dir

    def get_sysmodule_pattern(self):
        return re.compile("|".join(["^/bin/", "^/lib/", "^/lib32/", "^/lib64/",
            "^/usr/", "^/sbin/", "^/etc/", "^vmlinux$"]))

    def get_layout_name(self):
        return 'linux'

    def _get_default_install_dir(self):
        default_install_dir = "/opt/intel/vtune_profiler/"
        if PRODUCT_INFO_FILE:
            for line in open(PRODUCT_INFO_FILE, 'r', encoding=ENCODING).readlines():
                if 'defaultTargetInstallPath_ssh' in line:
                    default_install_dir = line.strip().split("=")[1].replace('"', '') + '/'
                    break
        return default_install_dir

    def get_binary_path(self, name):
#       return self.install_dir + 'bin`sh -c \'if [ $(echo $(uname -m)) = x86_64 ]; then echo 64; else echo 32;fi\'`/' + self.prefix + '-' + name
#        return self.install_dir + 'bin$(if [ `uname -m` = x86_64 ] || [ `uname -m` = amd64 ]; then echo 64; else echo 32;fi)/' + self.prefix + '-' + name
#        return '%s$(if [ -f "%s/bin64/%s" ]; then echo /%s;fi)/bin64/%s' % (self.user_install_dir, self.install_dir, self.prefix + '-' + name, TARGET_PACKAGE_DIR, self.prefix + '-' + name)
        return '%sbin64/%s' % (self.user_install_dir, self.prefix + '-' + name)

    def get_binary_path_with_arch(self, name, arch):
        if arch == "x86_64":
            arch = "64"
        else:
            arch = "32"
        return self.install_dir + 'bin' + arch +'/' + self.prefix + '-' + name

    def get_shell_binary_path(self, name):
        return self.get_binary_path(name)


class WindowsProductLayout(ProductLayout):
    def __init__(self, options):
        self.script_dir = SCRIPT_DIR
        install_dir = options.install_dir if options.install_dir else self._get_default_install_dir()
        tmp_dir = options.target_tmp_dir if options.target_tmp_dir else os.getenv("TEMP")
        project_dir = os.path.join(tmp_dir, PRODUCT_PREFIX + "-results-" + options.target.split('@')[0])
        ProductLayout.__init__(self, install_dir, project_dir, tmp_dir)

    def get_layout_name(self):
        return "windows"

    def _get_default_install_dir(self):
        return os.path.normpath(self.script_dir + "/../")

    def get_binary_path(self, name):
        return os.path.normpath(os.path.join(self.script_dir, self.prefix + "-" + name))

    def get_shell_binary_path(self, name):
        return self.get_binary_path(name)

class DockerProductLayout(ProductLayout):
    def __init__(self, options):
        self.copy_dir = "/tmp/intel/"
        install_dir = os.path.join(self.copy_dir, "target")
        tmp_dir = "/tmp/"
        project_dir = "/tmp/agent_result/"

        ProductLayout.__init__(self, install_dir, project_dir, tmp_dir)

    def get_layout_name(self):
        return 'docker'

    def get_copy_dir(self):
        return self.copy_dir

    def get_binary_path(self, arch, name):
        if arch == "x86_64":
            arch = "64"
        else:
            arch = "32"

        return os.path.normpath(os.path.join(self.install_dir, "bin" + arch, self.prefix + "-" + name))

class LxcProductLayout(LinuxProductLayout):
    def __init__(self, options):
        self.copy_dir = "/tmp/intel/"
        install_dir = os.path.join(self.copy_dir, "target/")
        tmp_dir = "/tmp/"
        project_dir = "/tmp/agent_result/"

        ProductLayout.__init__(self, install_dir, project_dir, tmp_dir)

    def get_layout_name(self):
        return 'lxc'

    def get_copy_dir(self):
        return self.copy_dir

    def get_binary_path(self, arch, name):
        if arch == "x86_64":
            arch = "64"
        else:
            arch = "32"

        return os.path.normpath(os.path.join(self.install_dir, "bin" + arch,  self.prefix + "-" + name))


class AndroidProductLayout(ProductLayout):
    def __init__(self, options):

        #direct install/uninstall does not have install_dir
        if not hasattr(options, 'install_dir'):
            options.install_dir=None

        pckg_dir = options.install_dir if options.install_dir else self._get_default_install_dir()
        install_dir = pckg_dir + "/perfrun"
        project_dir = pckg_dir + "/results"
        tmp_dir     = pckg_dir + "/tmp"

        #disable for android external values
        os.environ[PRODUCT_PREFIX.upper() + "_TARGET_PRODUCT_DIR"] = install_dir
        os.environ[PRODUCT_PREFIX.upper() + "_TARGET_TMP_DIR"] = tmp_dir

        ProductLayout.__init__(self, install_dir, project_dir, tmp_dir)

    def get_sysmodule_pattern(self):
        return re.compile("|".join(["^/system/", "^vmlinux$"]))

    def get_layout_name(self):
        return 'android'

    def get_binary_path(self, name):
        return self.bin_dir + self.prefix + '-' + name

    def get_shell_binary_path(self, name):
        return self.bin_dir.replace('/data/data', '/data/local/tmp') + self.prefix + '-' + name

    def _get_default_install_dir(self):
        default_install_dir = "/data/data/" + PACKAGE_NAME
        if PRODUCT_INFO_FILE:
            for line in open(PRODUCT_INFO_FILE, 'r', encoding=ENCODING).readlines():
                if 'defaultTargetInstallPath_adb' in line:
                    default_install_dir = line.strip().split("=")[1].replace('"', '') + '/'
                    break
        return default_install_dir

def which(program): #same as Linux which command - finds full path to given executable
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
        if sys.platform == 'win32' and is_exe(program + ".exe"):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
            if sys.platform == 'win32' and is_exe(exe_file + ".exe"):
                return exe_file
    return None

def default_apk_dirs():
    script_dir = SCRIPT_DIR
    product_specific_path = PACKAGE_NAME.replace(DEFAULT_PACKAGE_NAME + '.', '')
    dirs = []
    for product in ['.', 'vtune20']:
        dirs += [
                script_dir,
                os.path.join(script_dir, '..', 'target', product),
                os.path.join(script_dir, '..', 'target', PRODUCT_DIR, product),
                os.path.join(script_dir, '..', 'target', 'android_arm', product),
                os.path.join(script_dir, '..', 'target', PRODUCT_DIR + '_x86_64', product),
                os.path.join(script_dir, '..', 'target', PRODUCT_DIR, product_specific_path, product)
            ]
    return dirs

#this object is used for parsing options file.
#It allows to rewrite options file with new parameters
class OptionFileParser:
    def __init__(self, path):
        if not(path and os.path.exists(path)):
            os._exit(8)
        self.path = path
        self.options_list = []

        f = open(self.path, 'r', encoding=ENCODING)
        if not f:
            os._exit(8)
        self.values = {}
        self.multilines = []
        last_value = None
        for line in f:
            self.options_list.append(line.strip())
            if line.strip() == "--":
                break

            if last_value and not re.search("^-", line.strip()):
                self.values[last_value] = [line.strip()]
                self.multilines.append(last_value)
                last_value = None
                continue

            one_line = line.strip().split('=')
            last_value = one_line[0].strip()
            if len(one_line) > 1:
                self._append_value(one_line[0].strip(), "=".join(one_line[1:]))
            else:
                self._append_value(one_line[0].strip(), None)

        self.cmdline = [line.strip() for line in f if line.strip()]
        f.close()

    def _append_value(self, key, value):
        if key not in self.values.keys():
            self.values[key] = []

        if value:
            self.values[key].append(value)

    def get_arguments(self):
        return self.cmdline

    def set_arguments(self, args):
        assert(type(args)==type([]))
        self.cmdline = args

    def _get_values_for_key(self, key):
        if key in self.values.keys():
            return self.values[key]
        return None

    def create_new_option_file(self, path=None):
        if not path:
            path = self.path
        shutil.copy(self.path, self.path+"_back")
        f = open(path, "w", encoding=ENCODING)
        if not f:
            os._exit(8)

        for key in self.values.keys():
            if key in self.multilines:
                f.write("%s\n%s\n"%(key, self.values[key][0]))
            else:
                if len(self.values[key]) == 0:
                    f.write("%s\n"%key)
                else:
                    s = ",".join(self.values[key])
                    f.write("%s=%s\n" %(key, s))

        if len(self.cmdline) != 0:
            f.write("--\n")
            for cmd in self.cmdline:
                f.write("%s\n"%cmd)

        f.close()

    def get_all_options_except(self, except_keys=[]):
        ret=[]
        for key in self.values.keys():
            if key in except_keys:
                continue

            if key in self.multilines:
                ret.append(key)
                ret.append(self.values[key][0])
            else:
                if len(self.values[key]) == 0:
                    ret.append(key)
                else:
                    s = ",".join(self.values[key])
                    ret.append[key]
                    ret.append[s]
        return ret

    def is_option_present(self, option_key):
        return option_key in self.options_list

    def get_option_values(self, option_keys, first_only=False):
        ret = []
        if type(option_keys) == type([]):
            for key in option_keys:
                values = self._get_values_for_key(key)
                if values:
                    ret.extend(values)
        else:
            ret = self._get_values_for_key(option_keys)

        if first_only and ret:
            ret = ret[0]
        return ret

    def set_option_value(self, key, value):
        assert(type(value)==type([]))
        self.values[key] = value

    def remove_option_value(self, key):
        if key in self.values.keys():
            self.values.pop(key)

class RemoteShell:
    def __init__(self):
        self.devnull = open(os.devnull, "w")

        #exclude interrupts loops
        self.firstInterrupt = True

        self.productInfo = None

        self.system_arch = None #x86, arm, mips
        
    def is_ready(self):
        return True

    def is_root(self):
        return False

    def get_remote_product_info(self):
        return self.productInfo

    def chmod(self, mode, path):
        return self.call(["chmod", mode, path], silent=True)

    def ps(self, *options):
        return self.get_cmd_output(["ps"] + list(options))

    def rm(self, *options):
        return self.call(["rm"] + list(options), silent=True)

    def cp(self, *options):
        return self.call(["cp"] + list(options), silent=True)

    def mv(self, source, destination):
        cmd = ["mv"] + [source, destination]
        return self.call(cmd, silent=True)

    def ln(self, *options):
        return self.call(["ln"] + list(options), silent=True)

    def ls(self, *options):
        return self.get_cmd_output(["ls"] + list(options))

    def cat(self, *options):
        return self.get_cmd_output(["cat"] + list(options))

    def mkdir(self, directory):
        return self.call(["mkdir", "-p", directory], silent=True)

    def uname(self, *options):
        cmd = ["uname"]
        if list(options):
            cmd += list(options)
        uname_output = self.get_cmd_output(cmd)
        return uname_output[0]

    def call(self, args, silent=False, **kwargs):
        if silent:
            cout, cerr = tempfile.TemporaryFile('w+', encoding=ENCODING), tempfile.TemporaryFile('w+', encoding=ENCODING)
            retcode = self._call_shell(args, stdout=cout, stderr=cerr, **kwargs)
            cout.seek(0)
            cerr.seek(0)
            try:
                logging.debug("call stdout: %s" % cout.read().splitlines())
                logging.debug("call stderr: %s" % cerr.read().splitlines())
            except:
                logging.debug("call stdout/stderr: Output is not encoded")
        else:
            retcode = self._call_shell(args, **kwargs)

        return retcode


    def get_cmd_output(self, args):
        cout, cerr = tempfile.TemporaryFile('w+', encoding=ENCODING), tempfile.TemporaryFile('w+', encoding=ENCODING)
        self._call_shell(args, stdout=cout, stderr=cerr)
        cout.seek(0); logging.debug("get_cmd_output stdout: %s" % cout.read().splitlines())
        cerr.seek(0); logging.debug("get_cmd_output stderr: %s" % cerr.read().splitlines())

        cout.seek(0)
        cerr.seek(0)
        output = cout.read().splitlines() + cerr.read().splitlines()
        return [x.strip() for x in output if x]

    def get_cmd_stdout(self, args):
        cout, cerr = tempfile.TemporaryFile('w+', encoding=ENCODING), tempfile.TemporaryFile('w+', encoding=ENCODING)
        self._call_shell(args, stdout=cout, stderr=cerr)
        cout.seek(0); logging.debug("get_cmd_output stdout: %s" % cout.read().splitlines())
        cerr.seek(0); logging.debug("get_cmd_output stderr: %s" % cerr.read().splitlines())

        cout.seek(0)
        cerr.seek(0)
        output = cout.read().splitlines()
        return [x.strip() for x in output if x]

    def get_shell_name(self):
        return 'unknown'

    def get_default_run_options(self):
        return ''

    def get_default_push_options(self):
        return ''

    #we need to redefine this function for android
    def _call_interrupted_stop(self, stop_cmd, without_logs=False):
        self._call_shell(stop_cmd, without_logs)
        return 0

    def _create_interrupted_thread(self, args, kwargs):
        results = [None]
        child_pids = [None]
        thread = threading.Thread(target = self._call_shell_threaded_function, args = (results, child_pids, args, kwargs))
        thread.start()
        return (thread, results, child_pids)

    def _wait_interrupted_thread(self, thread, results, child_pids, args, kwargs):
        connectionCheck = 0
        while True:
            try:
                if thread.is_alive():
                    thread.join(1)

                    #check that target is reachable
                    # TODO disable that because some regressions on symacs, freebsd
                    if False and self.get_shell_name() not in ['adb', 'local']:
                        connectionCheck += 1
                        if connectionCheck == 10: #once per 10 seconds
                            connectionCheck = 0
                            connectionResults = [None]
                            connectionChildPids = [None]
                            self._call_shell_threaded_function(connectionResults, connectionChildPids, ['id', '>/dev/null', '2>&1'], kwargs)
                            if connectionResults[0] != 0:
                                kill(child_pids[0])
                                return connectionResults[0]
                else:
                    break
            except KeyboardInterrupt:
                if self.firstInterrupt:
                    stop_cmd = []
                    try:
                        for arg in args:
                            if "--result-dir" == arg:
                                stop_cmd += ["--command", "stop"]
                            elif "--result-dir" in arg:
                                arg = arg.replace("--result-dir", "--command stop --result-dir")
                            stop_cmd.append(arg)

                        self.firstInterrupt = False
                    except:
                        return 1
                    if len(stop_cmd) > 0:
                        self.options.messenger.severitywrite("CTRL-C signal is received.", "info")
                        if self._call_interrupted_stop(stop_cmd, without_logs=False) != 0:
                            return 1

        return results[0]

    def _check_interrupted_thread(self, thread, results, child_pids, args, kwargs):
        return thread.is_alive()

    def _run_interrupted_thread(self, args, kwargs):
        thread, results, child_pids = self._create_interrupted_thread(args, kwargs)
        return self._wait_interrupted_thread(thread, results, child_pids, args, kwargs)

    def get_platform(self):
        return "unknown"

    def is_selinux(self):
        return False

    def get_host_product_build_number(self):
        host_version = -1
        support_file = None
        script_dir = SCRIPT_DIR
        support_file_dirs = [
                            os.path.join(script_dir, '..'),
                            os.path.join(script_dir, '..', '..'),
                        ]
        for support_file_dir in support_file_dirs:
            support_file_tmp = os.path.join(support_file_dir, 'support.txt')
            if os.path.isfile(support_file_tmp):
                support_file = support_file_tmp
                break
        if support_file != None:
            for line in open(support_file, 'r', encoding=ENCODING).readlines():
                m = re.match(".*Build\s+Number:\s+(?P<version>\d+)", line.strip())
                if m:
                    host_version = int(m.group('version'))
                    break
        else:
            # For debug purposes
            return 0
        return host_version

    def get_target_product_build_number(self, product_info):
        target_version = ''
        m = re.match(".*build\s+(?P<version>\d+)", " ".join(product_info.splitlines()))
        if m:
            target_version = int(m.group('version'))
            return target_version
        return -1

    def _check_product_version(self, product_info):
        host_version = self.get_host_product_build_number()
        target_version = self.get_target_product_build_number(product_info)
        if host_version == 0:
            return True
        if host_version == -1 or target_version == -1:
            return False
        if host_version != target_version:
            return False
        return True

    def check_NDA(self, product_info):
        # This call is aplicable for android layout only!
        # Get NDA host product status
        vtune_pkg_name=PACKAGE_NAME
        host_has_nda = False
        nda_apk_ext = '.nda.apk'
        if not self.get_arch() in [None, 'x86']:
            nda_apk_ext = '.nda.%s.apk' % self.get_arch()

        for apk_file_dir in default_apk_dirs():
            nda_apk_file = os.path.join(apk_file_dir, vtune_pkg_name + nda_apk_ext)
            if os.path.isfile(nda_apk_file):
                host_has_nda = True
                break

        # Get NDA target product version
        target_has_nda = False
        if 'NDA' in product_info:
            target_has_nda = True

        # Compare NDA statuses
        if target_has_nda != host_has_nda:
            return False
        return True

    def check_product_info(self, product_info, check_NDA = False):
        if self._check_product_version(product_info) and \
            (not check_NDA or self.check_NDA(product_info)):
            return True
        else:
            return False

    def get_arch(self):
        if self.system_arch is None:
            uname_output = self.uname('-m')
            if 'amd64' in uname_output or 'x86_64' in uname_output:
                self.system_arch = 'x86_64'
            else:
                self.system_arch = 'x86'
        return self.system_arch


class SSH(RemoteShell):
    def __init__(self, options):
        RemoteShell.__init__(self)

        #arguments to enable non-default port
        self.ssh_port_args = []
        self.scp_port_args = []
        target = options.target.split(':')
        if len(target) > 1:
            self.ssh_port_args = ["-p", target[1]]
            self.scp_port_args = ["-P", target[1]]

        options.target = self.machine = target[0]
        self.options = options
        self.ssh_keys = SshKeys(self.machine)
        
    def get_shell_name(self):
        return 'ssh'

    def get_default_run_options(self):
        private_key = []
        if os.path.isfile(self.ssh_keys.private_key_path()):
            private_key = ["-i", self.ssh_keys.private_key_path()]
        return " ".join(private_key + ["-o", "BatchMode=yes", "-o", "ServerAliveInterval=5", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", self.machine] + self.ssh_port_args)

    def get_default_push_options(self):
        private_key = []
        if os.path.isfile(self.ssh_keys.private_key_path()):
            private_key = ["-i", self.ssh_keys.private_key_path()]
        return " ".join(["scp", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-BC"] + private_key + self.scp_port_args)

    def get_machine(self):
        return self.machine

    def get_port(self):
        if len(self.ssh_port_args) > 1:
            return self.ssh_port_args[1]
        return 'default'

    def pull(self, src, dest, is_module = False):
        machine_src = self.machine + ":" + src
        retcode = self._call_scp([machine_src, dest])
        if not(is_module) and retcode != 0 and not os.path.isfile(dest):
            retcode = self._call_scp(["-r", machine_src + "/*", dest])
        return retcode

    def rpull(self, src, dest):
        machine_src = self.machine + ":" + src
        return self._call_scp(["-r", machine_src + "/*", dest])

    def push(self, src, dest):
        machine_dest = self.machine + ":" + dest
        retcode =  self._call_scp(["-r", src, machine_dest])
        return retcode

    def serialno(self):
        hostname_output = self.get_cmd_output(["hostname"])
        return hostname_output[0]

    def _call_scp(self, args):
        logging.info("call scp %s", args)

        cout, cerr = tempfile.TemporaryFile('w+', encoding=ENCODING), tempfile.TemporaryFile('w+', encoding=ENCODING)

        default_args = self.get_default_push_options().split()
        retcode = subprocess.call(default_args + args, stdout=cout, stderr=cerr, universal_newlines=True)
        cout.seek(0); logging.debug("_call_scp stdout: %s" % cout.read().splitlines())
        cerr.seek(0); logging.debug("_call_scp stderr: %s" % cerr.read().splitlines())

        return retcode

    def _call_shell_threaded_function(self, results, child_pids, args, kwargs):
        def reader(stdout):
            try:
                line = stdout.readline()
                while line:
                    print(line.strip())
                    line = stdout.readline()
            except:
                pass

        default_args = self.get_default_run_options().split()

        if self.options.log_name and sys.platform == 'win32':
            tmp_sshlog = sshlog = self.options.log_name + 'ssh.log'
            index = 0
            while os.path.isfile(tmp_sshlog):
                tmp_sshlog = sshlog + str(index)
                index += 1
            default_args = ["-E", tmp_sshlog] + default_args

        if 'stdout' in kwargs.keys() or 'stderr' in kwargs.keys():
            process = subprocess.Popen(["ssh"] + default_args + args, **kwargs)
            stdout, stderr = process.communicate()
            child_pids[0] = process.pid
        else:
            # windows sys.stdout loose output
            if sys.platform == 'win32':
                process = subprocess.Popen(["ssh"] + default_args + args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    **kwargs)
                thread = threading.Thread(target=reader, args=[process.stdout])
                thread.daemon = True
                thread.start()
            else:
                process = subprocess.Popen(["ssh"] + default_args + args,
                    stderr=subprocess.PIPE,
                    **kwargs)

            child_pids[0] = process.pid

            line = process.stderr.readline()
            product_info = ""
            product_info_lines = False
            incorrect_product_version = False
            app_work_dir_issue = False

            delayed_errors = []
            while line:
                skip = False
                if "/_pvi_" in line.strip():
                    product_info_lines = False
                    line = process.stderr.readline()

                    if not self.check_product_info(product_info):
                        incorrect_product_version = True
                        break
                elif "_pvi_" in line.strip():
                    product_info_lines = True
                    line = process.stderr.readline()
                if product_info_lines:
                    product_info += line
                else:
                    line = patchFeedbackLine(line)

                    split_line = line.lower().split()
                    if 'segmentation' in split_line or 'aborted' in split_line or 'error:' in split_line or "cannot create directory" in line \
                       or 'osi_DLL_Error' in line or 'Unable to open shared library' in line or PRODUCT_PREFIX.upper() + '_TPSSCOLLECTOR:' in line \
                       or 'Assertion failed:' in line:
                        if not 'message severity' in line and not 'event name' in line and not 'modifier name' in line and not 'Network error' in line:
                            skip = True

                    #app-working-dir support
                    if self.options.app_work_dir:
                        for err in ['No such file or directory', 'Permission denied', 'can\'t cd to']:
                            if 'cd: ' + self.options.app_work_dir + ': ' + err in line or \
                                (self.options.app_work_dir.startswith('~/') and 'cd:' in line and self.options.app_work_dir[2:] in line and err in line) or \
                                'cd: ' + err + ' ' + self.options.app_work_dir in line:
                                line = 'Working directory ' + self.options.app_work_dir + ' is invalid: ' + err
                                skip = True
                                app_work_dir_issue = True

                    if skip:
                        if 'state_changed' in line:
                            self.options.messenger.write(line)
                        line = ''.join(e for e in line if e in string.printable)
                        delayed_errors.append(line)
                    else:
                        self.options.messenger.write(line)

                    # kill ssh session in case it did not stop itself
                    # example, could not kill all childs of profiled application
                    # in this case we hang on closing ssh pipes for stdout/stderr
                    # which were inhereted to all childs
                    if self.options.run and \
                        (collectionStateToStr(CS_STOPPED) in line \
                        or collectionStateToStr(CS_CANCELED) in line):
                        for i in range(10): # waiting for process 5 secs
                            if process.poll() is not None:
                                break
                            time.sleep(0.5)

                        if process.poll() is None:
                            if collectionStateToStr(CS_CANCELED) in line:
                                results[0] = 1
                            else:
                                results[0] = 0
                            kill(process.pid)
                            return

                line = process.stderr.readline()

            process.communicate()
            if product_info != "":
                self.productInfo = product_info

            for line in delayed_errors:
                self.options.messenger.severitywrite("target - %s" % line, "error")

            if incorrect_product_version or app_work_dir_issue:
                results[0] = 1
                return

        results[0] = process.poll()

    def _call_shell(self, args, without_logs=False, **kwargs):
        if not without_logs:
            logging.info("call ssh %s", args)

        #disable ctrl+c for child processes
        if sys.platform == 'win32':
            kwargs.update(creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS)
        else:
            kwargs.update(preexec_fn = preexec_signal_function)

        if sys.hexversion >= 0x03000000:
            # enable handling of stdout and stderr as text streams instead of bytes
            kwargs.update(universal_newlines=True)

        return self._run_interrupted_thread(args, kwargs)

class ADB(RemoteShell):
    def __init__(self, options, status_dir = "/data/data/" + PACKAGE_NAME, bridge = 'adb'):
        RemoteShell.__init__(self)

        if (not options.adb_path is None) and (bridge == 'adb'):
            self.bridge = options.adb_path
        else:
            self.bridge = bridge
        self.options = options
        self.uid = None
        self.status_dir = status_dir
        self.bridge_type = bridge
        self.serial_no = None
        self.board_platform = None
        self.selinux = True

        try:
            #start daemon if it is not exist
            subprocess.Popen([self.bridge, "start-server"], stdout=open(os.devnull, 'w')).communicate()
        except:
            pass

        #support of jit in dalvik
        self.libdvm_jitvtune_enabled = False
        self.jitvtune_enabled = False
        self.libdvm_prop = ''
        self.is_art = False
        self.set_vm_prop_enabled = False

        self.allow_automatic_rooting = None

    def get_shell_name(self):
        return 'adb'
 
    def get_default_run_options(self):
        return 'shell'

    def is_ready(self):
        self.is_root()
        if self.uid != None:
            return True
        try:
            tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
            retcode = self._call_adb(['shell', 'id'], stdout=tmp_log,
                stderr=tmp_log)
            tmp_log.seek(0)
            output = " ".join([x.strip() for x in tmp_log.readlines() if x])
            if retcode != 0:
                target = 'Android device'
                serial = os.getenv('ANDROID_SERIAL', '')
                if serial:
                    target += ' ' + serial
                error_message = "Cannot communicate with the %s." % target
                error_message += "(" + re.sub('error: ', self.bridge_type + ' - ', output) + ")\n"

                self.options.messenger.severitywrite(error_message)
                return False
            m = re.match("uid=(\d+)", output)
            if m:
                self.uid = int(m.group(0).replace("uid=", ''))
                return True
            else:
                return False
        except:
            return False

    def check_selinux(self, output, selinux_idx, ro_debuggable_idx):
        #set permissive
        try:
            if output[selinux_idx] == 'Enforcing' and output[ro_debuggable_idx] == '1':
                tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
                self._call_adb( [
                                 'shell', 'setenforce', '0', ';',
                                 'su', '-c', 'setenforce', '0', ';',
                                 'getenforce'';',
                             ], stdout=tmp_log, stderr=tmp_log)
                tmp_log.seek(0)
                enforce_output = [x.strip() for x in tmp_log.readlines() if x]
                if len(enforce_output) > 0:
                    self.selinux = enforce_output[-1].strip()
            else:
                self.selinux = output[selinux_idx]
            if self.selinux != 'Enforcing':
                self.selinux = False
            else:
                self.selinux = True
        except:
            self.selinux = True

    def is_root(self):
        if self.uid != None:
            return self.uid == 0
        try:
            tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)

            ro_product_cpu_abi_idx = 1
            ro_debuggable_idx = 2
            ro_serialno_idx = 3
            ro_board_platform_idx = 4
            selinux_idx = 5
            dalvik_vm_extra_opts_idx = 6
            retcode = self._call_adb( [
                                          'shell', 'id', ';',
                                          'getprop', 'ro.product.cpu.abi', ';',
                                          'getprop', 'ro.debuggable', ';',
                                          'getprop', 'ro.serialno', ';',
                                          'getprop', 'ro.board.platform', ';',
                                          'getenforce', ';',
                                          'getprop','dalvik.vm.extra-opts', ';',
                                          'dalvikvm', '-get', 'Help', ';',
                                          'getprop','persist.sys.dalvik.vm.lib', ';',
                                          'getprop','persist.sys.dalvik.vm.lib.2', ';',
                                      ], stdout=tmp_log, stderr=tmp_log)
            tmp_log.seek(0)
            output = [x.strip() for x in tmp_log.readlines() if x]

            try:
                if 'armeabi' in output[ro_product_cpu_abi_idx]:
                    self.system_arch = 'arm'
                elif 'arm64' in output[ro_product_cpu_abi_idx]:
                    self.system_arch = 'arm64'
                elif 'x86_64' in output[ro_product_cpu_abi_idx]:
                    self.system_arch = 'x86_64'
                elif 'x86' in output[ro_product_cpu_abi_idx]:
                    self.system_arch = 'x86'
                elif '' == output[ro_product_cpu_abi_idx]:
                    self.system_arch = 'indeterminate'
                else:
                    self.system_arch = None
            except:
                self.system_arch = None

            try:
                self.serial_no = output[ro_serialno_idx]
            except:
                self.serial_no = None

            try:
                self.board_platform = output[ro_board_platform_idx]
            except:
                self.board_platform = None

            if len(output) > 1 and 'uid=0' in output[0]:
                self.uid = 0
                #check jitvtune support
                self.jit_vtune_support_check(output)
                self.check_selinux(output, selinux_idx, ro_debuggable_idx)
                return True
            else:
                if 'error:' in " ".join(output):
                    return False
                else:
                    #check if "adb root" is allowed
                    if output[ro_debuggable_idx] == '1':
                        if self._allow_automatic_restart_adb_with_root():
                            self.options.messenger.severitywrite(message = "Restarting the adbd daemon with root permissions.", severity = "info")
                            root_cmd = ['root']
                            if self.bridge_type == 'tizen':
                                root_cmd += ['on']
                            self._call_adb(root_cmd, stdout=tmp_log,
                                stderr=tmp_log)

                        tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
                        self._call_adb(['wait-for-device', 'shell', 'id'], stdout=tmp_log,
                            stderr=tmp_log)
                        tmp_log.seek(0)
                        uid_output = [x.strip() for x in tmp_log.readlines() if x]
                        m = re.match("uid=(\d+)", " ".join(uid_output))
                        if m:
                            self.uid = int(m.group(0).replace("uid=", ''))
                        if self.uid == 0:
                            #check jitvtune support
                            self.jit_vtune_support_check(output)
                        self.check_selinux(output, selinux_idx, ro_debuggable_idx)
                        return self.uid == 0
                    else:
                        self.check_selinux(output, selinux_idx, ro_debuggable_idx)
                        self.uid = 1
                        return False
        except:
            return False

    def _allow_automatic_restart_adb_with_root(self):
        if self.allow_automatic_rooting == None:
            if PRODUCT_INFO_FILE:
                for line in open(PRODUCT_INFO_FILE, 'r', encoding=ENCODING).readlines():
                    if 'allowAutomaticRooting_adb' in line:
                        value = line.strip().split("=")[1].replace('"', '')
                        if value.lower() in ['true', 't', 'yes', 'y', '1']:
                            self.allow_automatic_rooting = True
                        else:
                            self.allow_automatic_rooting = False
                        break
                if self.allow_automatic_rooting == None:
                    self.allow_automatic_rooting = True
            else:
                self.allow_automatic_rooting = True
        return self.allow_automatic_rooting

    def jit_vtune_support_check(self, output):
        self.jitvtune_enabled = False
        self.libdvm_jitvtune_enabled = False

        dalvik_vm_extra_opts_idx = 6
        if not 'libart.so' in " ".join(output):
            self.libdvm_prop = ''
            try:
                if 'jitvtune' in output[dalvik_vm_extra_opts_idx]:
                    self.jitvtune_enabled = True

                self.libdvm_prop = output[dalvik_vm_extra_opts_idx].strip()

                if 'jitvtune' in " ".join(output[dalvik_vm_extra_opts_idx + 1:]):
                    self.libdvm_jitvtune_enabled = True
            except:
                pass
        else:
            self.is_art = True

    def set_vm_prop(self, force_enable_mode = False):
        #for example, gpa doesn't need dynamic code symbols info
        if not AUTOMATIC_ENABLE_JAVA_PROF:
            return False

        if self.is_art or self.set_vm_prop_enabled:
            return False

        #disable recursive calls
        self.set_vm_prop_enabled = True

        if not force_enable_mode:
            if not self.options.target_pid and not self.options.target_process and not self.options.launch:
                #system wide and native collections don't support jit resolving
                return False

        if not self.is_root():
            if self.options.mrte_mode != "native":
                if self.libdvm_jitvtune_enabled:
                    msg = "%s should be rooted to enable Java code profiling." % self.serial_no
                    self.options.messenger.severitywrite(msg, severity="warning")
                else:
                    msg = "Java code profiling is only available on the devices supported with the Intel Mobile Development Kit for Android. "
                    msg += "For more information, go to http://software.intel.com/mdk."
                    self.options.messenger.severitywrite(msg, severity="warning")
            return False

        #rooted device without libdvm vtune jit support
        if not self.libdvm_jitvtune_enabled and self.options.mrte_mode != "native":
            msg = "Java code profiling is only available on the devices supported with the Intel Mobile Development Kit for Android. "
            msg += "For more information, go to http://software.intel.com/mdk."
            self.options.messenger.severitywrite(msg, severity="warning")
            return False

        if self.libdvm_jitvtune_enabled:
            need_to_enable_jit = None
            if not self.jitvtune_enabled and self.options.mrte_mode != "native":
                need_to_enable_jit = True
                status = "enable"
            elif self.jitvtune_enabled and self.options.mrte_mode == "native":
                need_to_enable_jit = False
                status = "disable"

            if force_enable_mode:
                need_to_enable_jit = True
                status = "enable"

            if need_to_enable_jit == None:
                return False

            #don't patch if attach to native process
            if not force_enable_mode and not self.options.launch:
                if self.options.target_process:
                    package_name = self.options.target_process
                else:
                    package_name = self.cat("/proc/" + str(self.options.target_pid) + "/cmdline")
                    package_name = str(package_name[0]).split('\x00')[0]

                if ("".join(self.get_cmd_output(["pm", "path", package_name]))).strip() == '':
                    return False

            msg = "Please wait while Java services are restarted to %s Java code profiling." % status
            self.options.messenger.severitywrite(msg, severity="info")

            restart_cmd = ['stop', ';', 'start', ';']

            setprop_cmd = []
            for mode in ["jit", "src", "dex", "none"]:
                self.libdvm_prop = self.libdvm_prop.replace('-Xjitvtuneinfo:' + mode, '')
            if need_to_enable_jit:
                jit_mode = None
                try:
                    jit_mode = self.options.jitvtuneinfo
                except:
                    pass

                if not jit_mode:
                    local_prop = " ".join(self.get_cmd_output(["cat", "/data/local.prop"]))
                    if re.match("dalvik.vm.extra-opts", local_prop):
                        jitinfo = re.search("-Xjitvtuneinfo:(\w+)", local_prop)
                        if jitinfo:
                            jit_mode = jitinfo.group(1)
                if not jit_mode:
                    jit_mode = DEFAULT_JIT_MODE
                self.options.jitvtuneinfo = jit_mode
                setprop_cmd = [ 'setprop', 'dalvik.vm.extra-opts', (self.libdvm_prop + ' -Xjitvtuneinfo:' + jit_mode).strip(), ';' ]
            else:
                setprop_cmd = [ 'setprop', 'dalvik.vm.extra-opts', self.libdvm_prop.strip(), ';' ]

            clean_jit_cmd = ['rm','-rf', '/data/amplxe/results/*.jit', ';']

            if len(setprop_cmd + restart_cmd + clean_jit_cmd):
                tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
                retcode = self._call_adb( ['shell'] + clean_jit_cmd + setprop_cmd + restart_cmd,
                                          stdout=tmp_log, stderr=tmp_log)
                tmp_log.seek(0)

            if len(restart_cmd):
                tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
                retcode = self._call_adb( ['wait-for-device', 'shell', 'id'],
                                          stdout=tmp_log, stderr=tmp_log)
                tmp_log.seek(0)

                #waiting for zygote run
                for i in range(20): # waiting for zygote startup = 10 secs
                    for line in self.ps():
                        if "zygote" == line.split()[-1]:
                            break
                    time.sleep(0.5)

            self.jitvtune_enabled = need_to_enable_jit

            msg = "To %s Java code profiling, Java services were restarted" % status

            if not force_enable_mode:
                if self.options.launch:
                    msg += '.'
                    self.options.messenger.severitywrite(msg, severity="warning")
                else:
                    msg += " and your application was terminated. Please re-launch the application and start a new collection."
                    self.options.messenger.severitywrite(msg, severity="error")
                    self.options.messenger.failwrite(1)
                    os._exit(1)

            return True
        return False

    def get_devices(self, xml):
        logging.debug("call adb devices")
        process = subprocess.Popen([self.bridge, "devices"], stdout=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        retcode = process.poll()

        adbOutput = stdout.splitlines()
        if retcode or "List of devices attached" not in "".join(adbOutput):
            msg = self.bridge + " returned wrongly formatted output for the devices list attached to the system."
            self.options.messenger.severitywrite(msg)
            self.options.messenger.failwrite(1)
            os._exit(1)

        lt =  ''
        gt = '\n'
        if xml:
            lt = "&lt;device&gt;"
            gt = "&lt;/device&gt;\n"
            self.options.messenger.write("\n<data>&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;\n&lt;bag&gt;\n")

        listPoint = False
        for adbLine in adbOutput:
            adbLine = adbLine.strip()
            if listPoint and adbLine:
                self.options.messenger.write(lt + adbLine.split()[0] + gt)
            if not listPoint and 'List of devices attached' in adbLine:
                listPoint = True
        if xml:
            self.options.messenger.write("&lt;/bag&gt;\n</data>\n<nop/>\n")

    def install(self, apk):
        tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
        retcode = self._call_adb(["install", "-r", apk], stdout=tmp_log,
            stderr=tmp_log)

        tmp_log.seek(0)
        for line in tmp_log.readlines():
            if 'Fail' in line.strip():
                sys.stdout.write("\nCannot install apk file - %s\n" % line.strip())
                sys.stdout.write("Check '%s install %s' command\n" % (self.bridge_type, apk))
                os._exit(1)
            logging.debug(line.strip())
        return retcode

    def uninstall(self, package):
        tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
        retcode = self._call_adb(["shell", "pm", "uninstall", package], stdout=tmp_log,
            stderr=tmp_log)

        tmp_log.seek(0)
        for line in tmp_log.readlines():
            logging.debug(line)

        tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
        retcode = self._call_adb(["uninstall", package], stdout=tmp_log,
            stderr=tmp_log)

        tmp_log.seek(0)
        for line in tmp_log.readlines():
            logging.debug(line)
        return retcode

    def am_start(self, activity):
        tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
        retcode = self._call_adb(["shell", "am", "start", "-W", "-n", activity], stdout=tmp_log,
            stderr=tmp_log)

        tmp_log.seek(0)
        for line in tmp_log.readlines():
            if 'Status: timeout' in line:
                logging.debug(line)
                logging.debug("10 secs sleep")
                time.sleep(10)
            else:
                logging.debug(line)
        return retcode

    def am_force_stop(self, package):
        tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
        retcode = self._call_adb(["shell", "am", "force-stop", package], stdout=tmp_log,
            stderr=tmp_log)

        tmp_log.seek(0)
        for line in tmp_log.readlines():
            logging.debug(line.strip())
        return retcode

    def pull(self, src, dest, is_module = False):
        retcode = self._call_adb(["pull", src, dest], stdout=self.devnull,
            stderr=self.devnull)
        return retcode

    def rpull(self, src, dest):
        return self.pull(src, dest)

    def push(self, src, dest):
        src_list = []
        ret = 0
        if os.path.isdir(src) and self.version() > [1, 0, 34]:
            for src_target in os.listdir(src):
                src_list += [os.path.join(src, src_target)]
        else:
            src_list += [src]

        for src_target in src_list:
            tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
            retcode = self._call_adb(["push", src_target, dest], stdout=tmp_log,
                stderr=tmp_log)

            tmp_log.seek(0)
            for line in tmp_log.readlines():
                logging.debug(line)
            if retcode != 0:
                ret = retcode
        return ret

    def serialno(self):
        logging.debug("call " + self.bridge + " get-serialno")
        command = [self.bridge, "get-serialno"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        retcode = process.poll()
        if retcode:
            raise subprocess.CalledProcessError(retcode, command)
        return stdout.strip()

    def version(self):
        logging.debug("call " + self.bridge + " version")
        command = [self.bridge, "version"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        retcode = process.poll()
        if retcode:
            raise subprocess.CalledProcessError(retcode, command)

        m = re.match(".*version\s+(?P<version>\d+\.\d+\.\d+)", stdout.strip())
        if m:
            return [int(i) for i in m.group('version').split('.')]

        return [1, 0, 0]

    def get_platform(self):
        return self.board_platform

    def is_selinux(self):
        return self.selinux

    def is_otc(self):
        if 'No such file or directory' in str(self.ls('/system/lib/modules')):
            return False
        return True

    def get_jdwp_port_list(self):
        #on some devices 'adb jdwp' cmd hangs, so need to have timelimit
        class Jdwp():
            def __init__(self, bridge):
                self.process = None
                self.timeout = 5
                self.jdwp_out = tempfile.TemporaryFile('w+', encoding=ENCODING)
                self.bridge = bridge

            def kill(self, pid):
                if sys.platform == 'win32':
                    subprocess.Popen("taskkill /F /T /PID %s" % pid, stdout=subprocess.PIPE)
                else:
                    # killed childs
                    subprocess.run(["pkill", "-09", "-P", str(pid)])
                    # killed pid
                    os.kill(pid, signal.SIGTERM)

            def call(self):
                def target():
                    self.process = subprocess.Popen([self.bridge, "jdwp"], stdout=self.jdwp_out,
                        universal_newlines=True)
                    self.process.communicate()

                thread = threading.Thread(target=target)
                thread.start()

                thread.join(self.timeout)

                self.jdwp_out.seek(0)
                output = self.jdwp_out.read()

                if thread.is_alive():
                    self.kill(self.process.pid)
                    thread.join()
                    self.process.wait()

#                self.jdwp_out.seek(0)
#                output = self.jdwp_out.read()
                self.jdwp_out.close()
                return output

        try:
            return [int(x.strip()) for x in Jdwp(self.bridge).call().split() if x]
        except:
            return []

    def _call_shell(self, args, **kwargs):
        is_root = self.is_root()

        runss_mode = False
        if 'runss.sh' in " ".join(args):
            runss_mode = True

        errorfile = '/data/' + PRODUCT_PREFIX + '-errorlevel'
        stdoutfile= '/data/' + PRODUCT_PREFIX + '-stdout'
        if not is_root or self.bridge_type == 'tizen':
            errorfile = self.status_dir + '/' + PRODUCT_PREFIX + '-errorlevel'
            stdoutfile =  self.status_dir + '/' + PRODUCT_PREFIX + '-stdout'

        errorlevelcmd = ['echo', '$?','>', errorfile]
        if len(args) and args[len(args) - 1] != ';':
            errorlevelcmd = [';'] + errorlevelcmd

        run_as = []
        if runss_mode:
            args += ['>', stdoutfile]
        if self._call_adb(["shell"] + run_as + args + errorlevelcmd,  **kwargs):
            return 1

        #get return code
        process = subprocess.Popen([self.bridge, 'shell'] + run_as + ['cat', errorfile], stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        retcode = process.poll()
        if retcode:
            self.options.messenger.severitywrite("Connection was lost.\n")
            self.options.messenger.failwrite(1)
            os._exit(1)
        logging.info("call adb return code %s", stdout.strip())

        if runss_mode:
            process = subprocess.Popen([self.bridge, 'shell', 'cat', stdoutfile], **kwargs)
            process.communicate()
            retcode = process.poll()
        try:
            ret_code = int(stdout.strip())
        except:
            if self.options.package_command != None:
                return 0
            #that means that file is absent and product is not instlled or old
            msg = "Cannot find product on the device. Enabling automatic installation..."
            self.options.messenger.severitywrite(msg, "info")
            logging.info(msg)
            prev_package_command = self.options.package_command
            self.options.package_command = 'install'
            installer = AndroidPackageInstaller(self.options)
            installer.clean()
            installer.install()
            ret = self._call_shell(args, **kwargs)
            self.options.package_command = prev_package_command
            return ret
        return ret_code

    def _emulate_jdb(self):
        # emulate JDB: attach and continue suspended application
        # jdb -attach localhost:6666
        try:
            import socket
        except:
            self.options.messenger.severitywrite("Unable to load socket module.")
            self.options.messenger.failwrite(1)
            os._exit(1)
        host = "localhost"
        port = self.options.jdb_port
        socketJDB = None
        try:
            socketJDB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socketJDB.connect((host, port))
        except socket.error as excep:
            if socketJDB:
                socketJDB.close()
            self.options.messenger.severitywrite("Cannot open socket for JDB debugger.\n" + excep)
            self.options.messenger.failwrite(1)
            return 1
        # send handshake
        # extracted from jdb debugger
        handshakeMessage = b"JDWP-Handshake"
        sent = socketJDB.send(handshakeMessage)
        if sent == 0:
            self.options.messenger.severitywrite("Unable to send handshake message to Dalvik.")
            self.options.messenger.failwrite(1)
            return 1
        # recieve handshake from Dalvik
        buff = socketJDB.recv(len(handshakeMessage), socket.MSG_WAITALL)
        if buff != handshakeMessage:
            self.options.messenger.severitywrite("Wrong handshake message from Dalvik: %s\nSuggestion: Close all other Android debugger/profiler/ADT (Eclipse IDE) and try again." % buff)
            self.options.messenger.failwrite(1)
            return 1
        # sent continue to dalvik (magic number, extracted from jdb debugger)
        magicMessage = b"\0\0\0\v\0\0\0\1\0\1\7"
        sent = socketJDB.send(magicMessage)
        if sent != len(magicMessage):
            self.options.messenger.severitywrite("Unable to send continue command to Dalvik.")
            self.options.messenger.failwrite(1)
            return 1
        # recieve answer from dalvik debugger - 31 byte message (extracted from jdb debugger)
        buff = socketJDB.recv(31, socket.MSG_WAITALL)
        if len(buff) != 31:
            self.options.messenger.severitywrite("Wrong respond message len: %d from Dalvik, on continue command." % len(buff))
            self.options.messenger.failwrite(1)
            return 1
        time.sleep(1) # to setup JDB connection (as in ndk-gdb script)
        return 0

    def _call_shell_threaded_function(self, results, child_pids, args, kwargs):

        if 'stdout' in kwargs.keys() or 'stderr' in kwargs.keys():
            process = subprocess.Popen([self.bridge] + args, **kwargs)
            stdout, stderr = process.communicate()
            child_pids[0] = process.pid
        else:
            process = subprocess.Popen([self.bridge] + args,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                **kwargs)
            child_pids[0] = process.pid
            line = process.stdout.readline()
            product_info = ""
            product_info_lines = False
            incorrect_product_version = False
            app_work_dir_issue = False

            delayed_errors = []
            while line:
                skip = False
                if "/_pvi_" in line.strip():
                    product_info_lines = False
                    line = process.stdout.readline()
                    if not self.check_product_info(product_info, True):
                        incorrect_product_version = True
                        break
                elif "_pvi_" in line.strip():
                    product_info_lines = True
                    line = process.stdout.readline()
                if product_info_lines:
                    product_info += line
                else:
                    line = patchFeedbackLine(line)

                    split_line = line.lower().split()
                    if 'segmentation' in split_line or 'aborted' in split_line or 'error:' in split_line or "cannot create directory" in line \
                       or 'osi_DLL_Error' in line or 'Unable to open shared library' in line or PRODUCT_PREFIX.upper() + '_TPSSCOLLECTOR:' in line \
                       or 'Assertion failed:' in line:
                        if not 'message severity' in line and not 'event name' in line and not 'modifier name' in line and not 'Network error' in line:
                            skip = True

                    #app-working-dir support
                    if self.options.app_work_dir:
                        for err in ['No such file or directory', 'Permission denied', 'can\'t cd to']:
                            if 'cd: ' + self.options.app_work_dir + ': ' + err in line or \
                                (self.options.app_work_dir.startswith('~/') and 'cd:' in line and self.options.app_work_dir[2:] in line and err in line) or \
                                'cd: ' + err + ' ' + self.options.app_work_dir in line:
                                line = 'Working directory ' + self.options.app_work_dir + ' is invalid: ' + err
                                skip = True
                                app_work_dir_issue = True

                    if self.options.launch and ('Collection started' in line or collectionStateToStr(CS_STARTED) in line):
                        results[0] = self._emulate_jdb()
                        if results[0]:
                            os.kill(process.pid, signal.SIGTERM)
                            return

                    if skip:
                        if 'state_changed' in line:
                            self.options.messenger.write(line)
                        line = ''.join(e for e in line if e in string.printable)
                        delayed_errors.append(line)
                    else:
                        self.options.messenger.write(line)

                line = process.stdout.readline()
            process.communicate()

            if product_info != "":
                self.productInfo = product_info

            for line in delayed_errors:
                self.options.messenger.severitywrite("target - %s" % line, "error")

            if incorrect_product_version or app_work_dir_issue:
                results[0] = 1
                return

        results[0] = process.poll()

    def _call_interrupted_stop(self, stop_cmd, without_logs=False):
        self._call_adb(stop_cmd, without_logs)
        return 0

    def _call_adb(self, args, without_logs=False, **kwargs):
        if not without_logs:
            logging.info("call %s %s", self.bridge, args)

        #disable ctrl+c for child processes
        if sys.platform == 'win32':
            kwargs.update(creationflags=CREATE_NEW_PROCESS_GROUP)
        else:
            kwargs.update(preexec_fn = preexec_signal_function)

        if sys.hexversion >= 0x03000000:
            # enable handling of stdout and stderr as text streams instead of bytes
            kwargs.update(universal_newlines=True)

        return self._run_interrupted_thread(args, kwargs)

class LocalShell(RemoteShell):
    def __init__(self, options):
        RemoteShell.__init__(self)
        self.script_dir = SCRIPT_DIR

        self.options = options
        self.runtool_executabe = [os.path.join(self.script_dir,PRODUCT_PREFIX + "-runss")]

    def get_shell_name(self):
        return 'local'

    def pull(self, src, dest, is_module = False):
        return 0

    def rpull(self, src, dest):
        return 0

    def push(self, src, dest):
        return 0

    def _call_shell_threaded_function(self, results, child_pids, args, kwargs):
        if 'stdout' in kwargs.keys() or 'stderr' in kwargs.keys():
            process = subprocess.Popen(self.runtool_executabe + args, **kwargs)
            stdout, stderr = process.communicate()
            child_pids[0] = process.pid
        else:
            process = subprocess.Popen(self.runtool_executabe + args,
                stderr=subprocess.PIPE,
                **kwargs)
            child_pids[0] = process.pid
            line = process.stderr.readline()
            product_info = ""
            product_info_lines = False
            incorrect_product_version = False

            delayed_errors = []
            while line:
                skip = False
                if "/_pvi_" in line.strip():
                    product_info_lines = False
                    line = process.stderr.readline()

                    if not self.check_product_info(product_info):
                        incorrect_product_version = True
                        break
                elif "_pvi_" in line.strip():
                    product_info_lines = True
                    line = process.stderr.readline()
                if product_info_lines:
                    product_info += line
                else:
                    line = patchFeedbackLine(line)

                    split_line = line.lower().split()
                    if 'segmentation' in split_line or 'aborted' in split_line or 'error:' in split_line or "cannot create directory" in line \
                       or 'osi_DLL_Error' in line or 'Unable to open shared library' in line or 'bash:' in line or 'sh:' in line \
                       or PRODUCT_PREFIX.upper() + '_TPSSCOLLECTOR:' in line or 'Assertion failed:' in line:
                        if not 'message severity' in line and not 'event name' in line and not 'modifier name' in line and not 'Network error' in line:
                            skip = True

                    #app-working-dir support
                    if self.options.app_work_dir:
                        for err in ['No such file or directory', 'Permission denied', 'can\'t cd to']:
                            if 'cd: ' + self.options.app_work_dir + ': ' + err in line or \
                                (self.options.app_work_dir.startswith('~/') and 'cd:' in line and self.options.app_work_dir[2:] in line and err in line) or \
                                'cd: ' + err + ' ' + self.options.app_work_dir in line:
                                line = 'Working directory ' + self.options.app_work_dir + ' is invalid: ' + err
                                skip = True

                    if skip:
                        if 'state_changed' in line:
                            self.options.messenger.write(line)
                        line = ''.join(e for e in line if e in string.printable)
                        delayed_errors.append(line)
                    else:
                        self.options.messenger.write(line)

                line = process.stderr.readline()
            process.communicate()
            if product_info != "":
                self.productInfo = product_info

            for line in delayed_errors:
                self.options.messenger.severitywrite("target - %s" % line, "error")

            if incorrect_product_version:
                results[0] = 1
                return

        results[0] = process.poll()

    def _call_shell(self, args, without_logs=False, **kwargs):
        if not without_logs:
            logging.info("call local %s", args)

        #disable ctrl+c for child processes
        if sys.platform == 'win32':
            kwargs.update(creationflags=CREATE_NEW_PROCESS_GROUP)
        else:
            kwargs.update(preexec_fn = preexec_signal_function)

        if sys.hexversion >= 0x03000000:
            # enable handling of stdout and stderr as text streams instead of bytes
            kwargs.update(universal_newlines=True)

        return self._run_interrupted_thread(args, kwargs)

class DockerShell(LocalShell):
    def __init__(self, options):
        LocalShell.__init__(self, options)
        self.docker_command = "docker"
        self.docker_command_option = "exec"
        self.container_hash = options.container_hash
        self.runtool_executabe = []

    def is_accessible(self):
        args = [self.docker_command, "info"]
        res = subprocess.run(args)
        if res.returncode != 0:
            return 1
        return 0

    def cp_to_container(self, source_path, destination_path):
        cmd = [self.docker_command, "cp", source_path, self.container_hash + ":" + destination_path]
        return LocalShell.call(self, cmd)

    def cp_from_container(self, source_path, destination_path):
        cmd = [self.docker_command, "cp", self.container_hash + ":" + source_path, destination_path]
        return LocalShell.call(self, cmd)

    def mv(self, source_path, destination_path):
        args = ["mv", source_path, destination_path]
        return self.call_shell(args)

    def tar(self, archive, destination):
        args = ["tar", "xf", archive, "-C", destination]
        return self.call_shell(args)

    def rm(self, file):
        args = ["rm", "-rf", file]
        return self.call_shell(args)

    def mkdir(self, dir):
        args = ["mkdir", "-p", dir]
        return self.call_shell(args)

    def call_shell(self, args):
        args = [self.docker_command, self.docker_command_option, self.container_hash] + args
        return LocalShell.call(self, args)

class LxcShell(LocalShell):
    def __init__(self, options):
        LocalShell.__init__(self, options)
        self.lxc_command = "lxc-attach"
        self.lxc_command_option = "--name"
        self.lxc_command_prefix = "--"
        self.container_hash = options.container_hash
        self.runtool_executabe = []

    def is_accessible(self):
        args = ["lxc-checkconfig"]
        res = subprocess.run(args)
        if res.returncode != 0:
            return 1
        return 0

    def get_lxc_fs_path(self):
        cmd = ["lxc-config", "lxc.lxcpath"]
        lxc_out_file = tempfile.TemporaryFile('w+', encoding=ENCODING)
        retsut = LocalShell.call(self, cmd, False, stdout=lxc_out_file, stderr=lxc_out_file)
        lxc_out_file.seek(0)
        for line in lxc_out_file:
            if line:
                return os.path.join(line.strip(), self.container_hash, "rootfs")

        return ""

    def call_shell(self, args, **kwargs):
        args = [self.lxc_command, self.lxc_command_option, self.container_hash, self.lxc_command_prefix] + args
        if "runProccess" in kwargs:
            return self._create_process(args)

        return LocalShell.call(self, args, **kwargs)

    def _create_process(self, cmd):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        process = subprocess.Popen(cmd + ["&"])
        return process.wait()

def createSSHShell(options):
    if sys.platform == 'win32':
        script_dir = SCRIPT_DIR
        ssh_temp = os.path.join(script_dir, 'ssh.exe')
        scp_temp = os.path.join(script_dir, 'scp.exe')
        if os.path.isfile(ssh_temp) and os.path.isfile(scp_temp):
            os.environ["PATH"] = script_dir + os.pathsep + os.getenv('PATH')
    ssh   = which("ssh")
    scp   = which("scp")

    shell = None
    if ssh and scp:
        shell = SSH(options)
        os.putenv('PATH', os.getenv('PATH') + os.pathsep + os.path.dirname(ssh) + os.pathsep + os.path.dirname(scp))
    else:
        error_message = " is not in PATH."
        if ssh and not scp:
            error_message = "scp (secure copy (remote file copy program))" + error_message
        elif not ssh and scp:
            error_message = "ssh (OpenSSH SSH client (remote login program)" + error_message
        else:
            error_message = "ssh/scp tools are not available in PATH."
        options.messenger.severitywrite(error_message)
    return shell

def checkAdb(options):
    if options.target:
        target = options.target.split(':')
        if len(target) > 1:
            os.environ['ANDROID_SERIAL'] = ":".join(target[1:])

    if not options.adb_path is None:
        adbExecutable = options.adb_path
    else:
        adbExecutable = "adb"
    adb   = which(adbExecutable)
    if not options.package_command == "build":
        if not adb:
            error_message = "adb is not found on the host. Add it to PATH or specify adb location in the Menu / Options... / Intel VTune Profiler / General."
            if hasattr(options, 'messenger'):
                options.messenger.severitywrite(error_message)
            else:
                sys.stderr.write(error_message)
            return False
        else:
            os.putenv('PATH', os.getenv('PATH') + os.pathsep + os.path.dirname(adb))
    return True

def path_split(path):
    path = path.replace('\\', '/')
    return path.split('/')

class AndroidPackageInstaller:
    def __init__(self, options):
        self.options = options

        self.is_local_prop_modified = False

        if not hasattr(self.options, 'messenger'):
            self.options.messenger = MessageWriter(xml=False)

        self.empty_progress = hasattr(self.options, 'option_file')

        script_dir = SCRIPT_DIR
        try:
             log_dir = os.path.dirname(self.options.log_name)
        except:
            log_dir = script_dir
            log_name = "setup.%s.log" % os.getpid()
            full_log_name = os.path.join(log_dir, log_name)
            if not self._is_writable(full_log_name):
                log_dir = ''
                full_log_name = os.path.join(log_dir, log_name)
            if not self._is_writable(full_log_name):
                self.options.messenger.severitywrite("Installation has failed because current directory is not writable. Change the directory.")
                self.options.messenger.failwrite(1)
                os._exit(1)

            logging.basicConfig(filename=full_log_name, level=logging.DEBUG, filemode="w")

        self.adb = ADB(self.options)

        if not self.options.package_command == 'build':
            self._check_adb()

        apk_file_dirs = default_apk_dirs()

        self.vtune_pkg_name=PACKAGE_NAME
        self.apk_file = None

        apk_ext = '.apk'
        nda_apk_ext = '.nda.apk'
        if not self.adb.get_arch() in [None, 'x86']:
            apk_ext = '.' + self.adb.get_arch() + '.apk'
            nda_apk_ext = '.nda.%s.apk' % self.adb.get_arch()

        for apk_file_dir in default_apk_dirs():
            apk_file = os.path.join(apk_file_dir, self.vtune_pkg_name + apk_ext)
            nda_apk_file = os.path.join(apk_file_dir, self.vtune_pkg_name + nda_apk_ext)
            if os.path.isfile(apk_file):
                if os.path.isfile(nda_apk_file):
                    apk_file = nda_apk_file
                self.apk_file = os.path.normpath(apk_file)
                self.pkg_root_dir = os.path.dirname(self.apk_file)
                break

        if self.apk_file is None:
            if self.adb.get_arch() in ['x86_64', 'arm64']:
                self.options.messenger.severitywrite("64-bit target architecture is not supported.")
            else:
                self.options.messenger.severitywrite("Cannot find " + self.vtune_pkg_name  + apk_ext + " file to install the package. Check the target directory.")
            self.options.messenger.failwrite(1)
            os._exit(1)

        self.product = AndroidProductLayout(self.options)
        self.build_dir = os.path.join(log_dir, ".cache")
        self.install_dir = self.build_dir + self.product.get_install_dir()
        if not os.path.exists(self.build_dir):
            logging.info("Creating %s empty directory" % self.build_dir)
            os.makedirs(self.build_dir)
            logging.info("Creating %s empty directory" % self.install_dir)
            os.makedirs(self.install_dir)

    def _getprop(self, property_name):
        tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
        retcode = self.adb._call_adb( [
                              'shell', 'getprop', property_name, ';',
                          ], stdout=tmp_log, stderr=tmp_log)
        tmp_log.seek(0)
        return " ".join([x.strip() for x in tmp_log.readlines() if x]).strip()

    def update(self):
        self._check_adb()
        output = " ".join(self.adb.get_cmd_output([self.product.get_binary_path("version.sh"), '-V']))
        m = re.match(".*build\s+(?P<version>\d+)", output.strip())
        if m:
            current_version = None
            version = int(m.group('version'))

            install_product = False

            support_file = None
            script_dir = SCRIPT_DIR
            support_file_dirs = [
                                os.path.join(script_dir, '..'),
                                os.path.join(script_dir, '..', '..'),
                            ]
            for support_file_dir in support_file_dirs:
                support_file_tmp = os.path.join(support_file_dir, 'support.txt')
                if os.path.isfile(support_file_tmp):
                    support_file = support_file_tmp
                    break
            if support_file != None:
                for line in open(support_file, 'r', encoding=ENCODING).readlines():
                    m = re.match(".*Build\s+Number:\s+(?P<version>\d+)", line.strip())
                    if m:
                        current_version = int(m.group('version'))
                        break
            if current_version != None:
                if current_version != version:
                    self.clean()
                    self.install()
        else:
            self.clean()
            self.install()

    def install(self):
        if not hasattr(self.options, 'build_drivers'):
            self.options.build_drivers = False

        build_drv = self.options.build_drivers

        self.uninstall()
        self._check_adb()
        if self.apk_file is None:
            self._check_adb_root()

        is_root = self.adb.is_root()

        if not hasattr(self.options, 'use_cache'):
            self.options.use_cache = False

        if not SIMPLE_APK_INSTALL:
            self.build()

        serialno = self.adb.serialno()

        if not SIMPLE_APK_INSTALL:
            if not self.adb.get_arch() in ['x86', 'x86_64']:
                msg = "Device is not based on x86 architecture. Sytem-wide and event-based sampling collections are not available."
                self.options.messenger.severitywrite(msg, "info")
                logging.info(msg)
            elif not is_root:
                msg = "Device is not in the root mode. Java code profiling and system-wide collection are not available."
                self.options.messenger.severitywrite(msg, "info")
                logging.info(msg)

        msg = "Installing the package to %s" % serialno
        if self.empty_progress:
            progressbar = EmptyProgressBar("")
            self.options.messenger.severitywrite(message = msg, severity = "info")
        else:
            progressbar = ProgressBar(msg)
        logging.info(msg)

        progressbar.start()

        if self.apk_file is not None:
            self.adb.install(self.apk_file)
            self.adb.am_start(self.vtune_pkg_name + "/" + self.vtune_pkg_name + ".InstallActivity")
            self.adb.am_force_stop(self.vtune_pkg_name)

        if is_root:
            shell_dir = "/data/data/%s/" % self.vtune_pkg_name
            res = self.adb.mv(shell_dir + "/cache/*", shell_dir)
            if res == 0:
                dev_arch = '32'
                if '64' in self.adb.get_arch():
                    dev_arch = '64'
                self.adb.rm("-r", shell_dir + '/perfrun/bin')
                self.adb.rm("-r", shell_dir + '/perfrun/lib')
                self.adb.ln("-s", shell_dir + '/perfrun/bin' + dev_arch, shell_dir + '/perfrun/bin')
                self.adb.ln("-s", shell_dir + '/perfrun/lib' + dev_arch, shell_dir + '/perfrun/lib')

        if is_root and not SIMPLE_APK_INSTALL:
            if self.adb.is_otc() or self.adb.get_arch() == 'arm' or self.adb.is_art or not self.adb.libdvm_jitvtune_enabled:
                local_prop = os.path.join(self.build_dir, "data", "local.prop")
                shutil.move(local_prop, local_prop + '_jitvtuneinfo')
                self.adb.push(self.build_dir, "/")
                shutil.move(local_prop + '_jitvtuneinfo', local_prop)
                self.is_local_prop_modified = False
            else:
                self.adb.push(self.build_dir, "/")
                self.adb.chmod("0644", "/data/local.prop")
            self.adb.chmod("0777", self.product.get_project_dir())
            self.adb.chmod("0777", '/data/amplxe/results')
            if self.apk_file is None:
                self.adb.chmod("0775", self.product.get_bin32_dir() + '*')

        if self.adb.is_selinux():
            shell_dir = "/data/local/tmp/%s" % self.vtune_pkg_name
            runas_dir = "/data/data/%s/perfrun" % self.vtune_pkg_name
            self.adb.rm("-r", shell_dir)
            self.adb.mkdir(shell_dir)
            self.adb.cp("-rf", runas_dir, shell_dir)
            dev_arch = '32'
            if '64' in self.adb.get_arch():
                dev_arch = '64'
            self.adb.rm("-r", shell_dir + '/perfrun/bin')
            self.adb.rm("-r", shell_dir + '/perfrun/lib')
            self.adb.ln("-s", shell_dir + '/perfrun/bin' + dev_arch, shell_dir + '/perfrun/bin')
            self.adb.ln("-s", shell_dir + '/perfrun/lib' + dev_arch, shell_dir + '/perfrun/lib')

        progressbar.stop()
        if not SIMPLE_APK_INSTALL and is_root and self.adb.get_arch() in ['x86', 'x86_64'] and (self.is_local_prop_modified or not self.adb.jitvtune_enabled):
            if os.getenv(PRODUCT_PREFIX.upper() + '_INSTALL_DEVICE_PACKAGE', '0') == '1':
                self.adb.set_vm_prop(force_enable_mode = True)
#            msg = "Reboot your device to have correctly resolved dynamic code."
#            self.options.messenger.severitywrite(msg, "info")
#            logging.info(msg)

    def uninstall(self):
        self._check_adb()
        if self.apk_file is None:
            self._check_adb_root()

        is_root = self.adb.is_root()
        if is_root:
            self.adb.rm("-r","/data/amplxe/results/")
            self.adb.rm("-r", self.product.get_project_dir())
            self.adb.rm("/data/intel/libittnotify.so")

        if self.apk_file is not None:
            self.adb.uninstall(self.vtune_pkg_name)
            if is_root:
                self.adb.rm("-r", "/data/data/" + self.vtune_pkg_name)
        elif is_root:
            self.adb.rm("-r","/data/data/" + self.vtune_pkg_name + "/perfrun")
            self.adb.rm("-r", self.product.get_install_dir())

        if self.adb.is_selinux():
            shell_dir = "/data/local/tmp/%s" % self.vtune_pkg_name
            self.adb.rm("-r", shell_dir)

    def clean(self):
        msg = "Deleting %s directory" % repr(self.build_dir)
        self.options.messenger.severitywrite(msg, "info")
        logging.info(msg)
        shutil.rmtree(self.build_dir, True)

    def build(self):
        if not hasattr(self.options, 'build_drivers'):
            self.options.build_drivers = False
        build_drv = self.options.build_drivers

        marker_done = os.path.join(self.build_dir, "DONE")
        if os.path.exists(marker_done):
            self._copy_libittnotify() #this workaroud while we don't change path to ittnotify in dalvik
            logging.info("DONE marker exists, nothing to do")
            return

        msg = "Creating %s directory" % repr(self.build_dir)
        self.options.messenger.severitywrite(msg, "info")
        logging.info(msg)
        self._create_local_prop()
        self._create_results_dir()
        self._copy_libittnotify()
        if self.apk_file is None:
            self._create_tmp_dir()
            self._copy_bin32_dir()
            self._copy_lib32_dir()
            self._copy_config()
            self._copy_message_dir()
            self._copy_doc_dir()
        drivers = []
        if build_drv and self.adb.get_arch() in [None, 'x86', 'x86_64']:
            drivers += self._build_sepdk()

        self._create_drv_dir(drivers)

        open(marker_done, "w")
        logging.info("creating DONE marker file")

    def _is_writable(self, path):
        try:
            f = open(path,'w')
            f.close()
        except IOError:
            return False
        return True

    def _create_drv_dir(self, driver_list):
        drv_dir = self.build_dir + self.product.get_drv_dir()
        if not os.path.isdir(drv_dir):
            os.makedirs(drv_dir)
        for driver in driver_list:
            if os.path.isfile(driver):
                shutil.copy(driver, drv_dir)

    def _build_sepdk(self):
        sepdk_dir=os.path.join(self.pkg_root_dir, "sepdk")
        if not os.path.exists(sepdk_dir):
            sepdk_dir=os.path.join(self.pkg_root_dir, "../sepdk")
        self._build_driver("SEP/VTSS++", sepdk_dir, False, "VTSS=android") #"VTSS=android uec"
        sepdk_dir=os.path.join(self.build_dir + "_sepdk", "sepdk", "build")
        if not os.path.exists(sepdk_dir):
            sepdk_dir=os.path.join(self.build_dir + "_sepdk", "sepdk", "src")
        return [os.path.join(sepdk_dir, "pax", "pax.ko"),
            os.path.join(sepdk_dir, "sep" + PRODUCT_VERSION + ".ko"),
            os.path.join(sepdk_dir, "vtsspp", "vtsspp.ko"),
            os.path.join(sepdk_dir, "src/socperf/src", "socperf2_0.ko"),
            os.path.join(sepdk_dir, "src/socperf/src", "socperf3.ko")]

    def _build_driver(self, drvname, driverdk, backw_comp, *extra_args):
        ANDROID_KERNEL_SRC_DIR=self.options.kernel_src_dir
        KERNEL_VERSION=self.options.kernel_version

        driverdk_backw_comp = os.path.join(driverdk, '../../' + PRODUCT_BACK_DIR + '/sepdk')

        kernel_config = os.path.join( ANDROID_KERNEL_SRC_DIR, ".config")
        kernel_arch = 'x86'
        sig_hash_algorithm=None
        if os.path.isfile(kernel_config):
            for line in open(kernel_config, "r").readlines():
                if 'Kernel Configuration' in line:
                    if 'x86_64' in line:
                        kernel_arch = 'x86_64'
                    if KERNEL_VERSION=='unknown':
                        KERNEL_VERSION=line.split()[2]

                elif 'CONFIG_MODULE_SIG_HASH=' in line:
                    sig_hash_algorithm = re.search("CONFIG_MODULE_SIG_HASH=(.+)", line)
                    if sig_hash_algorithm:
                        sig_hash_algorithm = sig_hash_algorithm.group(1)
                    else:
                        sig_hash_algorithm=None

        #copy driverdk to local .cache
        shutil.rmtree(self.build_dir + '_' + os.path.basename(driverdk), True)
        sepdk = os.path.join(self.build_dir + '_' + os.path.basename(driverdk), os.path.basename(driverdk))
        shutil.copytree(driverdk, sepdk)

        src_dir = os.path.join(sepdk, 'src')
        if os.path.exists(src_dir):
            src_dir = os.path.join(sepdk, 'build')
            #os.makedirs(src_dir)
        shutil.copytree(driverdk, src_dir)

        if kernel_arch=='x86': #mcg
            ARCH= ["MARCH=i386"]
        if kernel_arch == 'x86_64':
            ARCH = ["MARCH=x86_64", "MACH=x86_64",]
        if os.path.exists(os.path.join(src_dir, 'Makefile.android')):
            for make_dir in ['', 'pax']:
                shutil.copy(os.path.join(src_dir, make_dir, 'Makefile.android'), os.path.join(src_dir, make_dir, 'Makefile'))

        driverdk = src_dir

        if not ANDROID_KERNEL_SRC_DIR:
            #backward compatibility
            ANDROID_REPO=os.environ.get("ANDROID_REPO")
            PRODUCT=os.environ.get("PRODUCT")

            if not PRODUCT or not ANDROID_REPO:
                self.options.messenger.severitywrite("Please set option --kernel-src-dir.");
                self.options.messenger.severitywrite("For example, --kernel-src-dir=path_to_src_tree/out/target/product/ctp_pr1/kernel_build")
                os._exit(2)

            ANDROID_REPO=os.path.abspath(ANDROID_REPO)
            ANDROID_KERNEL_SRC_DIR=os.path.join(ANDROID_REPO, "out", "target", "product", PRODUCT, "kernel_build")
        else:
            ANDROID_KERNEL_SRC_DIR=os.path.abspath(ANDROID_KERNEL_SRC_DIR)

        if os.path.isdir(ANDROID_KERNEL_SRC_DIR):
            make_log = tempfile.TemporaryFile('w+', encoding=ENCODING)

            driver_subdirs = ['.', 'pax', 'vtsspp', 'src/socperf/src'] #['.', 'pax', 'vtsspp']
            sep_version = 'sep' + PRODUCT_VERSION
            for line in open(os.path.join(driverdk, 'Makefile'), 'r').readlines():
                if 'DRIVER_NAME' in line:
                    sep_version = line.split('=')[1].strip()
                    break

            msg = "Building %s driver v%s:" % (drvname, sep_version.replace('sep', ''))
            if backw_comp:
                msg = "Cannot build driver.\nBuilding previous %s driver v%s:" % (drvname, sep_version.replace('sep3_', '3.'))

            if self.empty_progress:
                processbar = EmptyProgressBar("")
                self.options.messenger.severitywrite(message = msg, severity = "info")
            else:
                processbar = ProgressBar(msg)

            processbar.start()

            for driver_subdir in driver_subdirs:
                make_driver = ["make", "-C", os.path.join(driverdk, driver_subdir), "KERNEL_VERSION=" + KERNEL_VERSION,
                    "KERNEL_SRC_DIR=" + ANDROID_KERNEL_SRC_DIR] + ARCH + list(extra_args)
                subprocess.check_call(make_driver + ["clean"], stdout=make_log, stderr=make_log, universal_newlines=True)
                try:
                    subprocess.check_call(make_driver, stdout=make_log, stderr=make_log, universal_newlines=True)
                except:
                    if os.path.isdir(driverdk_backw_comp) and not backw_comp:
                        processbar.stop()
                        return self._build_driver(drvname, driverdk_backw_comp, True, *extra_args)

                    self.options.messenger.severitywrite(str(list(extra_args)))
                    self.options.messenger.severitywrite("Cannot build the driver. Please check the 'make' command output.")
                    self.options.messenger.severitywrite(" ".join(make_driver))
                    subprocess.call(make_driver)
                    os._exit(1)

            processbar.stop()

            make_log.seek(0)
            for line in make_log.readlines():
                logging.debug(line.rstrip())

            if sig_hash_algorithm is not None:
                sign_file = os.path.join(ANDROID_KERNEL_SRC_DIR, 'source', 'scripts', 'sign-file')
                if os.path.isfile(sign_file):
                    sign_driver = [
                                      sign_file,
                                      sig_hash_algorithm.replace("\"", ""),
                                      os.path.join(ANDROID_KERNEL_SRC_DIR, 'signing_key.priv'),
                                      os.path.join(ANDROID_KERNEL_SRC_DIR, 'signing_key.x509'),
                                  ]
                    for driver in ["pax/pax.ko", sep_version + ".ko", "vtsspp/vtsspp.ko", "src/socperf/src/socperf3.ko", "src/socperf/src/socperf2_0.ko"]:
                        sign_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
                        full_driver_path = [os.path.join(driverdk, driver)]
                        if not os.path.exists(os.path.join(driverdk, driver)):
                            logging.debug("Kernel module %s doesn't exist" % full_driver_path)
                            continue

                        logging.debug("Sign kernel module %s" % full_driver_path)
                        logging.debug("%s" % " ".join(sign_driver + full_driver_path))
                        try:
                            subprocess.check_call(sign_driver + full_driver_path, stdout=sign_log, stderr=sign_log,
                                universal_newlines=True)
                        except:
                            self.options.messenger.severitywrite("Cannot sign the driver. Please check the 'sign' command output.", "info")
                            self.options.messenger.severitywrite(" ".join(sign_driver + full_driver_path), "info")
                            subprocess.call(sign_driver + full_driver_path)

                        sign_log.seek(0)
                        for line in sign_log.readlines():
                            logging.debug(line.rstrip())
                else:
                    logging.debug("Cannot find %s to sign drivers" % sign_file)
        else:
            self.options.messenger.severitywrite("The script cannot build %s driver.\n" % drvname)
            self.options.messenger.severitywrite("Make sure the --kernel-src-dir value '%s' is correct." % ANDROID_KERNEL_SRC_DIR)
            os._exit(1)

    def _create_local_prop(self):
        local_prop = os.path.join(self.build_dir, "data", "local.prop")
        logging.info("creating '%s' file" % local_prop)
        os.makedirs(os.path.dirname(local_prop))

        if which(self.adb.bridge):
            self.adb.pull("/data/local.prop", local_prop)

        try:
            self.options.jitvtuneinfo
        except:
            self.options.jitvtuneinfo = DEFAULT_JIT_MODE

        content = []
        is_modified = False
        if os.path.isfile(local_prop):
            dalvikopt = False
            for line in open(local_prop, "r").readlines():
                line = line.strip()
                if not line: continue
                if re.match("dalvik.vm.extra-opts", line):
                    dalvikopt = True
                    jitinfo = re.search("-Xjitvtuneinfo:(\w+)", line)
                    if jitinfo:
                        jitinfo_value = jitinfo.group(1)
                        if self.options.jitvtuneinfo != None and jitinfo_value != self.options.jitvtuneinfo:
                            line = line.replace('-Xjitvtuneinfo:' + jitinfo_value, '-Xjitvtuneinfo:' + self.options.jitvtuneinfo)
                            is_modified = True
                    else:
                        if self.options.jitvtuneinfo == None:
                            self.options.jitvtuneinfo = DEFAULT_JIT_MODE
                        line += " -Xjitvtuneinfo:" + self.options.jitvtuneinfo
                        is_modified = True
                content += [line]
            if not dalvikopt:
                if self.options.jitvtuneinfo == None:
                    self.options.jitvtuneinfo = DEFAULT_JIT_MODE
                content += ["dalvik.vm.extra-opts=-Xjitvtuneinfo:" + self.options.jitvtuneinfo]
                is_modified = True
        else:
            if self.options.jitvtuneinfo == None:
                self.options.jitvtuneinfo = DEFAULT_JIT_MODE
            content += ["dalvik.vm.extra-opts=-Xjitvtuneinfo:" + self.options.jitvtuneinfo]
            is_modified = True

        if is_modified:
            self.is_local_prop_modified = True
            logging.info("local.prop content was modified: " + "; ".join(content))
            open(local_prop, "wb").write(encode("\n".join(content)))
        else:
            logging.info("local.prop content was not modified: " + "; ".join(content))


    def _copy_libittnotify(self):
        data_intel = os.path.join(self.build_dir, "data", "intel")
        src_ittnotify = os.path.join(self.pkg_root_dir, "lib32", "runtime",
            "libittnotify_collector.so")
        dst_ittnotify = os.path.join(data_intel, "libittnotify.so")

        if not hasattr(self.options, 'use_cache'):
            self.options.use_cache = False

        if os.path.isfile(dst_ittnotify) and self.options.use_cache:
            return
        if not os.path.isdir(data_intel):
            os.makedirs(data_intel)

        if self.apk_file is not None:
            apkzip = zipfile.ZipFile(self.apk_file, 'r')
            for name in apkzip.namelist():
                if '.zip' in name:
                    apk_cache = os.path.join(self.build_dir, '.apkcache')
                    if not os.path.isdir(apk_cache):
                        os.makedirs(apk_cache)
                    amplxeandroidzip = os.path.join(apk_cache, os.path.basename(name))
                    self._extract_from_zip(name, amplxeandroidzip, apkzip)
                    amplxezip = zipfile.ZipFile(amplxeandroidzip, 'r')
                    for amplxe_name in amplxezip.namelist():
                        if 'ittnotify' in amplxe_name:
                            apk_itt = os.path.join(apk_cache, os.path.basename(amplxe_name))
                            self._extract_from_zip(amplxe_name, apk_itt, amplxezip)
                            shutil.copy(apk_itt, dst_ittnotify)
                    amplxezip.close()
                    shutil.rmtree(apk_cache, True)
            apkzip.close()
        else:
            shutil.copy(src_ittnotify, dst_ittnotify)

    def _extract_from_zip(self, name, dest_path, zip_file):
        dest_file = open(dest_path, 'wb')
        dest_file.write(zip_file.read(name))
        dest_file.close()

    def _create_tmp_dir(self):
        product_tmp_dir = self.build_dir + self.product.get_tmp_dir()
        os.makedirs(product_tmp_dir)
        open(os.path.join(product_tmp_dir, ".keepme"), "w")

    def _create_results_dir(self):
        product_prj_dir = os.path.join(self.build_dir, "data/amplxe/results")
        os.makedirs(product_prj_dir)
        open(os.path.join(product_prj_dir, ".keepme"), "w")

    def _copy_bin32_dir(self):
        src_bin32 = os.path.join(self.pkg_root_dir,  "bin32")
        dst_bin32 = os.path.join(self.install_dir, "bin32")
        shutil.copytree(src_bin32, dst_bin32)

    def _copy_lib32_dir(self):
        src_lib32 = os.path.join(self.pkg_root_dir,  "lib32")
        dst_lib32 = os.path.join(self.install_dir, "lib32")
        shutil.copytree(src_lib32, dst_lib32)
        shutil.rmtree(os.path.join(dst_lib32, "python"), True)
        for lib in glob.glob(os.path.join(dst_lib32, "*.a")):
            os.remove(lib)

    def _copy_message_dir(self):
        src_message = os.path.join(self.pkg_root_dir,  "message")
        dst_message = os.path.join(self.install_dir, "message")
        shutil.copytree(src_message, dst_message)

    def _copy_config(self):
        src_doc = os.path.join(self.pkg_root_dir, "config")
        if os.path.isdir(src_doc):
            dst_doc = os.path.join(self.install_dir, "config")
            shutil.copytree(src_doc, dst_doc)

    def _copy_doc_dir(self):
        for doc in ['doc', 'documentation']:
            src_doc = os.path.join(self.pkg_root_dir, doc)
            if os.path.isdir(src_doc):
                dst_doc = os.path.join(self.install_dir, "doc")
                shutil.copytree(src_doc, dst_doc)
                break

    def _check_adb(self):
        if not self.adb.is_ready():
            serial = os.getenv('ANDROID_SERIAL', '')
            if serial:
                serial = ' ' + serial
            self.options.messenger.severitywrite("adb cannot communicate with the Android device%s." % serial)
            self.options.messenger.failwrite(1)
            os._exit(1)

        if self.adb.get_arch() == 'indeterminate':
            self.options.messenger.severitywrite("Cannot determine the Android device architecture.")
            self.options.messenger.failwrite(1)
            os._exit(1)
        elif self.adb.get_arch() is None:
            self.options.messenger.severitywrite("Unsupported device architecture - %s." % self.adb.get_arch())
            self.options.messenger.failwrite(1)
            os._exit(1)

    def _check_adb_root(self):
        if not self.adb.is_root():
            self.options.messenger.severitywrite("Device is not in the root mode.")
            self.options.messenger.failwrite(1)
            os._exit(1)

class LinuxPackageInstaller:
    def __init__(self, shell, options):
        self.options = options
        self.shell = shell

        self.installmarker = ".remoteinstall"

        if not hasattr(self.options, 'messenger'):
            self.options.messenger = MessageWriter(xml=False)

        self.empty_progress = hasattr(self.options, 'option_file')

        script_dir = SCRIPT_DIR
        try:
            log_dir = os.path.dirname(self.options.log_name)
        except:
            log_dir = script_dir
            log_name = "setup.%s.log" % os.getpid()
            full_log_name = os.path.join(log_dir, log_name)
            if not self._is_writable(full_log_name):
                log_dir = ''
                full_log_name = os.path.join(log_dir, log_name)
            if not self._is_writable(full_log_name):
                self.options.messenger.severitywrite("Installation has failed because current directory is not writable. Change the directory.")
                self.options.messenger.failwrite(1)
                os._exit(1)

            logging.basicConfig(filename=full_log_name, level=logging.DEBUG, filemode="w")

        self.product = LinuxProductLayout(self.options)

        self.local_package_dir = None
        self.remote_product_dir = None
        self.remote_packages = None

    def update(self):
        self.install()

    def _configure_package_info(self):
        if self.remote_packages is not None:
            return

        # Get the target package path
        arch = self.shell.get_arch()
        local_product_path = os.path.join(SCRIPT_DIR, '..')
        self.remote_product_dir = self.product.get_install_dir()
        self.remote_packages = ['{}_{}.tgz'.format(TARGET_PACKAGE_PREFIX, arch)]
        self.local_package_dir = os.path.normpath(os.path.join(local_product_path,
                                                           'target', self.shell.uname().lower()))
        if arch == 'x86_64':
            x86_package = '{}_x86.tgz'.format(TARGET_PACKAGE_PREFIX)
            if os.path.isfile(os.path.join(self.local_package_dir, x86_package)):
                self.remote_packages += [x86_package]
        base_package = os.path.join(self.local_package_dir, self.remote_packages[0])
        if not os.path.isfile(base_package):
            msg = "Cannot find target package %s for automatic installation" % base_package
            logging.error(msg)
            self.options.messenger.severitywrite(msg, "error")
            self.options.messenger.failwrite(1)
            os._exit(1)

    def install(self):
        self.uninstall()
        msg = "Installing the package to %s" % self.options.target

        if self.empty_progress:
            progressbar = EmptyProgressBar("")
            self.options.messenger.severitywrite(message=msg, severity="info")
        else:
            progressbar = ProgressBar(msg)
        logging.info(msg)

        progressbar.start()

        self._configure_package_info()

        result = self.shell.mkdir(self.remote_product_dir)
        common_msg = "\nMake sure VTune Profiler installation directory on the remote system option in the Analysis Target tab is set to the correct writable path.\n"
        common_msg += "Alternatively, you may use the --target-install-dir option to specify the correct path from command line.\n"
        if result != 0:
            msg = "Could not create target install directory %s.\n" % self.remote_product_dir
            logging.error(msg)
            self.options.messenger.severitywrite(msg + common_msg)
            self.options.messenger.failwrite(1)
            os._exit(1)

        ls_cmd = ['ls', self.remote_product_dir]
        ls_output = " ".join(self.shell.get_cmd_stdout(ls_cmd))
        if ls_output != "":
            msg = "Cannot start automatic installation process. " 
            msg += "Target install directory %s is not empty. " % self.remote_product_dir
            msg += "Specify another target install directory or clean current."
            logging.error(msg)              
            self.options.messenger.severitywrite(msg)
            self.options.messenger.failwrite(1)
            os._exit(1)

        clean_files = []
        for package in self.remote_packages[::-1]:
            local_package_path = os.path.join(self.local_package_dir, package)
            if not os.path.isfile(local_package_path):
                continue
            remote_package_path = self.remote_product_dir + package
            result = self.shell.push(local_package_path, self.remote_product_dir)
            if result != 0:
                msg = "Could not copy %s to %s on the target. " % (local_package_path, self.remote_product_dir)
                msg += "Run the specified command from the host to verify SSH password-less connection. "
                msg += "The username for this verification should be the same as the name used to run the analysis."
                msg += "'%s %s %s:%s'." % (self.shell.get_default_push_options(), local_package_path, self.shell.machine, self.remote_product_dir)
                logging.error(msg)
                self.options.messenger.severitywrite(msg + common_msg)
                self.options.messenger.failwrite(1)
                os._exit(1)
            result = self.shell.call(['tar', 'xf', remote_package_path, '-C', self.remote_product_dir])
            if result != 0:
                msg = "Could not unpack %s to %s on the target. " % (remote_package_path, self.remote_product_dir)
                self.uninstall()
                logging.error(msg)
                self.options.messenger.severitywrite(msg + common_msg)
                self.options.messenger.failwrite(1)
                os._exit(1)

        clean_files.append('%s/%s' % (self.remote_product_dir, TARGET_PACKAGE_PREFIX))
        result = self.shell.call(['mv', '%s/%s/*' % (self.remote_product_dir, TARGET_PACKAGE_PREFIX), self.remote_product_dir])
        if result != 0:
            msg = "Could not unpack %s to %s on the target. " % (remote_package_path, self.remote_product_dir)
            self.uninstall()
            logging.error(msg)
            self.options.messenger.severitywrite(msg + common_msg)
            self.options.messenger.failwrite(1)
            os._exit(1)

        target_linux_product_dir = self.remote_product_dir + "/target/linux"
        res = self.shell.mkdir(target_linux_product_dir)
        if (res == 0):
            self.shell.mv(remote_package_path, target_linux_product_dir)

        # Create the remote installation marker
#        result = self.shell.call(["touch", os.path.join(self.remote_product_dir, self.installmarker)])

        if len(clean_files):
            self.shell.rm(*(["-r"] + clean_files))

        progressbar.stop()

    def uninstall(self):
        self._configure_package_info()

    def clean(self):
        pass

    def _is_writable(self, path):
        try:
            f = open(path,'w')
            f.close()
        except IOError:
            return False
        return True

class DockerPackageInstaller:
    def __init__(self, options):
        self.options = options

        self.installmarker = ".containerinstall"

        self.options.messenger = MessageWriter(xml=False)

        script_dir = SCRIPT_DIR
        try:
            log_dir = os.path.dirname(self.options.log_name)
        except:
            log_dir = script_dir
            log_name = "setup.%s.log" % os.getpid()
            full_log_name = os.path.join(log_dir, log_name)
            if not self._is_writable(full_log_name):
                log_dir = ''
                full_log_name = os.path.join(log_dir, log_name)
            if not self._is_writable(full_log_name):
                self.options.messenger.severitywrite("Installation has failed because current directory is not writable. Change the directory.")
                self.options.messenger.failwrite(1)
                os._exit(1)

            logging.basicConfig(filename=full_log_name, level=logging.DEBUG, filemode="w")

        self.linuxProduct = LinuxProductLayout(self.options)
        self.target_package_name = os.path.basename(os.path.normpath(self.linuxProduct.get_install_dir().split("/")[-2]))

        self.product = DockerProductLayout(self.options)
        self.local_package_dir = None
        self.remote_packages = None

        self.shell = DockerShell(options)

    def update(self):
        self.install()

    def get_arch(self):

        uname_run = subprocess.Popen(['uname', '-m'], stdout=subprocess.PIPE,
            universal_newlines=True)
        uname_output = uname_run.communicate()[0];
        if 'amd64' in uname_output or 'x86_64' in uname_output:
            self.system_arch = 'x86_64'
        else:
            self.system_arch = 'x86'
        return self.system_arch

    def prepare_remote_dir(self, container_dir):
        res = self.shell.mkdir(container_dir)
        if (res != 0):
            return False

        return True

    def _configure_package_info(self):
        if self.remote_packages is not None:
            return

        # Get the target package path
        local_product_path = os.path.join(SCRIPT_DIR, '..')
        package_filename = '{}_{}.tgz'.format(TARGET_PACKAGE_PREFIX, self.get_arch())
        self.remote_packages = [package_filename]

        self.local_package_dir = os.path.normpath(os.path.join(local_product_path,
                                                           'target', 'linux'))
        if self.get_arch() == 'x86_64':
            x86_package = '{}_x86.tgz'.format(TARGET_PACKAGE_PREFIX)
            if os.path.isfile(os.path.join(self.local_package_dir, x86_package)):
                self.remote_packages += [x86_package]

        base_package = os.path.join(self.local_package_dir, self.remote_packages[0])
        if not os.path.isfile(base_package):
            msg = "Cannot find target package %s for automatic installation" % base_package
            logging.error(msg)
            self.options.messenger.severitywrite(msg, "error")
            msg = "Cannot find product on the target system at " + self.options.target
            msg += ":" + self.product.install_dir + "\n"
            msg += "Make sure VTune Profiler installation directory on the remote system option in the Analysis Target tab is set to the correct path. "
            msg += "Alternatively, you may use the --target-install-dir option to specify the correct path from command line.\n"
            self.options.messenger.severitywrite(msg)
            self.options.messenger.failwrite(1)

    def install(self):
        msg = "Installing the package to %s" % self.options.target
        logging.info(msg)

        self.uninstall()

        self._configure_package_info()

        common_msg = "\nMake sure VTune Profiler installation directory on the remote system option in the Analysis Target tab is set to the correct writable path.\n"

        if not self.prepare_remote_dir(self.product.get_copy_dir()):
            msg = "Could not create target install directory %s.\n" % self.product.get_install_dir()
            logging.error(msg)
            self.options.messenger.severitywrite(msg + common_msg)
            self.options.messenger.failwrite(1)
            os._exit(1)

        if not self.prepare_remote_dir(self.product.get_project_dir()):
            msg = "Could not create target result directory %s.\n" % self.product.get_project_dir()
            logging.error(msg)
            self.options.messenger.severitywrite(msg + common_msg)
            self.options.messenger.failwrite(1)
            os._exit(1)

        clean_files = []
        for package in self.remote_packages[::-1]:
            local_package_path = os.path.join(self.local_package_dir, package)
            if not os.path.isfile(local_package_path):
                continue

            remote_package_path = os.path.join(self.product.get_copy_dir(), package)
            clean_files.append(remote_package_path)

            res = self.shell.cp_to_container(local_package_path, self.product.get_copy_dir())
            if res != 0:
                msg = "Could not copy %s to %s on the target." % (local_package_path, self.product.get_copy_dir())
                logging.error(msg)
                self.options.messenger.severitywrite(msg + common_msg)
                self.options.messenger.failwrite(1)
                os._exit(1)

            cmd = ["tar", "xf", remote_package_path, "-C", self.product.get_copy_dir()]
            res = self.shell.call_shell(cmd)
            if res != 0:
                msg = "Could not unpack 1 %s to %s on the target. " % (remote_package_path, self.product.get_copy_dir())
                self.uninstall()
                logging.error(msg)
                self.options.messenger.severitywrite(msg + common_msg)
                self.options.messenger.failwrite(1)
                os._exit(1)

            res = self.shell.call_shell(["cp", "-aT", os.path.join(self.product.get_copy_dir(), TARGET_PACKAGE_PREFIX), self.product.install_dir])
            if res != 0:
                msg = "Could not rename %s to %s on the target. " % (TARGET_PACKAGE_PREFIX, self.product.get_install_dir())
                self.uninstall()
                logging.error(msg)
                self.options.messenger.severitywrite(msg + common_msg)
                self.options.messenger.failwrite(1)
                os._exit(1)

        cmd = ["touch", os.path.join(self.product.get_install_dir(), self.installmarker)]
        self.shell.call_shell(cmd)

        if len(clean_files):
             self.shell.rm(" ".join(clean_files))

    def uninstall(self):
        self._configure_package_info()
        arch = '64'

        clean_dirs = [self.product.get_copy_dir(), self.product.project_dir]
        full_clean_dirs = []
        for clean_dir in clean_dirs:
            self.shell.rm(clean_dir)

    def clean(self):
        pass

    def _is_writable(self, path):
        try:
            f = open(path,'w')
            f.close()
        except IOError:
            return False
        return True

class LXCPackageInstaller:
    def __init__(self, options):
        self.options = options

        self.installmarker = ".remoteinstall"

        self.options.messenger = MessageWriter(xml=False)

        script_dir = SCRIPT_DIR
        try:
            log_dir = os.path.dirname(self.options.log_name)
        except:
            log_dir = script_dir
            log_name = "setup.%s.log" % os.getpid()
            full_log_name = os.path.join(log_dir, log_name)
            if not self._is_writable(full_log_name):
                log_dir = ''
                full_log_name = os.path.join(log_dir, log_name)
            if not self._is_writable(full_log_name):
                self.options.messenger.severitywrite("Installation has failed because current directory is not writable. Change the directory.")
                self.options.messenger.failwrite(1)
                os._exit(1)

            logging.basicConfig(filename=full_log_name, level=logging.DEBUG, filemode="w")

        self.linuxProduct = LinuxProductLayout(self.options)
        self.target_package_name = os.path.basename(os.path.normpath(self.linuxProduct.get_install_dir().split("/")[-2]))

        self.product = LxcProductLayout(self.options);

        self.local_package_dir = None
        self.container_install_dir = os.path.normpath("/tmp/intel/")
        self.container_product_dir = os.path.normpath(self.container_install_dir + "/target")
        self.container_result_dir = os.path.normpath("/tmp/agent_result/")
        self.remote_packages = None

        lxc_config = subprocess.Popen(["lxc-config lxc.lxcpath", self.options.container_hash], stdout=subprocess.PIPE)
        lxc_config_output = lxc_config.communicate()[0];
        self.lxcShell = LxcShell(options)
        self.lxc_path =  self.lxcShell.get_lxc_fs_path()
        self.localShell = LocalShell(self.options);

    def prepare_remote_dir(self, container_dir):
        res = self.localShell.mkdir(container_dir)
        if (res != 0):
            return False

        return True

    def get_arch(self):

        uname_run = subprocess.Popen(["uname", "-m"], stdout=subprocess.PIPE,
            universal_newlines=True)
        uname_output = uname_run.communicate()[0];
        if 'amd64' in uname_output or 'x86_64' in uname_output:
            self.system_arch = 'x86_64'
        else:
            self.system_arch = 'x86'
        return self.system_arch

    def update(self):
        self.install()

    def _configure_package_info(self):
        if self.remote_packages is not None:
            return

        # Get the target package path
        local_product_path = os.path.join(SCRIPT_DIR, '..')
        package_filename = '{}_%s.tgz'.format(TARGET_PACKAGE_PREFIX, self.get_arch())
        self.remote_packages = [package_filename]

        self.local_package_dir = os.path.normpath(os.path.join(local_product_path,
                                                           'target', 'linux'))
        base_package = os.path.join(self.local_package_dir, self.remote_packages[0])
        if not os.path.isfile(base_package):
            msg = "Cannot find target package %s for automatic installation" % base_package
            logging.error(msg)
            self.options.messenger.severitywrite(msg, "error")
            msg = "Cannot find product on the target system at " + self.options.target
            msg += ":" + self.product.install_dir + "\n"
            msg += "Make sure VTune Profiler installation directory on the remote system option in the Analysis Target tab is set to the correct path. "
            msg += "Alternatively, you may use the --target-install-dir option to specify the correct path from command line.\n"
            self.options.messenger.severitywrite(msg)
            self.options.messenger.failwrite(1)
            os._exit(1)

    def install(self):
        self.uninstall()
        msg = "Installing the package to %s" % self.options.target
        logging.info(msg)

        self._configure_package_info()
        common_msg = ""
        if not self.prepare_remote_dir(os.path.normpath(self.lxc_path + self.product.get_copy_dir())):
            msg = "Could not create target install directory %s.\n" % self.product.get_copy_dir()
            logging.error(msg)
            self.options.messenger.severitywrite(msg + common_msg)
            self.options.messenger.failwrite(1)
            os._exit(1)
        if not self.prepare_remote_dir(os.path.normpath(self.lxc_path + self.product.get_project_dir())):
            msg = "Could not create target result directory %s.\n" % self.product.get_project_dir()
            logging.error(msg)
            self.options.messenger.severitywrite(msg + common_msg)
            self.options.messenger.failwrite(1)
            os._exit(1)
        clean_files = []
        for package in self.remote_packages[::-1]:
            local_package_path = os.path.join(self.local_package_dir, package)
            if not os.path.isfile(local_package_path):
                continue
            remote_package_path = os.path.join(self.product.get_copy_dir(), package)

            cmd = ["cp", local_package_path,  self.lxc_path + self.product.get_copy_dir()]
            result = self.localShell.cp(local_package_path, os.path.normpath(self.lxc_path + self.product.get_copy_dir()))
            if result != 0:
                msg = "Could not copy %s to %s on the target." % (local_package_path, self.product.get_copy_dir())
                logging.error(msg)
                self.options.messenger.severitywrite(msg + common_msg)
                self.options.messenger.failwrite(1)
                os._exit(1)

            cmd = ["tar", "-xzf", self.lxc_path + remote_package_path, "-C", os.path.normpath(self.lxc_path + self.product.get_copy_dir())]
            result = self.localShell.call(cmd)
            if result != 0:
                msg = "Could not unpack 1 %s to %s on the target. " % (self.lxc_path + remote_package_path, self.lxc_path + self.product.get_copy_dir())
                self.uninstall()
                logging.error(msg)
                self.options.messenger.severitywrite(msg + common_msg)
                self.options.messenger.failwrite(1)
                os._exit(1)

            instal_dir_path = self.product.get_install_dir()
            result = self.localShell.mv(os.path.join(self.lxc_path + self.product.get_copy_dir(), TARGET_PACKAGE_PREFIX), os.path.normpath(self.lxc_path + self.product.get_install_dir()))
            if result != 0:
                msg = "Could not rename %s to %s on the target. " % (TARGET_PACKAGE_PREFIX, self.product.get_install_dir())
                self.uninstall()
                logging.error(msg)
                self.options.messenger.severitywrite(msg + common_msg)
                self.options.messenger.failwrite(1)
                os._exit(1)


        result = self.localShell.call(["touch", os.path.join(self.lxc_path + self.product.get_install_dir(), self.installmarker)])
        if len(clean_files):
            self.localShell.rm(" ".join(clean_files))

    def uninstall(self):
        self._configure_package_info()
        arch = '64'

        clean_dirs = [self.container_install_dir, self.container_result_dir]
        full_clean_dirs = []
        for clean_dir in clean_dirs:
            full_clean_dirs.append(os.path.normpath(self.lxc_path + clean_dir))

        self.localShell.rm(*(['-rf'] + full_clean_dirs))

    def clean(self):
        pass

    def _is_writable(self, path):
        try:
            f = open(path,'w')
            f.close()
        except IOError:
            return False
        return True

class RunToolBase:
    def __init__(self, options):
        self.file_parser = None
        if options.option_file:
            self.file_parser = OptionFileParser(options.option_file)

    def _init(self, options):
        self.result_dir = None
        self.target_pid = None
        self.useDrivers = False

        if options.option_file:
            self.result_dir = self._get_option_value_from_option_file(options.option_file,  ["-r", "--result-dir"])
            self.target_pid = self._get_option_value_from_option_file(options.option_file,  ["--target-pid"])
            if self.target_pid:
                self.target_pid = int(self.target_pid)
                self.options.target_pid = self.target_pid
            self.target_process = self._get_option_value_from_option_file(options.option_file,  ["--target-process"])
            self.options.target_process = self.target_process
            command = self._get_option_value_from_option_file(options.option_file,  ["-C", "--command"])
            if command != None:
                options.command = command

            if self._get_option_value_from_option_file(options.option_file,  ["--event-config"]) is not None:
                self.useDrivers = True
            if self._get_option_value_from_option_file(options.option_file,  ["--chipset-event-config"]) is not None:
                self.useDrivers = True
            mrte_mode = self._get_option_value_from_option_file(options.option_file,  ["--mrte-mode"])
            if mrte_mode is not None:
                self.options.mrte_mode = mrte_mode
        else:
            if '--context-value-list' in options.runss_args \
                or '--event-config' in options.runss_args \
                or '--chipset-event-config' in options.runss_args:
                self.useDrivers = True

        create_result_dir = True
        if '--context-value-list' in options.runss_args \
           or '--event-value-list' in options.runss_args \
           or '--ftrace-config-list' in options.runss_args \
           or '--atrace-config-list' in options.runss_args \
           or '--md5sum' in options.runss_args \
           or '--find-bin-file' in options.runss_args \
           or 'docker' in options.target \
           or 'lxc' in options.target \
           or options.deploy:

            create_result_dir = False

        if self.result_dir is None:
            self.result_dir = options.result_dir

        if not options.module_dir:
            self.module_dir = os.path.join(self.result_dir, 'all')
        else:
            self.module_dir = options.module_dir
        # Create <result_dir> directory if it doesn't exist
        if not os.path.exists(self.result_dir) and create_result_dir:
            os.makedirs(self.result_dir)

        self.host_log_dir = options.log_folder or SCRIPT_DIR

    def _is_ebs_collection(self):
        a = "--pmu-config" in self.runss_args
        b = "--event-config" in self.runss_args
        c = "--chipset-event-config" in self.runss_args
        return a or b or c

    def _get_arguments_from_option_file(self, path):
        if not self.file_parser:
            return None
        return self.file_parser.get_arguments_from_option_file();

    def _get_option_value_from_option_file(self, path, option_keys):
        if not self.file_parser:
            return None
        return self.file_parser.get_option_values(option_keys, True);

    def _get_option_values_from_option_file(self, path, option_keys, first_only = False):
        if not self.file_parser:
            return None
        return self.file_parser.get_option_values(option_keys, first_only);

class DockerRunTool(RunToolBase):
    def __init__(self, shell, product, options):
        RunToolBase.__init__(self, options)
        self.options = options
        self.shell = shell
        self.product = product
        self._init(options)
        self.localShell = LocalShell(options)

    def start(self, process_option, options):

        cmd = [self.product.get_binary_path(self.shell.get_arch(), "runss")]

        tpss_collection = False
        if (options.run_tpss):
            cmd += ["-t cpu"]
            tpss_collection = True

        cmd += ["--mrte-mode=mixed", "--result-dir",  self.product.get_project_dir(), "--mrte-type=java", process_option]
        res = self.shell.call_shell(cmd)

        if (res == 0):
            self.copy_result(self.options.container_result_dir, tpss=tpss_collection)

        return res

    def attach(self, identifier):
        logging.debug("attach to %s process", identifier)
        if isinstance(identifier, int):
            return self.start("--target-pid=" + str(identifier), self.options)
        else:
            return self.start("--target-process=" + str(identifier), self.options)

    def stop(self):
        cmd = [self.product.get_binary_path(self.shell.get_arch(), "runss"), "-r", self.product.get_project_dir(), "-command", "stop"]
        return self.shell.call_shell(cmd)

    def _rename_jit_file(self, directory):
        for file in os.listdir(directory):
            if os.path.isdir(os.path.join(directory, file)):
                self._rename_jit_file(os.path.join(directory, file))
            else:
                if file.endswith(".jit"):
                    file_name_parts = file.split(".")
                    shutil.copy(os.path.join(directory, file), os.path.join(self.result_directory, self.options.container_hash + "." + file_name_parts[1] + ".jit"))

    def copy_result(self, destination, tpss = False):
        self.result_directory = destination
        self.shell.cp_from_container(os.path.join(self.product.project_dir, "data.0/"), destination)
        if not tpss:
            self._rename_jit_file(os.path.join(destination, "data.0/"))
        for trace_file in os.listdir(os.path.join(destination, "data.0/")):
            trace_file = os.path.join(destination, "data.0/", trace_file)
            if (os.path.isfile(trace_file)):
                # we dont need to copy system trace file because we already have one
                if not trace_file.endswith(".sc"):
                    shutil.copy(trace_file, destination)

        if os.path.isdir(os.path.join(destination, "data.0/")):
            shutil.rmtree(os.path.join(destination, "data.0/"), True)


class LxcRunTool(RunToolBase):
    def __init__(self, shell, product, options):
        RunToolBase.__init__(self, options)
        self.options = options
        self.shell = shell
        self.product = product
        self.localShell = LocalShell(options)
        self._init(options)

    def start(self, process_option):
        cmd = [self.product.get_binary_path(self.shell.get_arch(), "runss"),  "--mrte-mode=mixed", "--result-dir",  self.product.get_project_dir(), "--mrte-type=java", process_option]
        res = self.shell.call_shell(cmd, runProccess=True)

        return res

    def attach(self, identifier):
        logging.debug("attach to %s process", identifier)
        if isinstance(identifier, int):
            return self.start("--target-pid=" + str(identifier))
        else:
            return self.start("--target-process=" + str(identifier))

    def stop(self):
        cmd = [self.product.get_binary_path(self.shell.get_arch(), "runss"), "-r", self.product.get_project_dir(), "-command", "stop"]
        res = self.shell.call_shell(cmd)
        self.copy_result(self.options.container_result_dir)
        return res

    def _rename_jit_file(self, directory):
        for file in os.listdir(directory):
            if os.path.isdir(os.path.join(directory, file)):
                self._rename_jit_file(os.path.join(directory, file))
            else:
                if file.endswith(".jit"):
                    file_name_parts = file.split(".")
                    self.localShell.cp(os.path.join(directory, file), os.path.join(self.result_directory, self.options.container_hash + "." + file_name_parts[1] + ".jit"))

    def copy_result(self, destination):
        self.result_directory = destination
        self.localShell.cp("-r", os.path.normpath(self.shell.get_lxc_fs_path() + self.product.project_dir), os.path.join(destination, "container_results"))
        self._rename_jit_file(os.path.join(destination, "container_results"))
        self.localShell.rm("-rf", os.path.join(destination, "container_results"))


class RunTool(RunToolBase):
    def __init__(self, shell, product, options):
        RunToolBase.__init__(self, options)
        self.options = options
        self.shell = shell
        self.product = product
        self.mic = False

        self._init(options)

        if self.product.get_layout_name() == 'android':
            if not self.shell.is_ready():
                self.options.messenger.failwrite(1)
                os._exit(8)

        self.remote_dir = None
        self.tmp_log_dir_name = ''

        def _escapeTargetOption(targetOption):
            return targetOption.translate(str.maketrans('@:','__'))

        self.remoteConfigPath = os.path.join(self.result_dir, 'config',
            'remote_{}.cfg'.format(_escapeTargetOption(self.options.target)))

        if os.path.exists(self.remoteConfigPath):
            remoteParser = OptionFileParser(self.remoteConfigPath)
            self.remote_dir = remoteParser.get_option_values(['--result-dir'], True)
            #read remote product dir from remote.cfg
            product_dir = remoteParser.get_option_values(['--product-dir'], True)
            if product_dir is not None:
                self.product.install_dir = product_dir
            if self.remote_dir:
                self.tmp_log_dir_name = os.path.basename(os.path.dirname(self.remote_dir))

            if options.command == 'cancel':
                with open(self.remoteConfigPath, "a", encoding=ENCODING) as r_cfg:
                    r_cfg.write('--command\ncancel\n')

        if self.remote_dir == None and options.command:
             self.remote_dir = self.result_dir

        if self.remote_dir == None:
            tmp_name = os.path.basename(tempfile.NamedTemporaryFile().name)
            self.tmp_log_dir_name = tmp_name
            tmp_name = posixpath.join(_escapeTargetOption(self.options.target), tmp_name, os.path.basename(self.result_dir))
            self.remote_dir = self.product.get_project_dir() + tmp_name
            try:
                if os.path.exists(self.result_dir):
                    config_dir = os.path.join(self.result_dir, "config")
                    if not os.path.exists(config_dir):
                        os.makedirs(config_dir)
                    with open(self.remoteConfigPath, "w", encoding=ENCODING) as r_cfg:
                        r_cfg.write('--result-dir\n' + self.remote_dir + '\n')
                        r_cfg.write('--product-dir\n' + self.product.install_dir + '\n')
            except:
                pass

        self.runss_args = []
        add_extra_runss_args = True

        self.tmp_dir = self.product.get_tmp_dir()

        self.log_level = os.environ.get(PRODUCT_PREFIX.upper() + "_LOG_LEVEL")
        self.experimental = os.environ.get(PRODUCT_PREFIX.upper() + "_EXPERIMENTAL")
        self.sepdk_home = os.environ.get(PRODUCT_PREFIX.upper() + "_SEPDK_HOME")

        if '--md5sum' in options.runss_args or '--find-bin-file' in options.runss_args:
            self.runss_args = ["--tmp-dir", os.path.join(self.tmp_dir, self.tmp_log_dir_name)]
            self.runss_args += options.runss_args
            add_extra_runss_args = False

        if add_extra_runss_args:
            self.runss_args = ["--result-dir", self.remote_dir, "--tmp-dir", os.path.join(self.tmp_dir, self.tmp_log_dir_name)]
            self.runss_args += options.runss_args
        self.search_dirs = []
        self.option_file = options.option_file

        self.options = options

        if add_extra_runss_args:
            if self._is_ebs_collection() or self.mic:
                if options.pmu_stack:
                    self.runss_args += ["--collector", "vtsspp"]
                else:
                    self.runss_args += ["--collector", "sep"]
            if options.stack:
                if '--ptrace' in options.runss_args:
                    self.runss_args += ["--stack"]
            else:
                self.runss_args += ["--no-stack"]

            #if '--context-value-list' not in options.runss_args:
            #    self.runss_args += ["--compression=0"]

        self._set_search_dirs()

        logging.debug("initializing RunTool class")
        logging.debug("result directory: %s", self.result_dir)
        logging.debug("extra arguments for runss: %s", self.runss_args)
        logging.debug("option file: %s", self.option_file)

    def run(self):
        self._insmod_drivers()
        retcode = self._call_runtool(self.runss_args)
        self._rmmod_drivers()
        return retcode

    def start_md5sum(self):
        args = self.runss_args
        KERNEL_VERSION=self.options.kernel_version
        if KERNEL_VERSION != 'unknown':
            args += ['--kernel-version', KERNEL_VERSION]

        ind = args.index('--md5sum') + 1
        if ind < len(args):
            if self.product.get_layout_name() != 'android':
                if args[ind].find("docker:") == 0:
                    remote_path = args[ind].split(":")[2].replace(os.sep, '/')
                    self.shell.call(["docker", "cp", args[ind].split(":")[1] + ":" +remote_path, self.tmp_dir])
                    args[ind] = self.tmp_dir + "/" + os.path.basename(remote_path)
                if args[ind].find("lxc:") == 0:
                    remote_path = args[ind].split(":")[2].replace(os.sep, '/')
                    self.shell.call(["cp", "`lxc-config lxc.lxcpath`" + "/" + args[ind].split(":")[1] + "/rootfs/" +  remote_path, self.tmp_dir])
                    args[ind] = self.tmp_dir + "/" + os.path.basename(remote_path)
            args[ind] = '"' + args[ind] + '"'

        logging.debug("getting md5sum: %s", args)
        retcode = self._call_runtool(args)
#        clean_dirs = self._copy_logs()
#        self.shell.rm(*(["-r"] + clean_dirs))
        return retcode

    def start(self, args=None):
        if args is None:
            args = self.runss_args

        logging.debug("start data collection: %s", args)
        return self._collect_data(args)

    def attach(self, identifier):
        logging.debug("attach to %s process", identifier)
        if isinstance(identifier, int):
            self.target_pid = identifier
            return self._collect_data(["--target-pid", str(identifier)])
        elif self.product.get_layout_name() == 'android':
            ps_output = self.shell.ps()
            logging.debug("ps output: %s", ps_output)
            target_pids = []
            for line in ps_output:
                if identifier == line.split()[-1]:
                    target_pids.append(line.split()[1])
            if len(target_pids) < 1:
                self.options.messenger.severitywrite("There are no processes for %s" % identifier)
                self.options.messenger.failwrite(1)
                os._exit(1)
            if len(target_pids) > 1:
                self.options.messenger.severitywrite("There are more than one process for %s" % identifier)
                logging.debug("multiple attach - %s\n" % str(target_pids))
                self.options.messenger.failwrite(1)
                os._exit(1)
            if len(target_pids) > 0:
                self.target_pid = target_pids[0]
            logging.debug("target pid: %s", self.target_pid)
            return self._collect_data(["--target-pid", str(self.target_pid)])
        else:
            return self._collect_data(["--target-process", identifier])

    def mark(self):
        return self.execute("mark")

    def cancel(self):
        return self.execute("cancel")

    def pause(self):
        return self.execute("pause")

    def resume(self):
        return self.execute("resume")

    def detach(self):
        return self.execute("detach")

    def stop(self):
        return self.execute("stop")

    def execute(self, command):
        return self._call_runtool(self.runss_args + ['-C', command])

    #workaround for target system with tcsh on default
    def _sh_cmd_wrapper(self, cmd):
        if self.product.get_layout_name() == 'android':
            return cmd
        return ["sh -c '" + " ".join(cmd) + "\'"]

    def _set_search_dirs(self):
        self.search_dirs = []

        directories = self.options.search_dir
        if directories:
            self.search_dirs += directories

        if self.options.option_file:
            option_file_directories = self._get_option_values_from_option_file(self.options.option_file,  ["--search-dir"])
            if option_file_directories:
                #remove special symbols from path.
                #all:r=path --> path
                option_file_directories = list(map(lambda x: x if x.find("=")==-1 else x.partition("=")[2], option_file_directories))
                self.search_dirs += option_file_directories

        logging.debug("set search directories: %s", self.search_dirs)

    def _check_product(self):
        install_product = False
        ssh_keygen_status = False

        full_ssh_msg = "Cannot communicate with the target %s. To collect data on a remote Linux system, " % (self.options.target)
        full_ssh_msg += "configure SSH to work in a password-less mode so that it does not prompt for the password on each invocation. "
        full_ssh_msg += "Usually, this can be accomplished by either setting up a key-based authentication, or by setting the password "
        full_ssh_msg += "to an empty string. Press F1 for more details. "
        full_ssh_msg += "Run the specified command from the host to verify SSH password-less connection. "
        full_ssh_msg += "The username for this verification should be the same as the name used to run the analysis. "
        full_ssh_msg += "'%s %s uname'." % (self.shell.get_shell_name(), self.shell.get_default_run_options())

        def connection_check(output):
            known_issues = ['Unable to use key', 'FATAL ERROR:', 'Connection abandoned', 'Host key verification failed', 'Network error', 
                            'Server refused our key', 'Connection refused', 'Permission denied (', 'REMOTE HOST IDENTIFICATION HAS CHANGED']
            for error_type in known_issues:
               if error_type in output and self.product.get_layout_name() != 'android':
                    self.options.messenger.severitywrite(full_ssh_msg, "error")
                    self.options.messenger.failwrite(1)
                    os._exit(1)

        def ssh_keygen_check(output):
            for error_type in ['Permission denied (']:
                if error_type in output and self.product.get_layout_name() != 'android' and \
                    ('publickey' in output or 'password' in output):
                    return ssh_keygen(self.shell.get_machine(), self.shell.get_port())
            return False

        output = self.shell.get_remote_product_info()
        if output is None:
            if self.options.log_name and sys.platform == 'win32':
                ssh_log = self.options.log_name + 'ssh.log'
                if os.path.isfile(ssh_log):
                    lines = ''
                    try:
                        ssh_log_file = open(ssh_log, 'r', encoding=ENCODING)
                        lines = " ".join(ssh_log_file.readlines())
                        ssh_log_file.close()
                    except:
                        pass
                    ssh_keygen_status = ssh_keygen_check(lines)
                    if not ssh_keygen_status:
                        connection_check(lines)

            output = " ".join(self.shell.get_cmd_output( self._sh_cmd_wrapper(self._get_version_tool_path().split() + ['-V']) ))
            if ssh_keygen_status and self.shell.check_product_info(output, False):
                return True

        #plink could have empty output in failing authentication request
        if output.strip() == '':
            msg = "Cannot communicate with the target. Please check password-less authentication request."
            if self.product.get_layout_name() != 'android':
                msg = full_ssh_msg
            self.options.messenger.severitywrite(msg, "error")
            self.options.messenger.failwrite(1)
            logging.info(msg)
            os._exit(1)

        if 'not found' in output or 'No such file' in output:
            if 'loading' in output or 'required by' in output:
                self.options.messenger.severitywrite(output, "error")
                self.options.messenger.failwrite(1)
                logging.info(output)
                os._exit(1)

            if self.product.get_layout_name() == 'android':
                msg = "Cannot find product on the device. Enabling automatic installation..."
                self.options.messenger.severitywrite(msg, "info")
                logging.info(msg)
                install_product = True
            else:
                # Linux case
                ls_cmd = ['ls', '/lib/ld-linux-x86-64.so.2', '&&', 'echo', '\'LIB_FOUND\'', ';']
                ls_cmd += ['ls', '/lib64/ld-linux-x86-64.so.2', '&&', 'echo', '\'LIB64_FOUND\'', ';']
                output = " ".join(self.shell.get_cmd_output(ls_cmd))
                if not 'LIB64_FOUND' in output \
                    and 'LIB_FOUND' in output:
                    # yocto
                    msg = "Cannot run product on the target system at " + self.options.target
                    msg += ":" + self.product.install_dir + ".\n"
                    msg += "To make sure the dynamic linker is in the standard path, create the symlink /lib64/ld-linux-x86-64.so.2 to /lib/ld-linux-x86-64.so.2."
                    self.options.messenger.severitywrite(msg, "error")
                    self.options.messenger.failwrite(1)
                    logging.info(msg)
                    os._exit(1)

                if not self.options.deploy:
                    msg = "Cannot find product on the target system at " + self.options.target
                    msg += ":" + self.product.install_dir + ".\n"
                    msg += "Make sure VTune Profiler installation directory on the remote system option in the Analysis Target tab is set to the correct path. "
                    msg += "Alternatively, you may use the --target-install-dir option to specify the correct path from command line.\n"
                    self.options.messenger.severitywrite(msg, "error")
                    msg = "Press Deploy button to install the target package."
                    self.options.messenger.severitywrite(msg, "error")
                    logging.info(msg)
                    os._exit(1)
                install_product = True

        elif not '(build' in output:
            ssh_keygen_status = ssh_keygen_check(output)
            if ssh_keygen_status and self.shell.check_product_info(output, False):
                return True
            if not ssh_keygen_status:
                connection_check(output)
        else:
            is_android_layout = (self.product.get_layout_name() == 'android')
            if self.product.get_layout_name() == 'docker':
                install_product = True
            elif self.product.get_layout_name() == 'lxc':
                install_product = True

            if not self.shell.check_product_info(output, is_android_layout):
                if is_android_layout:
                    msg = "Package update on the device is required. Enabling automatic update..."
                    self.options.messenger.severitywrite(msg, "info")
                    logging.info(msg)
                    install_product = True
                else:
                    msg = "Detected VTune Profiler build #" + str(self.shell.get_target_product_build_number(output)) + " on the target system at " + self.options.target
                    msg += ":" + self.product.install_dir + " is incompatible with the build #" + str(self.shell.get_host_product_build_number()) + " on the host.\n"
                    msg += "Specify another target install directory or clean current "
                    msg += "to enable automatic installation process. " 
                    self.options.messenger.severitywrite(msg, "error")
                    self.options.messenger.failwrite(1)
                    logging.info(msg)
                    os._exit(1)

        #lazy installation of product
        if ssh_keygen_status:
            install_product = True 
        if install_product:
            self.options.package_command = 'install'
            installer = None
            if self.product.get_layout_name() == 'docker':
                installer = DockerPackageInstaller(self.options)
            elif self.product.get_layout_name() == 'lxc':
                installer = LxcPackageInstaller(self.shell, self.options)
            elif self.product.get_layout_name() == 'android':
                installer = AndroidPackageInstaller(self.options)
            elif self.product.get_layout_name() == 'linux' and self.options.deploy:
                installer = LinuxPackageInstaller(self.shell, self.options)

            if installer:
                installer.clean()
                installer.install()
            self.options.package_command = None
        return install_product

    def _collect_data(self, args, recursive=False):
        #cmd with no results directory
        no_result_dir_cmd = False
        if ('--event-list' in self.runss_args) \
            or ('--event-value-list' in self.runss_args)\
            or ('--ftrace-config-list' in self.runss_args)\
            or ('--atrace-config-list' in self.runss_args)\
            or ('--context-value-list' in self.runss_args)\
            or ('--find-bin-file' in self.runss_args)\
            or ('--md5sum' in self.runss_args):
            no_result_dir_cmd = True
            self.options.app_work_dir = None

        if self.options.deploy:
            return not self._check_product()

        self.runss_args += args
        # Create <result_dir>/config/runss.options
        self.options.remote_option_file = ""
        if self.option_file:
            remote_file = self.product.get_tmp_dir() + self.options.target + '_' + os.path.basename(self.remote_dir) +  '.opts'
            if self.shell.is_selinux():
                remote_file = '/data/local/tmp/%s/tmp/%s_%s.opts' % (PACKAGE_NAME, self.options.target, os.path.basename(self.remote_dir))
            if not recursive:
                #python subprocess.Popen Cannot run too long cmd. So, stay options file copying
                option_file_runss_options = []

                f = open(self.option_file, 'r', encoding=ENCODING)
                for line in f:
                     option_file_runss_options += [line.strip()]
                f.close()

                f = open(self.option_file + '_remote', 'w', encoding=ENCODING)
                skip_next = False
                application_params = False
                for line in self.runss_args + option_file_runss_options:
                     if skip_next:
                         skip_next=False
                         continue
                     if line == "--":
                         application_params = True
                         skip_next=False
                     elif not application_params and line in ["--result-dir","-r"]:
                         skip_next=True
                         continue
                     f.write(line + "\n")
                f.close()

                ret_code = self.shell.push(self.option_file + '_remote', remote_file)
                if ret_code != 0:
                    copy_cmd = 'scp'
                    if self.product.get_layout_name() == 'android':
                        copy_cmd = 'push'
                    msg = "Cannot copy %s to %s on target. " % (self.option_file  + '_remote', remote_file)
                    msg += 'Please make sure the %s command works.' % copy_cmd
                    if self.product.get_layout_name() != 'android':
                        msg += ' See the Troubleshooting help topic for more details.'
                    self.options.messenger.severitywrite(msg)
                    self.options.messenger.failwrite(1)
                    os._exit(1)

                self.runss_args = ["--result-dir", self.remote_dir, "--option-file", remote_file]
                self.options.remote_option_file = remote_file
            elif self.product.get_layout_name() == 'android':
                ret_code = self.shell.push(self.option_file + '_remote', remote_file)
        elif not no_result_dir_cmd:
            self._create_config_file(config_name='runss.options', args=self.runss_args)

        extra_args = {}
        # We need to do here extra insmod/rmmod to avoid problems with NMI
        # driver. By some reason it can be enabled and rmmod/insmod here is
        # an extra delay.
        # TODO: investigate how to avoid the problem completely. Probably
        # we should print a warning if NMI watchdog timer is enabled.
        if self.mic:
            pass
        else:
            if self.product.get_layout_name() == 'android' and not self.shell.is_root() and (self._is_ebs_collection() or self._is_pwr_collection()):
                self.options.messenger.severitywrite("This collection type cannot be started. Device is not in the root mode.")
                self.options.messenger.failwrite(1)
                os._exit(1)

            #check that vm is dalvik and jit properties
            if not no_result_dir_cmd and self.product.get_layout_name() == 'android':
                #enable/disable dynamic symbol resolving support
                self.shell.set_vm_prop()

            if self.target_pid:
                if (('--ptrace' in self.runss_args or self._get_option_value_from_option_file(self.options.option_file,  ["--ptrace"]) == 'cpu')):
                    #ptrace collector could not attach to tid 1
                    if str(self.target_pid) == '1':
                        message = "Failed to attach to the specified target process. "
                        message += "Please make sure the process exists and VTune Profiler process has enough permissions to attach to the target process. "
                        message += "See the Troubleshooting help topic for more details."
                        self.options.messenger.severitywrite(message)
                        self.options.messenger.failwrite(1)
                        os._exit(1)

                    if not self.shell.is_root():
                        package_name = self.shell.cat("/proc/" + str(self.target_pid) + "/cmdline")
                        if len(package_name):
                            package_name = str(package_name[0]).split('\x00')[0]
                            output = self.shell.get_cmd_output(["run-as", package_name, "id", ";", "pm", "path", package_name])
                            runas_id_output = output[0]
                            package_path = " ".join(output[1:])
                            if package_path:
                                if ('is not an application' in runas_id_output):
                                    msg = "Cannot run data collection for package '%s'." % package_name
                                    msg += " It is not an application."
                                    msg += " For more details, see product Release Notes."
                                    self.options.messenger.severitywrite(msg)
                                    self.options.messenger.failwrite(1)
                                    os._exit(1)
                                if ('is unknown' in runas_id_output):
                                    msg = "Cannot run data collection for package '%s'." % package_name
                                    msg += " A corrupted version of the run-as utility is detected on your Android device."
                                    msg += " For more details, see product Release Notes."
                                    self.options.messenger.severitywrite(msg)
                                    self.options.messenger.failwrite(1)
                                    os._exit(1)
                                if ('is not debuggable' in runas_id_output):
                                    self.options.messenger.severitywrite("Target application is not debuggable and cannot be profiled without debug flag 'android:debuggable'.")
                                    self.options.messenger.severitywrite("For more information, see http://developer.android.com/guide/topics/manifest/application-element.html")
                                    self.options.messenger.failwrite(1)
                                    os._exit(1)
                                #extra_args['run_as'] = ['run-as', package_name]

            if ('--ptrace' not in self.runss_args and self.shell.is_root()):
                self._insmod_drivers()
                if '--event-value-list' not in self.runss_args and not self._create_context_cfg():
                    self._rmmod_drivers()
                    self.options.messenger.severitywrite("Cannot create context cfg\n")
                    self.options.messenger.failwrite(1)
                    os._exit(1)
                retcode = self._call_runtool(self.runss_args)
                self._rmmod_drivers()
            else:
                with Multitarget(self.options, self.result_dir):
                    retcode = self._call_runtool(self.runss_args, extra_args=extra_args)
        clean_dirs = []
        if retcode in (0, 4):  # 4 need for duration detach
            if not no_result_dir_cmd:
                clean_dirs += self._copy_results()
                self._copy_modules()
        elif not no_result_dir_cmd:
            #stop finalization
            self.options.messenger.failwrite(retcode)

        if not recursive and self._check_product():
            return self._collect_data(args, recursive=True)

        if not no_result_dir_cmd:
            clean_dirs += self._copy_logs()

        if clean_dirs:
            rm_opts = "-r"
            if self.product.get_layout_name() == 'android':
                rm_opts = "-rf"
            self.shell.rm(*([rm_opts] + clean_dirs))

        if retcode != 0 and not self._check_product() and '--context-value-list' in self.runss_args:
            full_msg = 'Please, check that the command '
            try:
                full_msg += "'%s -V'" % (self.product.get_binary_path_with_arch("runss", self.shell.get_arch()))
            except:
                full_msg += "'%s -V'" % (self.product.get_binary_path("runss"))
            full_msg += " is run successfully on the target."
            self.options.messenger.severitywrite(message = full_msg, severity = "error")

        return retcode

    def copy_file(self, remote_path):
        if not os.path.exists(self.module_dir):
            os.makedirs(self.module_dir)

        local_path = self._pull_module(remote_path, self.module_dir, True)
        if not os.path.exists(local_path):
            return 1
        return 0

    def _is_cancel(self):
        #skip copying in cancel command case
        if os.path.exists(self.remoteConfigPath):
            remoteParser = OptionFileParser(self.remoteConfigPath)
            command = remoteParser.get_option_values(['--command'], True)
            if command == 'cancel':
                return True
        return False

    def _copy_results(self):
        #skip copying in cancel command case
        if self._is_cancel():
            return [self.remote_dir, self.options.remote_option_file]

        msg = "Copying result directory from the device"
        if self.options.option_file:
            processbar = EmptyProgressBar("")
            self.options.messenger.severitywrite(message = msg, severity = "info")
        else:
            processbar = ProgressBar(msg)
        processbar.start()

        remote_dir_tmp = self.remote_dir
        if self.shell.is_selinux():
            remote_dir_tmp = '/data/local/tmp/'
            remote_dir_tmp += os.path.basename(self.remote_dir)
            self.shell.call([
                             "rm", "-rf", remote_dir_tmp, ";",
                             "mv", self.remote_dir, remote_dir_tmp
                            ])
            ret = self.shell.rpull(remote_dir_tmp, self.result_dir)

            # we could not execute rpull. Probaly issue with file permissions
            # because mv don't change them
            if ret != 0:
                self.shell.call([
                             "cp", "-rf", remote_dir_tmp, remote_dir_tmp + "_tmp", ";",
                             "rm", "-rf", remote_dir_tmp, ";",
                             "mv", remote_dir_tmp + '_tmp', remote_dir_tmp,
                            ])
                ret = self.shell.rpull(remote_dir_tmp, self.result_dir)
        else:
            self.shell.rpull(remote_dir_tmp, self.result_dir)

        #fix for new adb
        incorrect_res_dir = os.path.join(self.result_dir, os.path.basename(remote_dir_tmp))
        if os.path.exists(incorrect_res_dir):
            for src in os.listdir(incorrect_res_dir):
                shutil.move(os.path.join(incorrect_res_dir, src), os.path.join(self.result_dir, src))
            shutil.rmtree(incorrect_res_dir, True)

#        self.shell.rm("-r", self.remote_dir, self.options.remote_option_file)
        result_data_dir = os.path.join(self.result_dir, "data.0")
        if self.target_pid and self.product.get_layout_name() == 'android':
            jit_pattern = re.compile("\.%s(-[0-9]+)?\.jit$" % self.target_pid)
            project_dir = "/data/amplxe/results/"
            ls_output = self.shell.ls(project_dir)
            logging.debug("list of jit files: %s", ls_output)
            for filename in ls_output:
                if jit_pattern.search(filename):
                    self.shell.pull(project_dir + filename, result_data_dir)
        processbar.stop()
        clean_dirs = [self.remote_dir, self.options.remote_option_file]
        if remote_dir_tmp != self.remote_dir:
            clean_dirs += [remote_dir_tmp]
        return clean_dirs

    def _copy_logs(self):
        #skip copying in cancel command case
        skip = self._is_cancel()

        msg = "Copying collection logs from the device."
        if self.options.option_file:
            processbar = EmptyProgressBar("")
            if not skip:
                self.options.messenger.severitywrite(message = msg, severity = "info")
        else:
            processbar = ProgressBar(msg)
        processbar.start()
        if os.path.exists(self.result_dir):
            dst_log_dir = os.path.join(self.result_dir, "log", "target")
        else:
            dst_log_dir =  self.host_log_dir

        if not os.path.exists(dst_log_dir):
            os.makedirs(dst_log_dir)

        src_log_dir = os.path.join(self.tmp_dir, self.tmp_log_dir_name)
#        self.shell.rpull(src_log_dir, dst_log_dir)
#        self.shell.rm("-r", src_log_dir, os.path.dirname(src_log_dir) + '/amplxe-log-*')

        if os.path.exists(os.path.join(dst_log_dir, "[vdso]")):
            os.remove(os.path.join(dst_log_dir, "[vdso]"))

        processbar.stop()

        #skip copying in cancel command case
        if skip:
            return [src_log_dir + '/[vdso]']
        return [src_log_dir, os.path.dirname(src_log_dir) + '/' + PRODUCT_PREFIX + '-log-*']

    def _copy_modules(self):
        if self.options.no_copy_modules:
            return

        if not os.path.exists(self.module_dir):
            os.makedirs(self.module_dir)

        msg = "Copying modules from the device."
        if self.options.option_file:
            processbar = EmptyProgressBar("")
            self.options.messenger.severitywrite(message = msg, severity = "info")
        else:
            processbar = ProgressBar(msg)
        processbar.start()
        result_data_dir = os.path.join(self.result_dir, "data.0")
        tracefiles  = glob.glob(os.path.join(result_data_dir, "*.tb6"))
        tracefiles += glob.glob(os.path.join(result_data_dir, "*.vtss"))
        tracefiles += glob.glob(os.path.join(result_data_dir, "*.vtss.aux"))
        tracefiles += glob.glob(os.path.join(result_data_dir, "*.pwr"))
        tracefiles += glob.glob(os.path.join(result_data_dir, "*.pt"))
        tracefiles += glob.glob(os.path.join(result_data_dir, "*.trace"))
        tracefiles += glob.glob(os.path.join(result_data_dir, "*.perf"))
        tracefiles += glob.glob(os.path.join(result_data_dir, "*.perf.sync"))
        tracefiles += glob.glob(os.path.join(result_data_dir, "*.events"))
        logging.debug("list of trace files: %s", tracefiles)

        cache_dir = self._prepare_cache_dir()

        if self.product.get_layout_name() == 'android':
            # FIXME: /lib/modules/*.ko it is specific of Android platform
            ls_output = self.shell.ls("/lib/modules/*.ko")
            logging.debug("list of kernel modules: %s", ls_output)
            for remote_path in ls_output:
                local_path = self._pull_module(remote_path, cache_dir)
                if os.path.isfile(local_path):
                    logging.debug("copy %s to %s", local_path, self.module_dir)
                    shutil.copy(local_path, self.module_dir)

        re_sysmodule = self.product.get_sysmodule_pattern()
        re_axemodule = re.compile(self.product.get_install_dir())

        # It is optimization. Look at '/' directory and construct the following
        # pattern: vmlinux|^/dir1|^/dir2... It will filter out most of all
        # trash.
        ls_output = self.shell.ls("/")
        logging.debug("list of directories/files from '/': %s", ls_output)
        escaped_list = ["vmlinux"] + [re.escape(x) for x in ls_output]
        module_pattern = "|^/".join(escaped_list)
        logging.debug("pattern for modules: %s", module_pattern)
        re_anymodule = re.compile(module_pattern)

        strings = set()
        for tracefile in tracefiles:
            strings.update(RunTool._extract_strings(tracefile))

        logging.debug("Unfiltered strings from tracefiles: %s", strings)
        strings = list(filter(re_anymodule.match, strings))
        logging.debug("Filtered strings from tracefiles: %s", strings)
        for remote_path in strings:
            if re_axemodule.match(remote_path):
                logging.warning("skip %s module from AXE package", remote_path)
                continue
            if remote_path.startswith("/dev/"):
                logging.warning("skip %s module from /dev/", remote_path)
                continue

            #if remore_path.startswith("/dev/"):
            #    logging.warning("skip %s pseudo file from /dev/", remote_path)
            #    continue

            # Several modules with the same name but with different pathes can
            # be in one process. Thus we can't use flat directory layout for
            # <result-dir>/all directory.
            remote_dir = os.path.dirname(remote_path)
            module_dir = os.path.join(self.module_dir, remote_dir[1:])

            if not os.path.exists(module_dir):
                os.makedirs(module_dir)

            # First try to find the module on local filesystem. Don't try to
            # cache the result. Module cache directory should contain only
            # modules from the device.
            local_path = self._search_file(remote_path)
            if local_path:
                logging.debug("copy %s to %s", local_path, module_dir)
                shutil.copy(local_path, module_dir)
            elif re_sysmodule.match(remote_path):
                local_path = self._pull_module(remote_path, cache_dir)
                if os.path.isfile(local_path):
                    logging.debug("copy %s to %s", local_path, module_dir)
                    shutil.copy(local_path, module_dir)
            else:
                self._pull_module(remote_path, self.module_dir)

            for ext in ['.dbg', '.pdb']:
                # Try to find separate debug file on local filesystem. Don't try
                # to cache the result. The idea is very useful for Android. For
                # example, some graphics libraries have such files.
                debug_file = remote_path.split('.so')[0] + ext
                local_path = self._search_file(debug_file)
                if local_path:
                    logging.debug("copy %s to %s", local_path, module_dir)
                    shutil.copy(local_path, module_dir)
        processbar.stop()

    def _search_file(self, remote_path):
        search_dirs = self.search_dirs
        for dir in search_dirs:
            if not os.path.isdir(dir):
                continue
            file_path = dir + '/'+ remote_path
            if os.path.isfile(file_path):
                return file_path
            file_path = os.path.join(dir, os.path.basename(remote_path))
            if os.path.isfile(file_path):
                return file_path
        return None

    def _pull_module(self, remote_path, local_dir, rewriteFile = False):
        local_path = local_dir + '/' + remote_path
        if sys.platform == "win32":
            if (remote_path.find("docker:") == 0 or remote_path.find("lxc:") == 0):
               if (self.options.target != "localhost"):
                   local_path = local_dir + '/' + remote_path.replace(":", "@").replace(os.sep, "/")

        #kallsyms is not usual file and could not be copied directly
        if remote_path == '/proc/kallsyms':
            self.shell.cp("-rf", remote_path, self.tmp_dir)
            remote_path = self.tmp_dir + '/kallsyms'
        if remote_path.endswith('.ko') or \
           remote_path == os.path.basename(remote_path) or \
           remote_path.startswith('/dev/') or \
           remote_path.startswith('/proc/'):
            runss_path = self._get_runss_path()

            kernel_opt = []
            KERNEL_VERSION=self.options.kernel_version
            if KERNEL_VERSION != 'unknown':
                kernel_opt = ['--kernel-version', KERNEL_VERSION]

            if self.product.get_layout_name() != 'android':
                md5info = self.shell.get_cmd_output([runss_path, '--find-bin-file', remote_path] + kernel_opt)
            else:
                tmp_log = tempfile.TemporaryFile('w+', encoding=ENCODING)
                retcode = self.shell._call_adb(['shell'] + [runss_path, '--find-bin-file', remote_path] + kernel_opt, stdout=tmp_log,
                    stderr=tmp_log)
                tmp_log.seek(0)
                md5info = [x.strip() for x in tmp_log.readlines() if x]
                logging.info("md5 info %s", " ".join(md5info))

            for record in md5info:
                if 'path:' in record:
                    remote_path = record.split(":")[1].strip()
                elif 'status:' in record:
                    status = record.split(":")[1].strip()
                    if status != 'SUCCESS':
                        remote_path = status
                    break

        if remote_path == 'ERROR_FILE_NOT_EXIST' or remote_path == 'ERROR_NOT_A_REGULAR_FILE':
            self.options.messenger.write("<data>&lt;bag status=&quot;ERROR_FILE_NOT_EXIST&quot;/&gt;</data>")
            return local_path

        if 'vmlinux' in os.path.basename(local_path) and 'vmlinuz' in os.path.basename(remote_path):
            self.options.messenger.write("<data>&lt;bag status=&quot;ERROR_FILE_NOT_EXIST&quot;/&gt;</data>")
            return local_path

        if not os.path.exists(local_path) or rewriteFile:
            directory = os.path.dirname(local_path)
            if not os.path.exists(directory):
                # pull module could be in parallel
                # and dir could be created in another process
                try:
                    os.makedirs(directory)
                except:
                    if not os.path.exists(directory):
                        return local_path

        if (remote_path.find("docker:") == 0 or remote_path.find("lxc:") == 0):
           if (self.options.target == "localhost"):
              self._get_file_from_containers(remote_path, directory, os.system, True)
           else:
              self._get_file_from_containers(remote_path, self.tmp_dir, self.shell.call, False)
              self.shell.pull(os.path.join(self.tmp_dir, os.path.basename(remote_path.split(":")[2])), local_path)
        else:
           self.shell.pull(remote_path, local_path, True)

        return local_path

    def _get_file_from_containers(self, container_path, dir_path, shell_function, string_command = True):
        container_type = container_path.split(":")[0]
        container_hash = container_path.split(":")[1]
        remote_path = container_path.split(":")[2].replace(os.sep, '/')
        if (container_type and container_type == "docker"):
            command = ["docker", "cp", container_hash + ":" + remote_path, dir_path]
            if string_command:
                command = " ".join(command)
            shell_function(command)
        elif (container_type and container_type == "lxc"):
            command = ["cp", "`lxc-config lxc.lxcpath`/" + container_hash + "/rootfs/" + remote_path, dir_path]
            if string_command:
                command = " ".join(command)
            shell_function(command)

    @staticmethod
    def _extract_strings(filepath):
        file = open(filepath, "rb")
        content = file.read(64*1024*1024)
        strings = []
        while content:
            strings += re.findall(b("([\x20-\x7e]{4,})[\n\0]"), content)
            # Don't lose strings between chunks. Here I believe that strings cannot be
            # more than 4096 bytes. It is possible that we will add an extra substring.
            # It isn't important.
            content = content[-4096:] + file.read(64*1024*1024)
            if len(content) <= 4096: break
        return [decode(x) for x in strings if x]

    def _prepare_cache_dir(self):
        uname_output = self.shell.uname("-a")
        serialno = self.shell.serialno()
        serialno = serialno.replace(':', '_')
        cache_dir = os.path.join(tempfile.gettempdir(), PRODUCT_PREFIX + "-runss.db.%s.%s"
            % (getpass.getuser(), serialno))
        uname_filepath = os.path.join(cache_dir, 'dev_uname.info.txt')

        if os.path.exists(cache_dir):
            logging.debug("%s cache directory exists.", cache_dir)
            if open(uname_filepath).read() != uname_output:
                logging.debug("Removing obsolete cache directory.")
                shutil.rmtree(cache_dir, True)

        if not os.path.exists(cache_dir):
            logging.debug("Creating %s cache directory.", cache_dir)
            logging.debug("uname -a for the device: %s", uname_output)
            os.makedirs(cache_dir)
            open(uname_filepath, "w").write(uname_output)

        return cache_dir

    def _get_runss_path(self, shell=False):
        if self.product.get_layout_name() == 'android':
            runss_path = self.product.get_binary_path("runss.sh")
            if shell:
                runss_path = self.product.get_shell_binary_path("runss.sh")
#            runss_path = '/data/local/tmp/com.intel.vtune/perfrun/bin/amplxe-runss.sh'

        # If 'runss.sh' helper script doesn't exist we use 'runss' binary.
        else:
            runss_path = self.product.get_binary_path("runss")
        return runss_path

    def _get_version_tool_path(self):
        if self.product.get_layout_name() == 'android':
            runss_path = self.product.get_binary_path("version.sh")
            if self.shell.is_selinux():
                runss_path = self.product.get_shell_binary_path("version.sh")
        # If 'runss.sh' helper script doesn't exist we use 'runss' binary.
        else:
            runss_path = self.product.get_binary_path("runss")
        return runss_path

    def _call_runtool(self, args, extra_args = {}, **kwargs):
        runss_path = self._get_runss_path()
        if self.shell.is_selinux() and \
           not 'run_as' in extra_args.keys():
            runss_path = self._get_runss_path(shell=True)

        log_dir = tmp_dir = os.path.join(self.tmp_dir, self.tmp_log_dir_name)
        if '--result-dir' in args:
            log_dir = self.remote_dir + '/log/target'

        log_level = []
        if self.log_level != None:
            log_level = [PRODUCT_PREFIX.upper() + "_LOG_LEVEL=" + self.log_level]

        experimental = []
        if self.experimental != None:
            experimental = [PRODUCT_PREFIX.upper() + "_EXPERIMENTAL=" + "".join(self.experimental.split())]
        elif 'sofia' in self.shell.get_platform() or 'sp9861e' in self.shell.get_platform() or 'sp9853i' in self.shell.get_platform():
            experimental = [PRODUCT_PREFIX.upper() + "_EXPERIMENTAL=sepsdk"]

        sepdk_home = []
        if self.sepdk_home != None:
            sepdk_home = [PRODUCT_PREFIX.upper() + "_SEPDK_HOME=" + self.sepdk_home]
        elif 'sofia' in self.shell.get_platform():
            sepdk_home = [PRODUCT_PREFIX.upper() + "_SEPDK_HOME=/system/bin/sepdk/bin"]
        elif 'sp9861e' in self.shell.get_platform():
            sepdk_home = [PRODUCT_PREFIX.upper() + "_SEPDK_HOME=/system/bin/sepdk/bin"]
        elif 'sp9853i' in self.shell.get_platform():
            sepdk_home = [PRODUCT_PREFIX.upper() + "_SEPDK_HOME=/system/bin/sepdk/bin"]

        options_file_echo = []

        #some ssh clients could copy file with 000 permissions, so we could not read options file
        options_file_chmod = []
        if self.option_file and self.product.get_layout_name() != 'android':
             options_file_chmod = ["chmod", "600", self.options.remote_option_file, ";"]

        chdir_to_tmp = [] # on not-rooted devices we could not cd to tmp and set BIN_DIR
        if self.shell.is_root():
            # Some programs are trying to write into the current directory. Thus
            # to avoid any problems with pemissions we "cd" into "tmp" directory.
            chdir_to_tmp = ["cd", self.tmp_dir, "&&"]

        if self.options.app_work_dir:
            quoted_app_work_dir = '\"' + self.options.app_work_dir + '\"'

            if self.options.app_work_dir.startswith('~/'):
                quoted_app_work_dir = '~/' +  '\"' + self.options.app_work_dir[2:] + '\"'

            chdir_to_tmp = ["cd", quoted_app_work_dir, "&&"]

        run_as = extra_args.get('run_as', [])

        version_tool_cmd = self._get_version_tool_path().split()
        if self.product.get_layout_name() != 'android':
            version_tool_cmd.append('-V')

        # try to install drivers on remote linux machine
        insmod_drivers = []
        if self.product.get_layout_name() == 'linux' and '--context-value-list' in self.options.runss_args and not os.getenv("FORCED_PERF"):
            insmod_drivers = ['if [ ${USER} = root ]; then %s ; fi ;' % (self.product.get_install_dir() + 'sepdk/src/insmod-sep >/dev/null 2>&1')]

        version_check = ["echo", "_pvi_", "1>&2", ";"] + version_tool_cmd + ["1>&2", ";", "echo", "/_pvi_", " 1>&2", ";"] + insmod_drivers
        version_check = self._sh_cmd_wrapper(version_check)

        mkdir = []
        if not '--md5sum' in args and not '--find-bin-file' in args:
            mkdir = ["mkdir", "-p", tmp_dir, ";"] + \
                    ["mkdir", "-p", log_dir, ";"]
        else:
            log_level = []
            version_check = []

        collection_cmd = self._sh_cmd_wrapper(
                            chdir_to_tmp +
                            [PRODUCT_PREFIX.upper() + "_LOG_DIR=" + log_dir] +
                            experimental +
                            sepdk_home +
                            log_level +
                            [runss_path] +  args
                        )

        full_cmd =  version_check + \
                    options_file_echo + \
                    options_file_chmod + \
                    mkdir + \
                    collection_cmd

        return self.shell.call( full_cmd,**kwargs)

    def _exists(self, path):
        return self.shell.call(["ls"] + [path], silent=True) == 0

    def _driver_paths(self):
        if 'sofia' in self.shell.get_platform() or 'sp9861e' in self.shell.get_platform() or 'sp9853i' in self.shell.get_platform():
            drv_paths = [
                            '/lib/modules/*',
                            '/vendor/lib/modules/*',
                            '/system/lib/modules/*',
                            self.product.drv_dir + "*",
                        ]

        else:
            drv_paths = [
                            self.product.drv_dir + "*",
                            '/lib/modules/*',
                            '/vendor/lib/modules/*',
                            '/system/lib/modules/*',
                        ]
        cmd = []
        for drv_path in drv_paths:
            cmd += ['ls', drv_path, ';']
        drv_list = self.shell.get_cmd_output(cmd)
        amplxe_drv_list = []

        sep = None
        sep_back = None
        for drv in drv_list:
            for split_drv in drv.split():
                drv = split_drv.strip()
                if 'sofia' in self.shell.get_platform():
                    if ('sep' + PRODUCT_SOFIA_VERSION in drv or 'pax' in drv or 'vtsspp' in drv) and drv.endswith('.ko'):
                        amplxe_drv_list.append(drv)
                elif 'sp9861e' in self.shell.get_platform() or 'sp9853i' in self.shell.get_platform():
                    if ('sep' + PRODUCT_VERSION or 'pax' in drv or 'socperf2' in drv) and drv.endswith('.ko'):
                        amplxe_drv_list.append(drv)
                else:
                    if ('sep' + PRODUCT_VERSION in drv) and drv.endswith('.ko'):
                        sep = drv
                    elif ('pax' in drv or 'vtsspp' in drv or 'socperf' in drv) and drv.endswith('.ko'):
                        amplxe_drv_list.append(drv)
        if sep:
            amplxe_drv_list.append(sep)
        elif sep_back:
            amplxe_drv_list.append(sep_back)
        return amplxe_drv_list

    def _find_driver(self, name, drv_paths):
        for drv_path in drv_paths:
            if name in drv_path:
                return drv_path
        return None

    def _insmod_drivers(self):
        def driver_load_order(driver_path):
            order = ['pax', 'socperf', 'sep', 'vtsspp']
            for index, name in enumerate(order):
                if name in driver_path:
                    return index
            logging.warning('Unknown driver %s, putting it in the back of the load order', driver_path)
            return len(order)

        if os.getenv("FORCED_PERF"):
            return

        if self.product.get_layout_name() != 'android' or not self.shell.is_root() or not self.useDrivers:
            return

        self.loaded_drivers = []

        drivers_aliases = {
#                              "socperf" : "socperf",
                              "pax"     : "pax",
                              "sep"     : "sep",
                              "vtsspp"  : "vtsspp",
                          }

        driver_paths = self._driver_paths()
        for driver_path in driver_paths:
            name = os.path.basename(driver_path)
            if 'socperf' in name:
                if not name in drivers_aliases.keys():
                    drivers_aliases[name] = name
        drivers_set = sum([[drivers_aliases[x]] for x in drivers_aliases.keys()], [])
        drivers = sum([[self._find_driver(x, driver_paths)] for x in drivers_set], [])
        drivers = sum([[x] for x in drivers if x], [])
        logging.debug("drivers on target device - " + str(drivers))

        skip_socperf = True
        for drv in drivers:
            if 'sep' + PRODUCT_VERSION in drv:
                skip_socperf = False
                break
        if skip_socperf:
            drivers = sum([[x] for x in drivers if not 'socperf' in x], [])

        self.loaded_drivers = []
        cmd = ['lsmod']
        lsmod_list = self.shell.get_cmd_output(cmd)
        for x in drivers:
            short_name = os.path.splitext(os.path.basename(x))[0]
            loaded = False
            for loaded_drivers in lsmod_list:
                short_loaded_name = loaded_drivers.split()[0]
                if short_name == short_loaded_name:
                    loaded = True
                    break
            if not loaded:
                self.loaded_drivers.append(x)

        drivers_to_insmod = sorted([x for x in self.loaded_drivers if x], key=driver_load_order)

        command = sum([["insmod", x, ";"] for x in drivers_to_insmod], [])

        self.loaded_drivers = sum([[os.path.splitext(os.path.basename(x))[0]] for x in self.loaded_drivers if x], [])

        if not command:
            return

        logging.debug("call insmod command \"" + " ".join(command) + "\"")
        if self.shell.call(command) != 0:
            self._rmmod_drivers(silent=True)
            if self.shell.call(command) != 0:
                self.options.messenger.severitywrite("Cannot load kernel modules - %s. \'insmod\' command is fail." %  " ".join(drivers))
                self.options.messenger.failwrite(1)
                os._exit(1)

    def _rmmod_drivers(self, silent = False):
        if os.getenv("FORCED_PERF"):
            return

        if self.product.get_layout_name() != 'android' or not self.shell.is_root() or not self.useDrivers:
            return

        if self.loaded_drivers:
            command = sum([["rmmod", x, ";"] for x in self.loaded_drivers if 'socperf' not in x ], [])
            #socperf should be rmmod the last
            command += sum([["rmmod", x, ";"] for x in self.loaded_drivers if 'socperf' in x ], [])

            status = self.shell.call(command)

            if silent:
                return

            if status != 0:
                self.options.messenger.severitywrite("Cannot unload kernel modules - %s. \'rmmod\' command is fail." % " ".join(self.loaded_drivers), "error")
                #ignore issues for kernel modules unloading
                #os._exit(1)
            self.loaded_drivers = []

    def _is_pwr_collection(self):
        return "--pwr-config" in self.runss_args

    def _is_itt_collection(self):
        return "--itt-config" in self.runss_args

    def _create_config_file(self, config_name, args):
        config_dir = os.path.join(self.result_dir, "config")
        config_file = os.path.join(config_dir, config_name)
        if not os.path.exists(os.path.dirname(config_file)):
            os.makedirs(os.path.dirname(config_file))
        if os.path.exists(config_file):
            os.remove(config_file)
        for argument in args:
            open(config_file, "a", encoding=ENCODING).write(argument.lstrip() + '\n')
        return config_file

    def _create_context_cfg(self):
        if '--context-value-list' in self.options.runss_args \
            or '--ftrace-config-list' in self.options.runss_args \
            or '--atrace-config-list' in self.options.runss_args \
            or '--event-value-list' in self.options.runss_args \
            or '--event-list' in self.options.runss_args \
            or self.options.option_file:
            return True

        config_dir = os.path.join(self.result_dir, "config")
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)

        runss_path = self._get_runss_path()
        self.ctx_value_list = self.shell.get_cmd_output(
            ['BIN_DIR=' + os.path.dirname(runss_path), runss_path, "--context-value-list"])
        logging.debug("context value list: %s", self.ctx_value_list)

        ctx_values_cfg = os.path.join(config_dir, 'context_values.cfg')
        if not os.path.exists(ctx_values_cfg):
            xml_file = '''<?xml version="1.0" encoding="UTF-8"?>
<bag xmlns:boolean="http://www.w3.org/2001/XMLSchema#boolean"
    xmlns:double="http://www.intel.com/2001/XMLSchema#double"
    xmlns:int="http://www.w3.org/2001/XMLSchema#int"
    xmlns:unsignedInt="http://www.w3.org/2001/XMLSchema#unsignedInt">
'''
            try:
                for line in self.ctx_value_list:
                    (key, value) = line.split(":", 1)
                    value = value.strip()
                    if self.mic and key == "PMU":
                        xml_file += '''
    <contextValue id="PMU" value="knc"/>'''
                    elif value == "true" or value == "false":
                        xml_file += """
    <contextValue id=\"%s\" boolean:value=\"%s\"/>""" % (key, value)
                    else:
                        xml_file += """
    <contextValue id=\"%s\" value=\"%s\"/>""" % (key, value)

                if self.product.get_layout_name() == 'android':
                    xml_file += '''
    <contextValue id="OS" value="Android"/>
    <contextValue id="pmuEventConfig" value="CPU_CLK_UNHALTED.REF:,INST_RETIRED.ANY:"/>'''
                else:
                    xml_file += '''
    <contextValue id="OS" value="Linux"/>
    <contextValue id="pmuEventConfig" value="CPU_CLK_UNHALTED:,INSTRUCTIONS_EXECUTED:"/>'''
                xml_file += '''
    <contextValue id="CLIENT_ID" value="CLI"/>
    <contextValue id="allowMultipleRuns" boolean:value="false"/>
    <contextValue id="analyzeSystemWide" boolean:value="false"/>
    <contextValue id="basicBlockAnalysis" boolean:value="true"/>
    <contextValue id="collectCallCounts" boolean:value="false"/>
    <contextValue id="collectMemBandwidth" boolean:value="false"/>
    <contextValue id="collectUserTasksMode" boolean:value="false"/>
    <contextValue id="cpuMask" value=""/>
    <contextValue id="dataLimit" int:value="100"/>
    <contextValue id="enableCallCountCollection" boolean:value="false"/>
    <contextValue id="enableLBRCollection" boolean:value="false"/>
    <contextValue id="enablePEBSCollection" boolean:value="false"/>
    <contextValue id="enableStackCollection" boolean:value="true"/>
    <contextValue id="enableVTSSCollection" boolean:value="true"/>
    <contextValue id="followChild" boolean:value="true"/>
    <contextValue id="followChildStrategy" value=""/>
    <contextValue id="goodFastFrameThreshold" double:value="100"/>
    <contextValue id="gpuCounters" value="off"/>
    <contextValue id="gpuCountersCollection" value=""/>
    <contextValue id="initialReport" value="summary"/>
    <contextValue id="initialViewpoint" value="%LightweightHotspotsViewpointName"/>
    <contextValue id="isGPUAnalysisAvailable" boolean:value="false"/>
    <contextValue id="mrteMode" value="auto"/>
    <contextValue id="runsa:enable" boolean:value="true"/>
    <contextValue id="slowGoodFrameThreshold" double:value="40"/>
    <contextValue id="targetDurationType" value="short"/>
    <contextValue id="targetType" value="launch"/>
    <contextValue id="useCountingMode" boolean:value="false"/>
    <contextValue id="useEventBasedCounts" boolean:value="false"/>
    <contextValue id="userTasksCollection" boolean:value="false"/>
</bag>'''
                open(ctx_values_cfg, 'w', encoding=ENCODING).write(xml_file)
            except:
                return False
        return True

class LocalRunTool(RunToolBase):
    def __init__(self, shell, options):
        RunToolBase.__init__(self, options)
        self.options = options
        #for local case we should use passed to the script arguments
        #remove target or target-system from commandline
        self.runss_args = options.runss_args
        self.shell = shell
        self._init(options)
        if sys.platform == "win32":
            self.product = WindowsProductLayout(options)
        else:
            self.product = LinuxProductLayout(options)

    def run(self):
        logging.debug("local run %s", self.runss_args)
        retcode = self._call_runtool(self.runss_args)
        return retcode

    def start_md5sum(self):
        logging.debug("local getting md5sum: %s", self.runss_args)
        retcode = self._call_runtool(self.runss_args)
        return retcode

    def start(self, args):
        logging.debug("start data collection: %s", args)
        return self._collect_data(args)

    def attach(self, identifier):
        logging.debug("attach to %s process", identifier)
        if isinstance(identifier, int):
            self.target_pid = identifier
            return self._collect_data(["--target-pid", str(identifier)])
        else:
            return self._collect_data(["--target-process", identifier])

    def mark(self):
        return self.execute("mark")

    def cancel(self):
        return self.execute("cancel")

    def pause(self):
        return self.execute("pause")

    def resume(self):
        return self.execute("resume")

    def detach(self):
        return self.execute("detach")

    def stop(self):
        return self.execute("stop")

    def execute(self, command):
        result_dir = []
        if self.options.result_dir:
            result_dir = ["--result-dir", self.options.result_dir]
        return self._call_runtool(self.runss_args + result_dir + ['-C', command])

    def _collect_data(self, args):

        full_args = self.runss_args + args

        if self.options.option_file:
             #need to know result dir for stop cmd
             result_dir = self._get_option_value_from_option_file(self.options.option_file,  ["-r", "--result-dir"])
             if result_dir:
                 full_args += ["--result-dir", result_dir]

             full_args += ["--option-file", self.options.option_file]

        retcode = self.shell.call(full_args)
        return retcode

    def copy_file(self, remote_path):
        return 1

    def _call_runtool(self, args, extra_args = {},**kwargs):
        return self.shell.call([self.product.get_binary_path("runss")] + self.runss_args + args, **kwargs)

#############################################################################################
debug = False
class MerDecoder():
    def __init__(self, binTraceFile, resultDir, importResults = False):
        self.binTraceFile = binTraceFile
        self.binTraceFileShort = os.path.basename(binTraceFile)
        self.resultDir = resultDir
        self.decoder = None

        script_dir = SCRIPT_DIR
        self.mer_config = (script_dir + '/../target/ghs/integrity_pointer.mc').replace('\\', '\\\\')

        self.messenger = InternalMessenger()

        self.importResults = importResults

    def initialize(self):
        self.gdump  = which("gdump")
        if not self.gdump:
            self.gdump = '/usr/ghs/comp/gdump'
            if sys.platform == 'win32':
                ghs_dir = 'C:\\GHS'
                if os.path.isdir(ghs_dir):
                    for product in os.listdir(ghs_dir):
                        if 'comp' in product:
                            self.gdump = os.path.join(ghs_dir, product, 'gdump.exe')
                            break
            if not os.path.exists(self.gdump):
                if debug:
                    print('Cannot find gdump. Please add [GHS_TOOLS]/comp to PATH and refinalize results.')
                return 1

        if not self.binTraceFile or not os.path.isfile(self.binTraceFile):
            if debug:
                print('Incorrect mer trace file path - %s' % self.binTraceFile)
            return 4

        if not self.resultDir or not os.path.isdir(self.resultDir):
            if debug:
                print('Incorrect decoded traces dir path - %s' % self.resultDir)
            return 5

        if not os.path.exists(self.mer_config):
            if debug:
                print("Cannot find integrity config file %s. Please contact product support to resolve this issue." % self.mer_config)
            return 2

        return 0

    def decode(self):
        if not (self.binTraceFile and os.path.exists(self.binTraceFile)):
            return 6

        gdump_mer_file = os.path.join(self.resultDir, self.binTraceFileShort + '.gdump')

        if not self._check_trace(self.binTraceFile, gdump_mer_file):
            if debug:
                print('Sync events were lost.')
            return 3

        try:
            os.remove(gdump_mer_file)
        except OSError as e:
            if debug:
                print('Could not remove mev files: %s, %s' % (gdump_mer_file, self.binTraceFile))
        return 0

    def _dump_gdump(self, gdump_file):
        dump_file = open(gdump_file, "wb")
        p = subprocess.Popen([self.gdump, '-v', self.binTraceFile, '-cfg="%s"' % self.mer_config],
                             stdout=dump_file, stderr=dump_file)
        dump_file.flush()
        dump_file.close()
        p.communicate()

    def _check_trace(self, trace_file, gdump_file):
        # we are waiting for our synchro events that should be dumped by EventAnalyzer
        for i in range(10):
            self._dump_gdump(gdump_file)
            if self.importResults or ftraceDumper(gdump_file, self.messenger).CheckSynchroEvents():
                if debug:
                    'Converting trace %s', self.binTraceFile
                ftraceDumper(gdump_file, self.messenger).DumpFtraceFile(self.importResults)
                return True
            time.sleep(1)

        return False

class threadInfo():
    def __init__(self, threadInfo = None):
        if threadInfo:
            self.tid  = None
            self.name = None
            self.processName = None
            self.priority = '0'
            self.status = 'D'
            self.setThreadInfo(threadInfo)
        else:
            self.tid  = '0'
            self.name = None
            self.processName = '<idle>'
            self.priority = '0'
            self.status = 'R'

    def setThreadInfo(self, threadInfo):
        info = threadInfo.splitlines()

        m = re.match(".*\),(?P<tid>\w+_\w+),", info[0])
        if m:
            self.tid = m.group('tid')
        if len(info) == 1: #construct thread from context switch
            self.priority = '0'
            self.processName = self.tid.split('_')[1]
            self.name = self.processName
            if self.tid == '00000000_00000000':
                self.processName = 'System'
        else:
            m = re.match(".*Pri=(?P<priority>\w+),(?P<process>.*)", info[1])
            if m:
                self.priority = int('0x' + m.group('priority'), 0)
                self.processName = m.group('process')

            self.name = "_".join(info[2].split())

        if debug:
            print(self.name)
            print(self.tid)
            print(self.processName)
            print(self.priority)

    def getTid(self):
         return self.tid

    def getStatus(self):
        return self.status
    def getName(self):
        return '%s@%s' % (self.processName, self.name)

    def setStatus(self, status):
        if status == "Ready":
            self.status = 'R'
        else:
            self.status = 'D'
        #if debug:
        #    print "Status was changed to %s" % self.status

class ftraceDumper():
    def __init__(self, traceFile, messenger):
        self.synchroEventsCount = 6
        self.messenger = messenger
        self.traceFile = traceFile
        self.ftraceFile = os.path.join(os.path.dirname(self.traceFile),
                                      'stdscr-%s.ftrace' % 123456)

        #ftrace file could not start from 0.0 time
        self.timeBase = 0.000001
        self.timeThreashold = 1000

        logging.info("EventAnalyzer trace file is %s", self.traceFile)
        logging.info("Generated ftrace file is %s", self.ftraceFile)

    def WriteFtraceCSwitch(self, f, timestamp, core, prevInfo, nextInfo):
        # Parameters offset should be consistent among all context switches, align it carefully
        prev_tid = int( '0x' + prevInfo.tid.split("_")[-1], 0)
        next_tid = int( '0x' + nextInfo.tid.split("_")[-1], 0)
        f.write(" %40.40s-%-12s[%03d] %.6f: sched_switch: prev_comm=%s prev_pid=%s prev_prio=%s prev_state=%s ==> next_comm=%s next_pid=%s next_prio=%s\n" % \
                   (prevInfo.getName().split("@")[0], prev_tid, core, timestamp, prevInfo.getName().split("@")[1], prev_tid, prevInfo.priority, prevInfo.status,
                    nextInfo.getName().split("@")[1], next_tid, nextInfo.priority))

    def DumpFtraceFile(self, importResults):
        f = open(self.ftraceFile, 'w')

        # Include idle pid 0 for handling gaps between switch-from/switch-to
        tidsInfo = {'0': threadInfo()}
        coreContextSwitches = {}
        pendingContextSwitches = {}

        bufferOverFlowEvent = False

        TimerSyncEvent = False
        TimerSyncEventCount = 0
        counter = 0
        readf = open(self.traceFile, "r")
        prevTimestamp = 0
        if readf:
            logging.debug("open %s", self.traceFile)
            content = readf.readlines()
            readf.close()
            syncTimestamps = []
            for x in range(len(content)):
               line = content[x]

               if not importResults and 'TimerSyncEvent' in line:
                   TimerSyncEventCount += 1
                   m = re.match(".* (?P<hextimestamp>\w+_\w+)\((?P<timestamp>.*)\),(?P<tid>\w+_\w+)", line)
                   mCol = re.match(".*timestamp=(?P<synctimestamp>\d+)", content[x + 1])
                   if m and mCol:
                       collectortimestamp = mCol.group('synctimestamp')
                       syncTimestamps.append(collectortimestamp)
                       timestamp = m.group('timestamp')
                       record = " %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: tsc=lookahead\n" % ('System', '0', self.timeBase + float(timestamp))
                       f.write(record)

                       if len(syncTimestamps) == self.synchroEventsCount / 2:
                           TimerSyncEvent = not TimerSyncEvent
                           #disable another records dump to ftrace file
                           if TimerSyncEventCount > self.synchroEventsCount / 2:
                               TimerSyncEvent = False

                           if TimerSyncEvent:
                               f.write(self.head(self.timeBase + float(timestamp), ",".join(syncTimestamps)))
                           else:
                               f.write(self.end(self.timeBase + float(timestamp), ",".join(syncTimestamps)))
                           syncTimestamps = []
                   else:
                       f.close()
                       if os.path.exists(self.ftraceFile):
                           os.remove(self.ftraceFile)
                       msg = "Cannot process a context switch trace. Please copy [install_folder]/target/ghs/integrity_pointer.mc to $HOME/.ghs/event_analyzer/."
                       if sys.platform == 'win32':
                           msg = "Cannot process a context switch trace. Please copy [install_folder]\\target\\ghs\\integrity_pointer.mc to %APPDATA%\\GHS\\event_analyzer\\."
                       self.messenger.severitywrite(msg)
                       self.messenger.failwrite(1)
                       os._exit(1)

#(662) 000000d9_c80468df(1.8226146060),ffff8000_01639000,UserEvent,VtuneInfoEvent(0x4/0x1001)
               if 'VtuneInfoEvent' in line and (TimerSyncEvent  or importResults):
                   m = re.match(".* (?P<hextimestamp>\w+_\w+)\((?P<timestamp>.*)\),(?P<tid>\w+_\w+).*,(?P<subtype>.*)\(", line)
                   mCol = re.match(".*timestamp=(?P<collectortimestamp>\d+)", content[x + 1])
                   if m and mCol:
                       #42,9754549924888,9754549924888,1,1
#                       collectortimestamp = int('0x' + "".join(m.group('hextimestamp').split('_')), 0)
                       collectortimestamp = int(mCol.group('collectortimestamp'))
                       tid = m.group('tid')


#(9482) 00000fc4_007127f9(0.7476482168),00000000_00000000,UserEvent,Discontinuity(0x4/0xfffe)
#    Extra Data(29 bytes): EVENT STREAM BUFFER OVERFLOW
#    Raw Extra Data(29 bytes): 0x4556454e,0x54205354,0x5245414d,0x20425546,0x46455220,0x4f564552,0x464c4f57,0x00
               if 'Discontinuity' in line:
                       counter += 1
                       record = "CPU:0 [LOST %s EVENTS]\n" % str(counter)
                       f.write(record)

#(3) 00000000_00000000(0.0000000000),ffff8000_01607000,Refresh,TaskNameRefresh(0x6/0xa)
#   Extra Data(68 bytes): Pri=0,multi_login_net_server_kernel
#Idle0
#   Raw Extra Data(68 bytes): 0x00000000,0x6d756c74,0x695f6c6f,0x67696e5f,0x6e65745f,0x73657276
               if 'TaskNameRefresh' in line:
                   if x + 2 > len(content):
                       os._exit('Incorrect trace format for %s' % self.traceFile)
                   line += content[x + 1] + content[x + 2]
                   thrInfo = threadInfo(line)
                   tidNumber = thrInfo.getTid()
                   tidsInfo[tidNumber] = thrInfo

#(96) 000005eb_d2ba1a04(0.0174402054),ffff8000_00d21000,StatusChange,Ready(0x5/0x0)
               if 'StatusChange' in line:
                   m = re.match(".*\),(?P<tid>\w+_\w+),.*,(?P<status>\w+)\(", line)
                   if m:
                       tid = m.group('tid')
                       if not tid in tidsInfo.keys():
                           thrInfo = threadInfo(line)
                           tidNumber = thrInfo.getTid()
                           tidsInfo[tidNumber] = thrInfo
                       tidsInfo[tid].setStatus(m.group('status'))

#(69) 00000000_00000000(0.0000000000),ffff8000_01607000,ContextSwitch,TaskChange(0x1/0x0)
#   Extra Data(4 bytes): CoreId=0
               if (TimerSyncEvent  or importResults) and 'ContextSwitch' in line:
                   if x + 1 > len(content):
                       os._exit('Incorrect trace format for %s' % self.traceFile)

                   m = re.match(".*\((?P<timestamp>.*)\),(?P<tid>\w+_\w+)", line)
                   if m:
                       nextTid = m.group('tid')
                       timestamp = m.group('timestamp')
                       if importResults and (float(timestamp) - prevTimestamp) > self.timeThreashold:
                           continue
                       else:
                           prevTimestamp = float(timestamp)
                   coreinfo = content[x + 1]
                   m = re.match(".*CoreId=(?P<core>\w+)", coreinfo)
                   if not m:
                       f.close()
                       if os.path.exists(self.ftraceFile):
                           os.remove(self.ftraceFile)
                       msg = "Cannot process a context switch trace. Please copy [install_folder]/target/ghs/integrity_pointer.mc to $HOME/.ghs/event_analyzer/."
                       if sys.platform == 'win32':
                           msg = "Cannot process a context switch trace. Please copy [install_folder]\\target\\ghs\\integrity_pointer.mc to %APPDATA%\\GHS\\event_analyzer\\."
                       self.messenger.severitywrite(msg)
                       self.messenger.failwrite(1)
                       os._exit(1)

                   if m:
                       core = int(m.group('core'))
                       if not core in coreContextSwitches:
                           coreContextSwitches[core] = nextTid
                       else:
#    amplxe-runss-5717  [001] d..3 0.218896: sched_switch: prev_comm=amplxe-runss prev_pid=5717 prev_prio=120 prev_state=S ==> next_comm=swapper/1 next_pid=0 next_prio=120
                            tidInfo = tidsInfo[coreContextSwitches[core]]
                            if not nextTid in tidsInfo.keys():
                               thrInfo = threadInfo(line)
                               tidsInfo[nextTid] = thrInfo
                            nextTidInfo = tidsInfo[nextTid]
                            timestamp = self.timeBase + float(timestamp)
#                            f.write(line + "\n")
                            for ctxCore, ctxTid in coreContextSwitches.items():
                                if ctxTid == nextTid:
                                    # The next task havent officially given up its core - generate switch-from event for it
                                    self.WriteFtraceCSwitch(f, timestamp, ctxCore, tidsInfo[ctxTid], tidsInfo['0'])
                                    coreContextSwitches[ctxCore] = '0'

                            self.WriteFtraceCSwitch(f, timestamp, core, tidInfo, nextTidInfo)
                            coreContextSwitches[core] = nextTid
                            tidsInfo[coreContextSwitches[core]].setStatus("Ready")
        f.close()

        processes = {}
        all_tids = []
        for tid in tidsInfo.keys():
            if not tidsInfo[tid].processName in processes.keys():
                processes[tidsInfo[tid].processName] = []
            tid_number = str(int( '0x' + tidsInfo[tid].getTid().split("_")[-1], 0))
            processes[tidsInfo[tid].processName].append(tid_number)
            all_tids.append(tid_number)

        record  = ""
        globalTidNumber = 2
        for process in processes.keys():
            while globalTidNumber in all_tids:
                globalTidNumber += 1
            record += self.WriteProcessInfo(f, process, processes[process], globalTidNumber)
            globalTidNumber += 1

        f = open(self.ftraceFile, 'r+')
        content = f.read()
        f.seek(0, 0)
        end = ''
        if importResults:
            time = 'utc'
            record += " %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: %s=lookahead\n" % ('System', '0', self.timeBase, time)
            record += " %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: %s=lookahead\n" % ('System', '0', self.timeBase, time)
            record += " %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: %s=lookahead\n" % ('System', '0', self.timeBase, time)
            synctime = int((self.timeBase) * 10000000000)
            record += self.head(self.timeBase, '%s,%s,%s' % (synctime,synctime + 1,synctime + 2), time)
            end = " %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: %s=lookahead\n" % ('System', '0', self.timeBase + prevTimestamp, time)
            end += " %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: %s=lookahead\n" % ('System', '0', self.timeBase + prevTimestamp, time)
            end += " %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: %s=lookahead\n" % ('System', '0', self.timeBase + prevTimestamp, time)
            synctime = int((self.timeBase + prevTimestamp) * 10000000000)
            end += self.head(self.timeBase + prevTimestamp, '%s,%s,%s' % (synctime,synctime + 1,synctime + 2), time)
        f.write(record + content + end)
        f.close()

    def WriteProcessInfo(self, f, process, tids, pid):
        # Parameters offset should be consistent among all context switches, align it carefully
        record = " %40.40s-%-12s[000] %.6f: vtune_proc_info: pid=%s cmdline=%s\n" % ('System', '0', self.timeBase, pid, process)
        record += " %40.40s-%-12s[000] %.6f: vtune_tid2pid: pid=%s tids=%s\n" % ('System', '0', self.timeBase, pid, ",".join(tids))
        return record

    def CheckSynchroEvents(self):
        TimerSyncEventCount = 0
        UserEventCount = 0
        readf = open(self.traceFile, "r")
        if readf:
            if debug:
                print("open %s" % self.traceFile)
            content = readf.readlines()
            readf.close()
            for x in range(len(content)):
               line = content[x]
               if 'TimerSyncEvent' in line:
                   TimerSyncEventCount += 1
               if 'UserEvent' in line and '(0x4/0x1000)' in line:
                   UserEventCount += 1
        if TimerSyncEventCount != self.synchroEventsCount:
            if UserEventCount == self.synchroEventsCount:
               msg = "Cannot process a context switch trace. Please copy [install_folder]/target/ghs/integrity_pointer.mc to $HOME/.ghs/event_analyzer/."
               if sys.platform == 'win32':
                   msg = "Cannot process a context switch trace. Please copy [install_folder]\\target\\ghs\\integrity_pointer.mc to %APPDATA%\\GHS\\event_analyzer\\."
               self.messenger.severitywrite(msg)
               self.messenger.failwrite(1)
               return False
            return False
        return True

    def head(self, timestamp, collectortimestamp, time='tsc'):
        head = ' %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: %s=%s\n'
        return head % ( 'System', '1', timestamp, time, collectortimestamp)

    def end(self, timestamp, collectortimestamp, time='tsc'):
        end = ' %40.40s-%-12s[000] %.6f: tracing_mark_write: vtune_time_sync: %s=%s\n'
        return end % ('System', '0', timestamp, time, collectortimestamp)
#############################################################################################
def get_last_result_dir(pattern):
    if os.path.exists(pattern):
        return pattern

    directory = os.path.join(os.path.dirname(pattern), 
        os.path.basename(pattern).replace("@", "[0-9]"))
    result_dirs = sorted(glob.glob(directory))
    if result_dirs:
        return os.path.abspath(result_dirs[-1])
    else:
        return None

def get_next_result_dir(pattern):
    directory = get_last_result_dir(pattern)
    if directory:
        directory = directory[-len(pattern):]
        result_dir = []
        is_done = False
        for (x, y) in zip(reversed(pattern), reversed(directory)):
            if not is_done and x == "@":
                if y == "9":
                    result_dir.append("0")
                else:
                    result_dir.append(str(int(y) + 1))
                    is_done = True
            else:
                result_dir.append(y)
        result_dir.reverse()
        result_dir = "".join(result_dir)
    else:
        result_dir = pattern.replace("@", "0")

    return os.path.abspath(result_dir)

def add_search_dir(option, opt, value, parser):
    if not parser.values.search_dir:
        parser.values.search_dir = []
    parser.values.search_dir += value.split(",")

def add_runss_args(option, opt, value, parser):
    if not parser.values.runss_args:
        parser.values.runss_args = []
    parser.values.runss_args += [opt]
    if value or isinstance(value, int):
        parser.values.runss_args += [str(value)]

def create_itt_marker(package_name, isRooted, bridge):
    marker_file = "/data/data/%s/com.intel.itt.collector_lib" % package_name
    run_as = [] if isRooted else ["run-as", package_name]

    touch = []
    for suffix in ['', '32', '64']:
        touch_file = marker_file if suffix == '' else marker_file + '_' + suffix
        if suffix == '':
            itt_path = "/data/data/%s/intel/libittnotify.so" % PACKAGE_NAME
        else:
            itt_path = "/data/data/%s/perfrun/lib%s/runtime/libittnotify.so" % (PACKAGE_NAME, suffix)

        touch += [
                 "touch", touch_file, ";", "echo", "-n",
                 itt_path,
                 ">", touch_file, ";"
                ]

    cmd_marker_file = '""' + " ".join(run_as + ["sh", "-c", "'"] + touch + ["'"]) + '""'

    process = subprocess.Popen([bridge,"shell", cmd_marker_file])
    process.communicate()
    retcode = process.poll()
    return retcode

def remove_itt_marker(package_name, isRooted, bridge):
    marker_file = "/data/data/%s/com.intel.itt.collector_lib" % package_name
    remove_files = []
    for suffix in ['', '32', '64']:
        remove_files += [marker_file if suffix == '' else marker_file + '_' + suffix]

    cmd_marker_file = '""' + " ".join(["run-as", package_name, "rm"] + remove_files) + '""'
    if isRooted:
        cmd_marker_file = '""' + " ".join(["rm"] + remove_files) + '""'
    process = subprocess.Popen([bridge,"shell", cmd_marker_file])
    process.communicate()
    retcode = process.poll()
    return retcode

def find_free_port(messenger):
    try:
        import socket
    except:
        messenger.write("Unable to load socket module.")
        os._exit(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    port = s.getsockname()[1]
    if s:
        s.close()
    if port:
        return port
    raise Exception("Cannot find open port.")

def initializeParser():
    package_installation = False
    #AMPLXE_INSTALL_DEVICE_PACKAGE will be set in installation wrapper to hide collection options
    #and amplxe-runss.py script will be look like installation script only
    if os.getenv(PRODUCT_PREFIX.upper() + '_INSTALL_DEVICE_PACKAGE', '0') == '1':
        package_installation = True
    if package_installation:
        parser = OptionParser(usage="Usage: " + PRODUCT_PREFIX + "-androidreg{.bat|.sh} --package-command=<install|uninstall|update|build> [--use-cache] [--with-drivers] [--jitvtuneinfo]")
    else:
        parser = OptionParser(usage = "Usage: %prog [options] [[--] <application> [<args>]]")

    collection_group = OptionGroup(parser, "Collection options")
    collection_group.add_option("-r", "--result-dir",
                        metavar="DIRECTORY",
                        default="r@@@",
                        dest="result_dir",
                        help="Specify the directory used for creating the data collection results.")

    collection_group.add_option("--target-process",
                        metavar="NAME",
                        dest="target_process",
                        help="Specify the name for the process to which data collection should be attached.")

    collection_group.add_option("--target", "--target-system",
                        metavar="host",
                        dest="target",
                        default="android",
                        help="Specify target for data collection.")

    collection_group.add_option("--target-install-dir",
                        metavar="host",
                        dest="install_dir",
                        help="Specify target installation folder.")

    collection_group.add_option("--target-tmp-dir",
                        metavar="host",
                        dest="target_tmp_dir",
                        help="Specify target tmp folder.")

    collection_group.add_option("--log-folder",
                        metavar="host",
                        dest="log_folder",
                        help="Specify host log folder.")

    collection_group.add_option("--app-working-dir",
                        metavar="host",
                        dest="app_work_dir",
                        help="Specify application working dir.")

    collection_group.add_option("--target-pid",
                        metavar="PID",
                        type="int",
                        dest="target_pid",
                        help="Specify ID for the process to which data collection should be attached.")

    collection_group.add_option("--detached-mode", "--unplugged-mode",
                    action="store_true",
                    default=False,
                    dest="detached_mode",
                    help="Enable detached mode.")

    collection_group.add_option("--no-detached-mode",
                        action="store_false",
                        dest="detached_mode",
                        help="Disable detached mode.")

    collection_group.add_option("-C", "--command",
                        type="choice",
                        choices=["pause", "resume", "detach", "stop", "mark", "cancel"],
                        help="Process control command for a given result directory. " +
                        "Possible commands: " +
                        "pause - pause profiling all processes for a given result directory; " +
                        "resume - resume profiling all processes for a given result directory; " +
                        "stop - stop data collection; " +
                        "mark - put a discrete mark into the data being collected; " +
                        "detach - detach from a given result directory.")

    collection_group.add_option("--no-modules",
                    action="store_true",
                    default=False,
                    dest="no_copy_modules",
                    help="Don't copy modules from target device.")

    collection_group.add_option("--module-dir",
                        metavar="DIRECTORY",
                        default="",
                        dest="module_dir",
                        help="Specify the directory used for copying modules from target device.")

    collection_group.add_option("--search-dir",
                        type="string",
                        metavar="DIRECTORY",
                        dest="search_dir",
                        action="callback",
                        callback=add_search_dir,
                        help="Specify list of host directories where to search modules.")

    collection_group.add_option("-v", "--verbose",
                        action="store_true",
                        default=False,
                        dest="verbose",
                        help="Print additional information.")

    collection_group.add_option("--option-file",
                        type="string",
                        metavar="FILE",
                        help="Specify the path to the option file as <string>. " +
                        "Options from the specified file are read and applied. If options given" +
                        " on the command line conflict with options given in the file, the " +
                        "command line options overwrite the conflicting options read from the " +
                        "file. To specify an option name and its value, use equal sign, like " +
                        "\"name=value\", or put the option name and the option value on " +
                        "separate lines.")

    collection_group.add_option("--pwr-config",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        metavar="CONFIG",
                        help="Specify types of power data to be collected. " +
                        "Possible values: " +
                        "sleep - C-state information; " +
                        "frequency - P-state information; " +
                        "ktimer - kernel-level call stack path used to schedule a timer causing a C-state break.")

    collection_group.add_option("--sys-config",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        metavar="CONFIG",
                        help="Specify types of system data to be collected. " +
                        "Possible values: " +
                        "cswitch - collect context switch information.")

    collection_group.add_option("--itt-config",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        metavar="CONFIG",
                        help="Specify a sub-set of ITT API to collect. " +
                        "Possible values: all, frame, event, task, counter, preload.")

    collection_group.add_option("--start-paused",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        help="Start data collection in 'paused' mode. To re-start the " +
                        "data collection, issue the resume command.")

    collection_group.add_option("--resume-after",
                        type="int",
                        dest="runss_args",
                        action="callback",
                        metavar="MILLISECONDS",
                        callback=add_runss_args,
                        help="Specify the delay in milliseconds as integer to delay " +
                        "the data collection while the application is executing.")

    collection_group.add_option("--data-limit",
                        type="int",
                        dest="runss_args",
                        action="callback",
                        metavar="MB",
                        callback=add_runss_args,
                        help="Limit amount of data collected with the given value (in MB).")

    collection_group.add_option("-d", "--duration",
                        type="int",
                        dest="runss_args",
                        action="callback",
                        metavar="SECONDS",
                        callback=add_runss_args,
                        help="Specify duration for the collection in seconds.")

    collection_group.add_option("-i", "--interval",
                        type="int",
                        dest="runss_args",
                        action="callback",
                        metavar="MILLISECONDS",
                        callback=add_runss_args,
                        help="Specify an interval of data collection (for example, " +
                        "sampling) in milliseconds.")

    collection_group.add_option("--bts-count",
                        type="int",
                        dest="runss_args",
                        action="callback",
                        metavar="NUMBER",
                        callback=add_runss_args,
                        help="Specify the number of BTS records collected after each " +
                        "sample or context switch.")

    collection_group.add_option("--pmu-config", "--event-config",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        metavar="CONFIG",
                        callback=add_runss_args,
                        help="Perform data collection for the events.")

    collection_group.add_option("--chipset-event-config",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        metavar="CONFIG",
                        callback=add_runss_args,
                        help="Perform data collection for the chipset events.")

    collection_group.add_option("--event-list",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        help="List events for which a sampling data collection can be " +
                        "performed on this platform.")

    collection_group.add_option("--context-value-list",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        help="Display possible context values.")

    collection_group.add_option("--deploy",
                        action="store_true",
                        default=False,
                        dest="deploy",
                        help="Enable package deploy on the target.")

    collection_group.add_option("--ui-output-fd",
                        type="string",
                        help="Output fd.")

    collection_group.add_option("--ui-output-format",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        help="Output format.")

    collection_group.add_option("--allow-multiple-runs",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        help="Disable timer- or trigger-based event multiplexing.")

    collection_group.add_option("--pmu-stack",
                        action="store_true",
                        default=True,
                        dest="pmu_stack",
                        help="Enable collection of stacks together with PMU samples.")

    collection_group.add_option("--no-pmu-stack",
                        action="store_false",
                        dest="pmu_stack",
                        help="Disable collection of stacks together with PMU samples.")

    collection_group.add_option("--sample-after-multiplier",
                        type="float",
                        dest="runss_args",
                        action="callback",
                        metavar="DOUBLE",
                        callback=add_runss_args,
                        help="Specify the sample after multiplier as <double>. " +
                        "This multiplier modifies the sample after value " +
                        "for all the events specified in --event-config " +
                        "option. The values can range from 0.1 to 100.0.")

    collection_group.add_option("--cpu-mask",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        metavar="STRING",
                        callback=add_runss_args,
                        help="Specify which CPU(s) <string> to collect data on. " +
                        "For example, specify \"2-8,10,12-14\" to sample " +
                        "only CPUs 2 through 8, 10, and 12 through 14.")

    collection_group.add_option("--stdsrc-config",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        metavar="STRING",
                        callback=add_runss_args,
                        help="Enable etw/ftrace collector. Possible values: cswitch, igfx")

    collection_group.add_option("--etw-config",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        metavar="STRING",
                        callback=add_runss_args,
                        help="Enable etw collector.")

    collection_group.add_option("--ptrace",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        metavar="STRING",
                        callback=add_runss_args,
                        help="Enable driver-less Hotspots data collection. Possible values: cpu.")

    collection_group.add_option("--stack-size",
                        type="int",
                        dest="runss_args",
                        action="callback",
                        metavar="NUMBER",
                        callback=add_runss_args,
                        help="Specify the number of pages during a raw stack processing. ")

    collection_group.add_option("--stack",
                        action="store_true",
                        default=True,
                        dest="stack",
                        help="Enable collection of stacks.")

    collection_group.add_option("--no-stack",
                        action="store_false",
                        dest="stack",
                        help="Disable collection of stacks.")

    collection_group.add_option("--stackwalk",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        callback=add_runss_args,
                        metavar="CONFIG",
                        help="Specify stack unwinding method."
                        "Possible values: online - unwind stacks during collection; offline - unwind stacks after collection is finished.")

    collection_group.add_option("--mrte-mode",
                      type="choice",
                      choices=["auto", "native", "managed", "mixed"],
                      dest="mrte_mode",
                      default="auto",
                      help="Specify Java/.NET collection mode." +
                      "Possible values: auto, native, managed, mixed.")

    collection_group.add_option("--profiling-signal",
                        type="int",
                        dest="runss_args",
                        action="callback",
                        metavar="SIGNUM",
                        callback=add_runss_args,
                        help="Specify a signal to be used for driver-less Hotspots data collection. Default is 38.")

    collection_group.add_option("--adb-path",
                        default=None,
                        type="string",
                        dest="adb_path",
                        help="Specify a path to the adb executable if it is not reachable from the PATH environment variable.")


    if not package_installation:
        parser.add_option_group(collection_group)

    internal_group = OptionGroup(parser, "Internal options")

    internal_group.add_option("-m", "--mer-trace",
                        metavar="NAME",
                        dest="mer_trace",
                        help="Specify the mer trace path.")

    internal_group.add_option("--import",
                  action="store_true",
                  default=False,
                  dest="import_results",
                  help="import decoding files.")

    internal_group.add_option("--get-android-devices","--get-devices",
                  action="store_true",
                  default=False,
                  dest="get_devices",
                  help="get list of devices. Avalable for android target only.")

    internal_group.add_option("--get-package-list",
                  action="store_true",
                  default=False,
                  dest="get_package_list",
                  help="get list of packages. Avalable for android target only.")

    internal_group.add_option("--get-process-list",
                  action="store_true",
                  default=False,
                  dest="get_process_list",
                  help="get list of processes.")

    internal_group.add_option("--event-value-list",
                  dest="runss_args",
                  action="callback",
                  callback=add_runss_args,
                  help="List events for which a sampling data collection can be " +
                  "performed on this platform.")

    internal_group.add_option("--platform-type",
                  type="int",
                  action="callback",
                  callback=add_runss_args,
                  dest="runss_args",
                  help="Specify platform type for --event-value-list.")

    internal_group.add_option("--ftrace-config-list",
                  dest="runss_args",
                  action="callback",
                  callback=add_runss_args,
                  help="List Linux Ftrace subsystem events.")

    internal_group.add_option("--atrace-config-list",
                  dest="runss_args",
                  action="callback",
                  callback=add_runss_args,
                  help="List Android framework events.")

    internal_group.add_option("--copy-file",
                          default="",
                          dest="target_file",
                          help="Specify moudule name for copying from target device.")

    internal_group.add_option("--md5sum",
                      type="string",
                      dest="runss_args",
                      action="callback",
                      callback=add_runss_args,
                      help="Display md5sum.")

    internal_group.add_option("--find-bin-file",
                      type="string",
                      dest="runss_args",
                      action="callback",
                      callback=add_runss_args,
                      help="Locate binary file.")

    internal_group.add_option("--container-result-dir",
                          default="",
                          dest="container_result_dir",
                          help="Specify directory in result directory for copy results from container.")

    internal_group.add_option("--is-accessible",
                          default="",
                          dest="is_accessible",
                          help="check access of container cl should have cl value")

    install_group = OptionGroup(parser, "Package installation options")
    install_group.add_option("--package-command",
                      type="choice",
                      choices=['install', 'uninstall', 'update', 'build'],
                      dest="package_command",
                      default=None,
                      help="choose package installation command - " +
                      "install, uninstall or build. ")
    install_group.add_option("--with-drivers",
                      action="store_true",
                      default=False,
                      dest="build_drivers",
                      help="build drivers (if your image doesn't have VTSS++ & SEP 3.xx drivers)")
    install_group.add_option("--kernel-src-dir",
                      metavar="DIRECTORY",
                      default=os.environ.get("ANDROID_KERNEL_SRC_DIR", None),
                      dest="kernel_src_dir",
                      help="directory of the configured kernel source tree")
    install_group.add_option("--kernel-version",
                      action="store",
                      type="string",
                      default=os.environ.get("KERNEL_VERSION", "unknown"),
                      dest="kernel_version",
                      help="version string of kernel")
    install_group.add_option("--use-cache",
                      action="store_true",
                      default=False,
                      help="use <cache> directory after 'build' command")
    install_group.add_option("--jitvtuneinfo",
                      type="choice",
                      choices=["jit", "src", "dex", "none", None],
                      default=None,
                      help="information about java byte code and source code; " +
                      "possible values: jit, src, dex, none. ")

    install_group.add_option("--container-hash",
                      action='store',
                      type="string",
                      default=None,
                      help="Container hash")

    itt_group = OptionGroup(parser, "User tasks instrumentation options")
    itt_group.add_option("--enable-itt-attach",
                      action="store",
                      type="string",
                      default=None,
                      dest="enable_itt_package_name",
                      help="enable itt attach for package")
    itt_group.add_option("--disable-itt-attach",
                      action="store",
                      type="string",
                      default=None,
                      dest="disable_itt_package_name",
                      help="disable itt attach for package")
    internal_group.add_option("--run_tpss",
                  action="store_true",
                  default=False,
                  dest="run_tpss",
                  help="run tpss analyse in container")

    if package_installation:
        parser.add_option_group(install_group)
        parser.add_option_group(itt_group)

    return parser

def handleAndroidPckgCommand(options):
    if not checkAdb(options):
        return 1

    package = AndroidPackageInstaller(options)

    if not options.use_cache and options.package_command != "uninstall" and options.package_command != "update":
        package.clean()

    if   options.package_command == "build"    : package.build()
    elif options.package_command == "uninstall": package.uninstall()
    elif options.package_command == "install"  : package.install()
    elif options.package_command == "update"  : package.update()
    else:
        sys.stderr.write(parser.get_usage())
        return 2
    return 0

def handleDockerPckgCommand(options):
    options.mic=""
    package = DockerPackageInstaller(options)
    if options.package_command == "install"  : package.install()
    return 0

def handleLxcPckgCommand(options):
    options.mic=""
    package = LXCPackageInstaller(options)
    if options.package_command == "install"  : package.install()
    return 0

def handleMarkerCommand(options):
    if not checkAdb(options):
        return 1

    product = AndroidProductLayout(options)
    shell = ADB(options = options, status_dir = os.path.join(product.get_install_dir(), '..'))

    #itt enabling command
    if options.enable_itt_package_name:
        retcode = create_itt_marker(options.enable_itt_package_name, shell.is_root(), shell.bridge)
        if retcode == 0:
            sys.stdout.write("ITT marker file created\n")
        return retcode
    elif options.disable_itt_package_name:
        retcode = remove_itt_marker(options.disable_itt_package_name, shell.is_root(), shell.bridge)
        if retcode == 0:
            sys.stdout.write("ITT marker file destroyed\n")
        return retcode

def handleMerTraceDecoding(options):
    merDecoder = MerDecoder(options.mer_trace, options.result_dir, options.import_results)
    ret = merDecoder.initialize()
    if ret != 0:
        return ret

    return merDecoder.decode()

xml_escape_table = {
    "&": "&amp;amp;",
    ">": "&amp;gt;",
    "<": "&amp;lt;",
    '"': "&quot;",
    "'": "&apos;",
    }

def xml_escape(data):
    return "".join(xml_escape_table.get(symbol,symbol) for symbol in data)

def handleGetProcessListCommand(product, shell, messenger):
    params = ['']
    separator = "||||"
    uname_output = 'Linux'
    if product.get_layout_name() != 'android':
        uname_output = shell.uname()
        if 'FreeBSD' in uname_output:
            params = ['ps', '-xo "pid, comm"', ';', 'ps', '-xo "pid, command"']
        elif 'Darwin' in uname_output:
            params = ['ps', '-eo "pid, comm"', ';', 'ps', '-eo "pid, command"']
        else:
            params = ['ps'] + ['-eo "%p' + separator + '%c' + separator + '%a"']
            params += [';', "`sh -c \"if [ $? != '0' ]; then echo \"ps\"; fi\"`", ";", "echo 'secondary_ps'"]
        ps_output = shell.get_cmd_output(params)
    else:
        uname_output = 'Android'
        ps_output = shell.get_cmd_output(['ps'])

    if len(ps_output) < 2 or not 'PID' in " ".join(ps_output):
        messenger.severitywrite(" ".join(ps_output))
        return 1

    lt =  ''
    gt = '\n'
    pidlt = ""
    pidgt = "\n"
    namelt = ""
    namegt = "\n"
    cmdlt = ""
    cmdgt = "\n"
    if messenger.xml:
        lt = "&lt;process&gt;\n"
        gt = "&lt;/process&gt;\n"
        pidlt = "&lt;pid&gt;"
        pidgt = "&lt;/pid&gt;\n"
        namelt = "&lt;name&gt;"
        namegt = "&lt;/name&gt;\n"
        cmdlt = "&lt;cmd&gt;"
        cmdgt = "&lt;/cmd&gt;\n"
        messenger.write("\n<data>&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;\n&lt;bag&gt;\n")


    # FreeBSD and Darwin don't allow separator in ps command
    if 'FreeBSD' in uname_output in ('FreeBSD', 'Darwin'):
        ps_info = {}
        is_name_section = True
        for line in ps_output[1:]:
           if 'PID' in line:
               is_name_section = False
               continue
           if is_name_section:
               info = line.strip().split()
               pid = info[0]
               name = info[1]
               pid_info = {'pid': pid, 'name': name}
               ps_info[int(pid)] = pid_info
           else:
               info = line.strip().split()
               pid = info[0]
               cmd = " ".join(info[1:])
               if int(pid) in ps_info.keys():
                   ps_info[int(pid)]['cmd'] = cmd

        for pid_number in sorted(ps_info):
            pid_info = ps_info[pid_number]
            messenger.write(lt)
            messenger.write(pidlt + xml_escape(pid_info['pid']) + pidgt)
            messenger.write(namelt + xml_escape(pid_info['name']) + namegt)
            messenger.write(cmdlt + xml_escape(pid_info.get('cmd', pid_info['name'])) + cmdgt)
            messenger.write(gt)
    else: #not 'FreeBSD', 'Darwin'
        ps_output_size = len(ps_output)
        if ps_output_size:
            head = ps_output[0].strip().split(separator, 3)
            if len(head) != 3:
                head = ps_output[0].strip().split()
            head_pid_idx  = 0
            head_name_idx = 0
            for column_idx in range(len(head)):
                if head[column_idx].lower().strip() == 'pid':
                    head_pid_idx  = column_idx
                elif head[column_idx].lower().strip() in ['name', 'command', 'cmd']:
                    head_name_idx  = column_idx
                    break

            stat_shift = 0
            if product.get_layout_name() == 'android' and not('STAT' in head or 'S' in head):
                stat_shift = 1

            for line in ps_output[1:]:
                if 'secondary_ps' in line and not 'echo' in line:
                    break

                if 'ps -eo' in line:
                    continue

                #workaroud for STAT
                if product.get_layout_name() != 'android':
                    line = line.replace(' S ', ' S')

                if len(head) == 3:
                    array = line.strip().split(separator, 3)
                    pid = array[head_pid_idx].strip()
                    name = array[head_name_idx].strip()
                    cmd = array[head_name_idx + 1].strip()
                else:
                    array = line.strip().split()
                    pid = array[head_pid_idx].strip()
                    cmd = " ".join(array[head_name_idx + stat_shift:])
                    name = cmd.split()[0]

                messenger.write(lt)
                messenger.write(pidlt + xml_escape(pid) + pidgt)
                messenger.write(namelt + xml_escape(name) + namegt)
                messenger.write(cmdlt + xml_escape(cmd) + cmdgt)
                messenger.write(gt)

    if messenger.xml:
        messenger.write("&lt;/bag&gt;\n</data>\n")
    messenger.finalize()

    return 0

def handleGetPackageListCommand(options):
    if not checkAdb(options):
        return 1

    product = AndroidProductLayout(options)
    shell = ADB(options = options, status_dir = os.path.join(product.get_install_dir(), '..'))
    messenger = options.messenger

    product_install_dir = "/data/data/" + PACKAGE_NAME
    product_package_name = os.path.basename(product_install_dir)

    # put command to list all packages
    shell.get_cmd_output(["echo", "all", ">", product_install_dir + "/cmd.txt"])
    output = shell.get_cmd_output(["pm", "path", PACKAGE_NAME, ";", "echo", "-1", ">", product_install_dir + "/out.txt"])
    if not "package:" in " ".join(output):
        msg = "Cannot find product on the device. Enabling automatic installation..."
        options.messenger.severitywrite(msg, "info")
        options.package_command = "install"
        handleAndroidPckgCommand(options)

        shell.get_cmd_output(["echo", "all", ">", product_install_dir + "/cmd.txt"])
        shell.get_cmd_output(["echo", "-1", ">", product_install_dir + "/out.txt"])

    # cleanup
    shell.am_force_stop(product_package_name)

    # call vtune apk activity to get list installed applications
    shell.get_cmd_output(["am", "start", "-W", "-n", product_package_name + "/" + product_package_name + ".PackageInfoActivity"])[0]
    # get packages info from out file
    pm_output = shell.get_cmd_output(["cat", product_install_dir + "/out.txt"])
    shell.am_force_stop(product_package_name)

    if pm_output == "-1":
        messenger.severitywrite("Unable to get list packages.")
        return 1

    lt_package =  ''
    gt_package = '\n'

    lt_package_name =  ''
    gt_package_name = '\n'

    lt_app = ''
    gt_app = '\n'

    lt_debug = ''
    gt_debug = '\n'

    lt_system = ''
    gt_system = '\n'

    if messenger.xml:
        lt_package = "&lt;package&gt;\n"
        gt_package = "&lt;/package&gt;\n"

        lt_package_name =  "&lt;package_name&gt;\n"
        gt_package_name = "&lt;/package_name&gt;\n"

        lt_app = "&lt;app_name&gt;\n"
        gt_app = "&lt;/app_name&gt;\n"

        lt_debug = "&lt;debuggable&gt;\n"
        gt_debug = "&lt;/debuggable&gt;\n"

        lt_system = "&lt;system&gt;\n"
        gt_system = "&lt;/system&gt;\n"

        messenger.write("\n<data>&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;\n&lt;bag&gt;\n")

    i = 0
    while (i < len(pm_output)):
        packageName = ''
        appName = ''
        debuggableFlag = ''
        systemFlag = ''

        while (i < len(pm_output)):
            if "Package name:" in pm_output[i]:
                packageName = pm_output[i].replace("Package name: ", "")
                i += 1
                break
            i += 1

        while (i < len(pm_output)):
            if "App name:" in pm_output[i]:
                appName = pm_output[i].replace("App name: ", "")
                i += 1
                break
            packageName += pm_output[i]
            i += 1

        while (i < len(pm_output)):
            if "Debuggable:" in pm_output[i]:
                debuggableFlag = pm_output[i].replace("Debuggable: ", "")
                i += 1
                break
            appName += pm_output[i]
            i += 1

        while (i < len(pm_output)):
            if "System:" in pm_output[i]:
                systemFlag = pm_output[i].replace("System: ", "")
                break
            debuggableFlag += pm_output[i]
            i += 1

        messenger.write(lt_package)

        messenger.write(lt_package_name)
        messenger.write(xml_escape(packageName))
        messenger.write(gt_package_name)

        messenger.write(lt_app)
        messenger.write(xml_escape(appName))
        messenger.write(gt_app)

        messenger.write(lt_debug)
        messenger.write(xml_escape(debuggableFlag))
        messenger.write(gt_debug)

        messenger.write(lt_system)
        messenger.write(xml_escape(systemFlag))
        messenger.write(gt_system)

        messenger.write(gt_package)

        i += 1

    if messenger.xml:
        messenger.write("&lt;/bag&gt;\n</data>\n")
    messenger.finalize()

    return 0


# Wrapper for std* handles that duplicates everything to logging
class OutputLogReplicator:
    def __init__(self, stdhandle):
        self.stdhandle = stdhandle
    def write(self, data):
        logging.debug("%s: %s", self.stdhandle.name, data.rstrip())
        self.stdhandle.write(data)
    def flush(self):
        self.stdhandle.flush()


def enableLogging(options):
    # Create <result_dir>/log directory if it doesn't exist
    log_dir = options.log_folder or SCRIPT_DIR
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    #installation commands
    if options.package_command:
        options.log_name = os.path.join(log_dir, "setup.%s.log" % os.getpid())
        try:
            f = open(options.log_name,'w', encoding=ENCODING)
            f.close()
        except IOError:
            options.log_name = os.path.join(tempfile.gettempdir(), "setup.%s.log" % os.getpid())
    else:
        options.log_name = os.path.join(log_dir, PRODUCT_PREFIX + "_runss.py.%s.log" % os.getpid())

    logging.basicConfig(filename=options.log_name, level=logging.DEBUG)

    # Replicate this script's stderr output to the log to debug tracebacks and tool interaction
    sys.stderr = OutputLogReplicator(sys.stderr)

    if options.verbose:
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter("%(levelname)-8s %(message)s")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

    return options

import pythonhelpers1.genhelpers as genhelpers
class SshKeys(object):
    def __init__(self, machine):
        user_home_dir = os.path.expanduser("~")
        private_key_name = "id_rsa_vtune_" + machine
        public_key_name = "id_rsa_vtune_" + machine + ".pub"
        ssh_dir_path = os.path.join(user_home_dir,  '.ssh')
        self._private_key_path = os.path.join(ssh_dir_path, private_key_name)
        self._public_key_path = os.path.join(ssh_dir_path, public_key_name)
        self._ssh_dir_path = ssh_dir_path

    def private_key_path(self):
        return self._private_key_path

    def public_key_path(self):
        return self._public_key_path

    def ssh_dir_path(self):
        return self._ssh_dir_path

    def get_install_ssh_key_path(self):
        file_path = os.path.abspath(__file__)
        script_path = os.path.dirname(file_path) + '/install_ssh_key'
        if os.name == 'nt':
            script_path += '.bat'

        if not os.path.isfile(script_path):
            return None

        return script_path

    def clean(self):
        if os.path.isfile(self.private_key_path()):
            os.remove(self.private_key_path())
        if os.path.isfile(self.public_key_path()):
            os.remove(self.public_key_path())

def ssh_keygen(machine, port):

    # windows generation only
    if os.name != 'nt':
        return False

    ssh_keys = SshKeys(machine)

    # could not generate scripts
    if not genhelpers.ssh_keygen(ssh_keys.private_key_path(), ssh_keys.public_key_path()):
        return False

    # there are no install keys script
    if not ssh_keys.get_install_ssh_key_path():
        ssh_keys.clean()
        return False

    try:
        cmd = subprocess.Popen([ssh_keys.get_install_ssh_key_path(), machine, port, ssh_keys.private_key_path(), ssh_keys.public_key_path(), ssh_keys.ssh_dir_path()],
                               creationflags=subprocess.CREATE_NEW_CONSOLE)
    except subprocess.CalledProcessError:
        ssh_keys.clean()
        return False

    cmd.wait()
    retcode = cmd.poll()
    if retcode:
        return False
    return True

def main():
    parser = initializeParser()
    (options, arguments) = parser.parse_args()
    if len(sys.argv) == 1:
        sys.stdout.write(parser.get_usage())
        return 1

    #decoding command
    if options.mer_trace:
        return handleMerTraceDecoding(options)

    options = enableLogging(options)

    logging.debug("CMDLINE: %s", " ".join(sys.argv))

    #installation commands
    if options.package_command:
        if options.target == "docker":
            return handleDockerPckgCommand(options)
        elif options.target == "lxc":
            return handleLxcPckgCommand(options)
        else:
            return handleAndroidPckgCommand(options)

    #marker file commands
    if options.enable_itt_package_name or options.disable_itt_package_name:
        return handleMarkerCommand(options)

    if not options.runss_args:
        options.runss_args = []

    options.xml_output = False
    if '--ui-output-format xml' in " ".join(options.runss_args):
        options.xml_output = True

    #Initialize message writer
    options.messenger = MessageWriter(xml=options.xml_output)

    if options.get_package_list:
        return handleGetPackageListCommand(options)

    if options.option_file:
        if not os.path.exists(options.option_file):
            parser.error("File path specified for --option-file option is invalid.")

    else:
        #TODO: Pending for no checks arguments
        if arguments and (options.target_pid or options.target_process):
            parser.error("Options --target-pid or --target-process cannot be specified together " \
                "with application arguments.")

        if options.target_pid and options.target_process:
            parser.error("Options --target-pid or --target-process cannot be specified together.")

        if options.command and (options.target_pid or options.target_process or arguments):
            parser.error("Cannot start a collection and send a command at the same time.")

        if not options.command and not options.target_pid and not options.target_process \
            and not arguments and options.pmu_stack \
            and not options.target_file \
            and not options.is_accessible \
            and not '--pwr-config' in sys.argv \
            and not '--sys-config' in sys.argv \
            and not '--event-list' in sys.argv \
            and not '--context-value-list' in sys.argv \
            and not '--deploy' in sys.argv \
            and not '--event-value-list' in sys.argv \
            and not '--ftrace-config-list' in sys.argv \
            and not '--atrace-config-list' in sys.argv \
            and not '--find-bin-file' in sys.argv \
            and not '--md5sum' in sys.argv\
            and not options.get_devices \
            and not options.get_process_list \
            and not options.get_package_list \
            and not options.runss_args is None  \
            and not "--etw-config" in options.runss_args:
            parser.error("Stack collection is not supported for system-wide analysis. " \
                          "\nUse --no-pmu-stack option or set a target.")

    if options.target not in ["docker", "lxc"]:
        if not options.command and\
            not '--md5sum' in sys.argv and\
            not '--find-bin-file' in sys.argv and\
            not '--copy-file' in sys.argv and\
            not options.target_file:
            options.result_dir = get_next_result_dir(options.result_dir)
            if os.path.exists(options.result_dir):
                parser.error("Please specify non-existent result directory using -r option.")
        else:
            tmp_result_dir = get_last_result_dir(options.result_dir)
            if tmp_result_dir == None:
                parser.error("Cannot open the result directory %s. Please specify a valid path." % options.result_dir)
            else:
                options.result_dir = tmp_result_dir

    options.mic = False
    runtool = None
    product = None

    if re.match('^android', options.target):
        if options.deploy or not checkAdb(options):
            return 1

        #remove device name from option.
        #Result dir includes incorrect symbols like ':' if we stay device name
        options.target = 'android'

        product = AndroidProductLayout(options)
        shell = ADB(options = options, status_dir = os.path.join(product.get_install_dir(), '..'))

        if options.get_devices:
            shell.get_devices(xml=options.xml_output)
            return 0

    elif re.match('^docker', options.target):
        product = DockerProductLayout(options)
        shell = DockerShell(options)
        runtool = DockerRunTool(shell, product, options)

        if options.command == "stop":
            return runtool.stop()

        if options.is_accessible == "cl":
            return shell.is_accessible()

    elif re.match('^lxc', options.target):
        product = LxcProductLayout(options)
        shell = LxcShell(options)
        runtool = LxcRunTool(shell, product, options)
        if options.command == "stop":
            return runtool.stop()

        if options.is_accessible == "cl":
            return shell.is_accessible()

    elif re.match('^tizen', options.target):
        sdb = which("sdb")
        if not sdb:
            error_message = "sdb is not found on the host. Add it to PATH."
            options.messenger.severitywrite(error_message)
            return 1
        else:
            os.putenv('PATH', os.getenv('PATH') + os.pathsep + os.path.dirname(sdb))
        shell = ADB(options, status_dir='/tmp', bridge = 'sdb')
        product = LinuxProductLayout(options)

    else:
        options.target = re.sub('^ssh:', '', options.target)
        shell = createSSHShell(options)
        if not shell:
            return 1

        if re.match("^docker", options.target):
            product = DockerProductLayout(options)
        else:
            product = LinuxProductLayout(options)

    #get process list
    if options.get_process_list:
        return handleGetProcessListCommand(product, shell, options.messenger)

    if product and product.get_layout_name() == 'android':
        #replace --pmu-config as deprecated option
        if '--pmu-config' in options.runss_args:
            options.runss_args[options.runss_args.index('--pmu-config')] = "--event-config"
        if not options.option_file and not options.command and not options.target_file:
            if not options.runss_args or \
                ("--event-config" not in options.runss_args and \
                "--chipset-event-config" not in options.runss_args and \
                "--pwr-config"    not in options.runss_args and \
                "--sys-config"    not in options.runss_args and \
                "--ptrace"        not in options.runss_args and \
                "--etw-config"    not in options.runss_args and \
                "--stdsrc-config" not in options.runss_args and \
                "--event-value-list" not in options.runss_args and \
                "--ftrace-config-list" not in options.runss_args and \
                "--atrace-config-list" not in options.runss_args and \
                "--context-value-list" not in options.runss_args and \
                "--find-bin-file" not in options.runss_args and \
                "--md5sum" not  in options.runss_args and \
                "--itt-config"    not in options.runss_args):
                options.runss_args += ["--event-config", "CPU_CLK_UNHALTED.REF,CPU_CLK_UNHALTED.CORE,INST_RETIRED.ANY"]

    #collect event info locally
    #if "--event-value-list" in options.runss_args:
    #    shell = LocalShell(options)
    #    runtool = LocalRunTool(shell, options)

    try:
        options.launch = False
        options.run = False
        if not runtool:
            runtool = RunTool(shell, product, options)

        appArguments = None
        if options.option_file != None:
            optionsParser = OptionFileParser(options.option_file)
            appArguments = optionsParser.get_arguments()

        return_code = 0
        out_message = ''

        try:
            if not options.command:
                if options.target_pid:
                    return_code = runtool.attach(options.target_pid)
                    out_message = "Attach return code is " + str(return_code)
                elif options.target_file:
                    with Multitarget(options, options.result_dir) as acrn_multitarget:
                        return_code = runtool.copy_file(options.target_file)
                        return_code = acrn_multitarget.copy_file(return_code)
                    out_message = "Copy return code is " + str(return_code)
                elif "--md5sum" in options.runss_args:
                    with Multitarget(options, options.result_dir) as acrn_multitarget:
                        return_code = runtool.start_md5sum()
                        return_code = acrn_multitarget.start_md5sum(return_code)
                    out_message = "md5sum return code is " + str(return_code)
                elif options.target_process:
                    return_code = runtool.attach(options.target_process)
                    out_message = "Attach return code is " + str(return_code)
                elif appArguments and re.match('^android', options.target):
                    installed_packages = shell.get_cmd_output(["pm", "list", "packages"])
                    if ("package:" + appArguments[0]) in installed_packages:
                        shell.options.launch = True

                        #enable/disable dynamic symbol resolving support
                        shell.set_vm_prop()

                        for i in range(0, 20): # waiting for pm startup = 10 secs
                            installed_packages = shell.get_cmd_output(["pm", "list", "packages"])
                            if ("package:" + appArguments[0]) in installed_packages:
                                 break
                            time.sleep(0.5)

                        product_install_dir = "/data/data/" + PACKAGE_NAME
                        #default name is com.intel.vtune
                        product_package_name = os.path.basename(product_install_dir)
                        # get activity name from vtune apk
                        # start app via am start -D <package>/<activity>
                        # adb shell am start -D -n com.intel.fluid/android.app.NativeActivity
                        package_name = appArguments[0]
                        activity_name = ""
                        # put target package name to input file for vtune apk
                        shell.get_cmd_output(["echo", package_name, ">", product_install_dir + "/cmd.txt"])
                        shell.get_cmd_output(["echo", "-1", ">", product_install_dir + "/out.txt"])
                        # cleanup
                        shell.am_force_stop(product_package_name)
                        shell.am_force_stop(package_name)
                        # call vtune apk activity to get target start activity
                        shell.get_cmd_output(["am", "start", "-W", "-n", product_package_name + "/" + product_package_name + ".PackageInfoActivity"])[0]
                        # get activity name from output file
                        activity_name = shell.get_cmd_output(["cat", product_install_dir + "/out.txt"])[0]
                        shell.am_force_stop(product_package_name)
                        if activity_name == "-1":
                            options.messenger.severitywrite("there is no activity for package %s" % package_name)
                            options.messenger.failwrite(1)
                            return 1
                        # to support ITT on startup we need to create marker file for itt scatic part (android only)
                        itt_collection_enabled = False
                        if runtool._get_option_value_from_option_file(options.option_file,  ["--itt-config"]) or "--itt-config" in options.runss_args:
                            itt_collection_enabled = True
                            create_itt_marker(package_name, shell.is_root(), shell.bridge)

                        shell.get_cmd_output(["am", "start", "-D", "-n", package_name + "/" + activity_name])[0]
                        # get app PID
                        # scan /proc or adb jdwp and take last entry (ndk-debug way)
                        target_pids = []
                        for i in range(10): # Due to Android limits launch time of application on 5 seconds, we check 10 time with 0.5 sec interval
                            for line in shell.ps():
                                if package_name == line.split()[-1]:
                                    target_pids.append(line.split()[1])
                            if target_pids:
                                break
                            time.sleep(0.5)
                        if not target_pids:
                            options.messenger.severitywrite("Unable to start application %s. Probably, application launch takes more than 5 seconds." % package_name)
                            shell.am_force_stop(package_name)
                            options.messenger.failwrite(1)
                            return 1
                        elif len(target_pids) > 1:
                            options.messenger.severitywrite("There are more than one process for %s." % package_name)
                            shell.am_force_stop(package_name)
                            options.messenger.failwrite(1)
                            return 1
                        elif len(target_pids) > 0:
                            options.target_pid = int(target_pids[0])

                        try:
                            shell.options.jdb_port = find_free_port(options.messenger)
                        except:
                            raise
                        # forward JDWP port to host
                        # get debug port number from adb interface via 'adb jdwp' command
                        # application is not debuggable in case of 'adb jdwp' returns nothing
                        jdwp_port_list = shell.get_jdwp_port_list()
                        if jdwp_port_list == []:
                            time.sleep(5)
                            jdwp_port_list = shell.get_jdwp_port_list()

                        if options.target_pid in jdwp_port_list:
                            if not options.detached_mode:
                                # adb forward tcp:<local port> jdwp:<app pid>
                                shell._call_adb(["forward", "tcp:%d" % int(shell.options.jdb_port), "jdwp:%d" % int(options.target_pid)])
                            options.target_process = package_name
                            # attach profiler to running process
                            return_code = runtool.attach(options.target_pid)
                            out_message = "Attach return code is " + str(return_code)
                        else:
                            error_message = "Cannot profile the specified target type. Make sure the 'debuggable' flag is set for your application."
                            if shell.is_root():
                                error_message  = "Your system works in the root mode but does not have 'ro.debuggable' property set. "
                                error_message += "To profile the specified target type, make sure to set the 'debuggable' flag for your application."
                            options.messenger.severitywrite(error_message)
                            shell.am_force_stop(package_name)
                            options.messenger.failwrite(1)
                            return 1

                        # close target application
                        shell.am_force_stop(package_name)

                        # remove marker file
                        if itt_collection_enabled:
                            remove_itt_marker(package_name, shell.is_root(), shell.bridge)
                    else:
                        if runtool._get_option_value_from_option_file(options.option_file,  ["--ptrace"]) or "--ptrace" in options.runss_args:
                            options.messenger.severitywrite("This analysis type does not support Launch Application target type. " +
                                                             "Please check correctness Android Package name or " +
                                                             "use Launch Android Package or Attach to Process target types.")
                            options.messenger.failwrite(1)
                            return 1
                        else:
                            return_code = runtool.start(arguments)
                            out_message = "Collection return code is " + str(return_code)
                elif options.runss_args or '--no-pmu-stack' in sys.argv:
                    options.run = True
                    return_code = runtool.start(arguments)
                    out_message = "Collection return code is " + str(return_code)
                else:
                    parser.print_usage(sys.stderr)
                    return_code = -1
            else:
                #don't need app work dir for command
                options.app_work_dir = None
                with Multitarget(options, options.result_dir):
                    return_code = runtool.execute(options.command)
                if return_code != 0:
                    out_message = "Hint: Probably collection is not running\n"
                out_message += options.command + " command return code is " + str(return_code)

            if not options.xml_output:
                sys.stdout.write( out_message + "\n")
            return return_code
        except KeyboardInterrupt:
            options.messenger.failwrite(1)
            return 1
        except:
            options.messenger.severitywrite('An internal error has occurred. Our apologies for this inconvenience. Please gather a description of the steps leading up to the problem and contact the Intel customer support team.')
            logging.debug("Exception: %s occured", sys.exc_info()[0])
            import traceback
            logging.debug("%s", " ".join(traceback.format_exception(*sys.exc_info())))
        
            return 1
    finally:
        options.messenger.finalize()


class Multitarget(object):
    def __init__(self, options, result_dir):
        self.options = options
        self.result_dir = result_dir
        self.collection_process = None
        self.collection_output = None
        self.python_path = self.__get_python_path()
        self.is_multitarget = self.__is_multitarget()

    def __is_multitarget(self):
        if not self.options.option_file and os.path.exists(self.get_android_runsa_path()):
            return True
        if not self.options.option_file:
            return False
        if not os.path.exists(self.options.option_file):
            return False
        remote_config = os.path.join(self.options.option_file + '_remote')
        with open(remote_config, 'r', encoding=ENCODING) as remote_config:
            if '--acrn-map-info' not in remote_config.read():
                return False
        return self.check_adb_devices()

    def __get_python_path(self):
        file_path = os.path.abspath(__file__)
        python_path = file_path[:-len('-runss.py')] + '-python'
        if os.name == 'nt':
            python_path += '.exe'
        return python_path

    def check_adb_existance(self):
        adb_executable = self.options.adb_path or 'adb'
        return bool(which(adb_executable))

    def get_android_runtool(self):
        if not self.check_adb_devices():
            return None
        import copy

        options = copy.deepcopy(self.options)
        options.messenger = InternalMessenger()
        options.messenger.message = ''
        options.install_dir = None
        product = AndroidProductLayout(options)
        shell = ADB(options=options, status_dir=os.path.join(product.get_install_dir(), '..'))
        runtool = RunTool(shell, product, options)
        return runtool

    def check_adb_devices(self):
        if not self.check_adb_existance():
            return False
        import copy
        options = copy.deepcopy(self.options)
        options.messenger = InternalMessenger()
        product = AndroidProductLayout(options)
        shell = ADB(options=options, status_dir=os.path.join(product.get_install_dir(), '..'))
        shell.get_devices(xml=None)
        return '<feedback>' != options.messenger.message.splitlines()[1]

    def get_collection_data_directory(self):
        return os.path.join(self.result_dir, 'data.0', 'VM1')

    def create_collection_data_directory(self):
        if not os.path.exists(self.get_collection_data_directory()):
            os.makedirs(self.get_collection_data_directory())

    def get_config_directory(self):
        return os.path.join(self.result_dir, 'config')

    def create_config_directory(self):
        if not os.path.exists(self.get_config_directory()):
            os.makedirs(self.get_config_directory())

    def get_android_runsa_path(self):
        return os.path.join(self.get_config_directory(), 'android_runsa.options')

    def generate_android_collection_config(self):
        with open(self.get_android_runsa_path(), 'w', encoding=ENCODING) as f:
            f.write('-r\n')
            f.write(self.get_collection_data_directory() + '\n')
            f.write('--collector=perf\n')
            f.write('--perf-event-config\n')
            f.write('cpu-clock:u\n')
            f.write('--perf-pass-thru="-F 10"\n')
            f.write('--stdsrc-config=cswitch\n')
            f.write('--system-wide\n')
            f.write('--duration\n')
            f.write('unlimited\n')

    def spawn_android_collection(self):
        try:
            self.collection_process = subprocess.Popen(
                [
                    self.python_path, sys.argv[0],
                    '--target-system=android',
                    '--option-file', self.get_android_runsa_path(),
                    '--ui-output-format', 'text',
                    '--no-modules',
                    '--log-folder', self.options.log_folder
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            logging.debug("Read collection info from ACRN Guest")
            while self.collection_process.poll() is None:
                full_line = ''
                for line in iter(self.collection_process.stdout.readline, ''):
                    line = line.strip()
                    full_line += line
                    logging.debug(line)
                    logging.debug('Full line: ' + full_line)
                    if 'Collection started.' in line or 'Collection started.' in full_line:
                        logging.debug("End reading")
                        return
                    if 'Collection return' in line or 'Collection return' in full_line:
                        self.collection_process.wait()
                        logging.debug("End reading")
                        return
                time.sleep(0.1)
        except subprocess.CalledProcessError:
            return

    def stop_android_collection(self):
        if self.collection_process is not None:
            self.on_collection_stop()
            self.collection_process.wait()

    def on_collection_start(self):
        self.create_collection_data_directory()
        self.create_config_directory()
        self.generate_android_collection_config()
        self.spawn_android_collection()
        self.md5_messenger = None

    def get_stop_command(self):
        return [
            self.python_path, sys.argv[0],
            '--command', 'stop',
            '--target-system=android',
            '--no-modules',
            '-r', self.get_collection_data_directory(),
            '--log-folder', self.options.log_folder
        ]

    def get_cancel_command(self):
        return [
            self.python_path, sys.argv[0],
            '--command', 'cancel',
            '--target-system=android',
            '--no-modules',
            '-r', self.get_collection_data_directory(),
            '--log-folder', self.options.log_folder
        ]

    def on_collection_stop(self):
        current_cmdline = subprocess.list2cmdline([self.python_path]+sys.argv)
        if current_cmdline != subprocess.list2cmdline(self.get_stop_command()):
            subprocess.call(self.get_stop_command(), stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    def on_collection_cancel(self):
        current_cmdline = subprocess.list2cmdline([self.python_path]+sys.argv)
        if current_cmdline != subprocess.list2cmdline(self.get_cancel_command()):
            subprocess.call(self.get_cancel_command(), stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    def start_md5sum(self, return_code):
        if not self.is_multitarget:
            return return_code

        runtool = self.get_android_runtool()
        if not runtool:
            self.md5_messenger.write(self.options.messenger.message)
            self.options.messenger = self.md5_messenger
            return return_code

        if 'ERROR_FILE_NOT_EXIST' in self.options.messenger.message:
            runtool.tmp_dir = '/'
            runtool.runss_args = ['--target-system=android'] + runtool.options.runss_args
            return_code = runtool.start_md5sum()
            if 'ERROR_FILE_NOT_EXIST' not in runtool.options.messenger.message:
                self.md5_messenger.write(self.options.messenger.message)
                self.options.messenger = self.md5_messenger
                return return_code
        self.md5_messenger.write(self.options.messenger.message)
        self.options.messenger = self.md5_messenger
        return return_code

    def copy_file(self, return_code):
        if self.is_multitarget and return_code != 0:
            runtool = self.get_android_runtool()
            if runtool:
                return runtool.copy_file(self.options.target_file)
            return 1
        else:
            return return_code

    def __enter__(self):
        if self.is_multitarget:
            if self.options.run:
                self.on_collection_start()
            elif self.options.command:
                if self.options.command == 'cancel':
                    self.on_collection_cancel()
            elif '--md5sum' in self.options.runss_args:
                self.md5_messenger = self.options.messenger
                self.options.messenger = InternalMessenger()
                self.options.messenger.message = ''
            elif self.options.target_file:
                self.target_file_messenger = self.options.messenger
                self.options.messenger = InternalMessenger()
                self.options.messenger.message = ''
        return self

    def __exit__(self, *args):
        if self.is_multitarget:
            if self.options.run:
                self.stop_android_collection()
            elif self.options.command and self.options.command == 'stop':
                self.stop_android_collection()
            elif self.options.target_file:
                self.options.messenger = self.target_file_messenger


if __name__ == "__main__":
    return_code = main()
    os._exit(return_code)
