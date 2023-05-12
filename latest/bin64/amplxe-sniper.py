#!/usr/bin/env python
#
# Copyright (C) 2016 Intel Corporation
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
PRODUCT_PREFIX = os.path.basename(sys.argv[0]).split('-')[0]
runss = __import__(PRODUCT_PREFIX + "-runss")

import errno
import subprocess
from optparse import OptionParser, OptionGroup
import logging

#use following variable for local debugging without sniper
# Sniper configs will be simulated by this script
local_debug=False

sniperSimulatedOutput = [ 
               "CONFIGS:",
               "  knh                               : Intel Xeon Phi KNH [1.3GHz, 72 cores]",
               "  knh2                              : Intel Xeon Phi KNH [1.3GHz, 72 cores]",
               "  silvermont                        : Silvermont [2.4GHz]",
               "  skl                               : Intel Xeon rocessor Skylake [2.6GHz, 14 cores]",
               "",
               "EVENTS:",
               "  BR_INST_RETIRED.ANY               : The number of branch instructions retired",
               "  CPU_CLK_UNHALTED.REF              : Reference cycles when core is not halted",
               "  INST_RETIRED.ANY                  : The number of instructions that retire from execution"
             ]

result_dir_keys = ["-r", "--result-dir"]
def appendSniperRootFooter(message):
    return message + " Please define valid path by environment variable SNIPER_ROOT or provide it by argument --sniper-root"

class SniperConfigParser(object):
    def __init__(self, content):
        configs_started = False
        events_started = False
        self._proc = []
        self._events = []
        self._names = []
        for line in content:
            if line.find("CONFIGS:") != -1:
                configs_started = True
                continue
            if line.find("EVENTS:") != -1:
                configs_started = False
                events_started = True
                continue
            if configs_started:
                res = self._parse_line(line)
                if not res:
                    continue
                (id, name) = res
                suffix = ""
                while name + suffix in self._names:
                    suffix = suffix + "."
                self._names.append(name + suffix)
                res = (id, name + suffix)
                self._proc.append(res)

            if events_started:
                res = self._parse_line(line)
                if not res:
                    continue
                self._events.append(res)

    def _parse_line(self, line):
        semicolomn_pos = line.find(":")
        if semicolomn_pos == -1:
            return None
        left = line[0:semicolomn_pos]
        right = line[semicolomn_pos+1:]
        return (left.strip(), right.strip())

    def get_devices(self, xml = False):
        out = []
        line_format = "%s\t:%s\n"
        if xml:
            line_format = "    &lt;device id='%s'&gt;%s&lt;/device&gt;\n"
            out.append("\n<data>&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;\n&lt;bag&gt;\n")

        for item in self._proc:
            out.append(line_format%item)
        if xml:
            out.append("&lt;/bag&gt;\n</data>\n<nop/>\n")
        return out

    def get_events(self, xml = False):
        out = []
        line_format = "%s\t:%s\n"
        if xml:
            line_format = """    &lt;event name=&quot;%s&quot; description=&quot;%s&quot;&gt;
      &lt;modifiers&gt;
         &lt;modifier name=&quot;sa&quot; description=&quot;&quot; type=&quot;integer&quot; unsignedLong:min=&quot;100000&quot; unsignedLong:value=&quot;2000003&quot;/&gt;
      &lt;/modifiers&gt;
    &lt;/event&gt;"""

            out.append("\n<data>\n  &lt;bag xmlns:unsignedLong=&quot;http://www.w3.org/2001/XMLSchema#unsignedLong&quot;&gt;\n")

        for item in self._events:
            out.append(line_format%item)
        if xml:
            out.append("\n  &lt;/bag&gt;\n</data>\n<nop/>\n")
        return out

    def get_raw_events(self):
        return self._events

class SniperShell(runss.LocalShell):
    def __init__(self, options):
        options.mic = False
        runss.LocalShell.__init__(self, options)

        self._proc = "knh"
        target = options.target.split(':')
        if len(target) > 1:
            self._proc = target[1]
        logging.debug("Processor config: %s", self._proc)

        if not local_debug:
            self._sniper = [os.path.join(options.sniper_root, "run-sniper")]
            if not os.path.exists(self._sniper[0]):
                options.messenger.severitywrite(appendSniperRootFooter("Sniper file [%s] is not exist." %self._sniper), "error")
            logging.debug("using sniper: %s", self._sniper)
            self.runtool_executabe = self._sniper

    def get_proc_name(self):
        return self._proc

    def _call_shell_threaded_function(self, results, child_pids, args, kwargs):
        if 'stdout' in kwargs.keys() or 'stderr' in kwargs.keys():
            process = subprocess.Popen(self.runtool_executabe + args, **kwargs)
            stdout, stderr = process.communicate()
            child_pids[0] = process.pid
        else:
            process = subprocess.Popen(self.runtool_executabe + args,
                stdout=subprocess.PIPE,
                **kwargs)
            child_pids[0] = process.pid

            line = process.stdout.readline()

            started = False
            while line:
                if not started and line.find("[SNIPER]") != -1:
                    started = True
                    self.options.messenger.write('<state_changed %s data=""/>' % runss.collectionStateToStr(runss.CS_STARTED))

                sys.stdout.write(line)
                """
                TODO this is atempt to write sniper messages to log window
                    The problem with this solution is info messages are displayed in one line and delete previous message
                    Need better handling in GUI as an example using "verbose" type to not delete previous message
                if line.find("[SNIPER]") != -1 or line.find("[TRACE") != -1:
                   lines = line.split("\n")
                   for l in lines:
                       if l.find("[SNIPER]") != -1 or l.find("[TRACE") != -1:
                           self.options.messenger.severitywrite(line,"warning")
                       else:
                           sys.stdout.write(l)
                else:
                    sys.stdout.write(line)
                """

                line = process.stdout.readline()
            process.communicate()

        results[0] = process.poll()

    def get_sniper_config(self):
        if not local_debug:
            logging.debug("call run_sniper --show-sim-configs")
            process = subprocess.Popen(self.runtool_executabe + ["--show-sim-configs"], stdout=subprocess.PIPE)
            stdout, stderr = process.communicate()
            retcode = process.poll()
            sniperOutput = stdout.splitlines()
        else:
            sniperOutput = sniperSimulatedOutput

        parser = SniperConfigParser(sniperOutput)
        return parser

    def get_devices(self, xml):
        parser = self.get_sniper_config()
        out = parser.get_devices(xml)
        for line in out:
            self.options.messenger.write(line)

def generate_event_config(filename, events, memory_access_analysis, sav, all_events):
    required_events = events.split(',')

    #generate header
    contents=['#include vtt-events-desc', '', '[vtt]', 'enabled=true']
    analyze_mem_string = "true" if memory_access_analysis else "false"
    contents.append('trace_mem_allocs=%s' % analyze_mem_string)
    contents.append('trace_mem_refs=%s' % analyze_mem_string)
    contents.append('callstack=%s' % analyze_mem_string)
    contents.append('max_records=0')
    contents.append('')

    for (event, descr) in all_events:
        contents.append('[vtt/events/%s]' % event)
        contents.append('interval=%i' % sav)
        if event in required_events:
            contents.append('enabled=true')
        else:
            contents.append('enabled=false')
        contents.append('')

    outfile = open(filename,'w')
    for line in contents:
        outfile.write(line)
        outfile.write('\n')
    outfile.close()


class SniperRunTool(object):
    def __init__(self, options, shell):
        self._options = options
        self._error = False
        logging.debug("option file: %s", self._options.option_file)
        if options.option_file:
            self._file_parser = runss.OptionFileParser(options.option_file)
        else:
            self._file_parser = None

        self._result_dir = self._get_option_value_from_option_file(result_dir_keys)
        logging.debug("result directory: %s", self._result_dir)

        self._shell = shell

    def execute(self, command):
        pass

    def _decodeRoiParameters(self, params):
        value = params[0]
        out = []
        if value == "roi-function":
            out.append('--roi')
            return out

        idx = value.find("ssc:")
        if idx != -1:
            values = value[value.find(":") + 1:]
            delimiter_pos = values.find(":")
            if delimiter_pos != -1:
                start = values[:delimiter_pos]
                end = values[delimiter_pos + 1:]
                if len(start) == 0:
                    self._options.messenger.severitywrite("Start SSC Mark is empty.", "error")
                    self._error = True
                if len(end) == 0:
                    self._options.messenger.severitywrite("End SSC Mark is empty.", "error")
                    self._error = True
                out += ['--roi-start-ssc', "0x"+start, '--roi-end-ssc', "0x"+end]
            else:
                self._options.messenger.severitywrite("Can not parse SSC Marks values. Giving option is [%s]"%value, "error")
                self._error = True
            return out

        idx = value.find("function:")
        if idx != -1:
            function = value[value.find(":") + 1:]
            if len(function) == 0:
                function="main"
            out += ["--roi-rtn", function]
            return out

        self._options.messenger.severitywrite("Invalid ROI option: %s"%value, "error")
        self._error = True
        return out

    def collect(self):
        result_data_dir = os.path.join(self._result_dir, "data.0")
        result_config_dir = os.path.join(self._result_dir, "config")
        sniper_data_dir = os.path.join(self._result_dir, "sniper_data")
        args = ["--vtt-out-dir", result_data_dir]
        args += ["--vtt-vtss-only"]
        args += ["-d", sniper_data_dir]

        giving_options = self._file_parser.get_option_values('--roi')
        if giving_options and len(giving_options) != 0:
            args += self._decodeRoiParameters(giving_options)

        args += ["-c", self._shell.get_proc_name()]

        analyze_mem_access = self._file_parser.is_option_present('--analyze-mem-access')
        sav = int(self._file_parser.get_option_values(['--sav'], True))
        all_events = self._file_parser.get_option_values(['--events'])
        events = ','.join(all_events)
        event_config_path = os.path.join(result_config_dir, "vtt-events.cfg")
        parser = self._shell.get_sniper_config()
        all_events = parser.get_raw_events()
        logging.debug("Detected sniper events [%s]", str(all_events))    
        if not self._check_event_names(all_events, events):
            return 1
        generate_event_config(event_config_path, events, analyze_mem_access, sav, all_events)
        args += ["-c", event_config_path]

        giving_options = self._file_parser.get_option_values('--adv-config')
        if giving_options and len(giving_options) != 0:
            args += giving_options[0].split(" ")

        args += ["--"] + self._get_arguments_from_option_file()
        if local_debug:
            debug_file_name = os.path.join(result_config_dir, "debug.log")
            debug_file = open(debug_file_name, "w")
            debug_file.write("Calling sniper with following parameters:\n %s"%"\n".join(args));
            return 0

        if self._error:
            return 4

        self._shell.call(args)
        return 0

    def _check_event_names(self, all_events, to_check):
        events = [x for (x,y) in all_events]
        required_events = to_check.split(',')

        error = False
        for event in required_events:
            if not event in events:
                error = True
                self._options.messenger.severitywrite("The event [%s] is not supported." % event)
                logging.debug("The event [%s] is not supported." % event)
        if error:
            logging.debug("Supported events are: %s" % ','.join(events))
        return not error
    
    def _get_arguments_from_option_file(self):
        if not self._file_parser:
            return None
        return self._file_parser.get_arguments();

    def _get_option_value_from_option_file(self, option_keys):
        if not self._file_parser:
            return None
        return self._file_parser.get_option_values(option_keys, True);

    def _get_option_values_from_option_file(self, option_keys, first_only = False):
        if not self._file_parser:
            return None
        return self._file_parser.get_option_values(option_keys, first_only);


def initializeParser():

    parser = OptionParser(usage = "Usage: %prog [options] [[--] <application> [<args>]]")

    collection_group = OptionGroup(parser, "Collection options")
    collection_group.add_option("--target-system",
                        metavar="host",
                        dest="target",
                        default="sniper",
                        help="Specify target for data collection.")

    collection_group.add_option("--log-folder",
                        metavar="host",
                        dest="log_folder",
                        help="Specify host log folder.")

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

    collection_group.add_option("--event-list",
                        dest="runss_args",
                        action="callback",
                        callback=runss.add_runss_args,
                        help="List events for which a sampling data collection can be " +
                        "performed on this platform.")

    collection_group.add_option("--context-value-list",
                        dest="runss_args",
                        action="callback",
                        callback=runss.add_runss_args,
                        help="Display possible context values.")

    collection_group.add_option("--ui-output-fd",
                        type="string",
                        help="Output fd.")

    collection_group.add_option("--ui-output-format",
                        type="string",
                        dest="runss_args",
                        action="callback",
                        callback=runss.add_runss_args,
                        help="Output format.")

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

    collection_group.add_option("--sniper-root",
                        default=os.environ.get("SNIPER_ROOT", None),
                        type="string",
                        dest="sniper_root",
                        help="Specify a path to the adb executable if it is not reachable from the PATH environment variable.")

    collection_group.add_option("--app-working-dir",
                        metavar="host",
                        dest="app_work_dir",
                        help="Specify application working dir.")

    internal_group = OptionGroup(parser, "Internal options")
    internal_group.add_option("--event-value-list",
                  action="store_true",
                  dest="get_event_value_list",
                  default=False,
                  help="List events for which a sampling data collection can be performed on this platform.")

    internal_group.add_option("--platform-type",
                  type="int",
                  dest="platform_type",
                  help="Specify platform type for --event-value-list.")

    internal_group.add_option("--get-devices",
                  action="store_true",
                  default=False,
                  dest="get_devices",
                  help="get list of devices. Avalable for android target only.")


    return parser

def main():
    parser = initializeParser()
    (options, arguments) = parser.parse_args()
    if len(sys.argv) == 1:
        sys.stdout.write(parser.get_usage())
        return 1
    options.package_command = False
    options = runss.enableLogging(options)
    options.mic = False;

    options.xml_output = False

    if options.runss_args and '--ui-output-format xml' in " ".join(options.runss_args):
        options.xml_output = True

    #Initialize message writer
    options.messenger = runss.MessageWriter(xml=options.xml_output)

    try:
        if options.option_file:
            if not os.path.exists(options.option_file):
                parser.error("File path specified for --option-file option is invalid.")

        if not local_debug:
           if not options.sniper_root:
               options.messenger.severitywrite(appendSniperRootFooter("Can not detect sniper root."), "error")
               return 1

        shell = SniperShell(options)
        runtool = SniperRunTool(options, shell)

        return_code = 0
        out_message = ''

        if options.get_devices:
            shell.get_devices(xml=options.xml_output)
            return 0

        if options.get_event_value_list:
            return 0
        try:

            return_code = runtool.collect()

            if not options.xml_output:
                sys.stdout.write( out_message + "\n")
            return return_code
        except KeyboardInterrupt:
            options.messenger.failwrite(1)
            return 1
    finally:
        options.messenger.finalize()


if __name__ == "__main__":
    return_code = main()
    sys.exit(return_code)
    


