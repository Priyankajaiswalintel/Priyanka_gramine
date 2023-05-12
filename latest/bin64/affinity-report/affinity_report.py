#
# Copyright (C) 2018 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#

import sys
import csv
import re
import os
import subprocess
import argparse


def get_runtool_path(bin_dir):
    runtool_name = 'vtune'
    if 'win32' == sys.platform:
        runtool_name += '.exe'
    runtool_path = os.path.join(bin_dir, runtool_name)
    return runtool_path


def get_topology_from_result_config(result_path):
    config_path = os.path.join(result_path, 'config', 'context_values.cfg')
    with open(config_path, 'r') as config_file:
        for line in config_file:
            if '"logicalCPUCount"' in line:
                log_core_count_all = int(re.findall(r"int:value=\"(\d+)\"", line)[0])
            if '"packageCount"' in line:
                socket_count = int(re.findall(r"int:value=\"(\d+)\"", line)[0])
            if '"physicalCoreCount"' in line:
                core_count_all = int(re.findall(r"int:value=\"(\d+)\"", line)[0])
    topology = {
        'socket_count': socket_count,
        # number of cores per socket
        'core_count': int(core_count_all / socket_count),
        # number of logical cores per core
        'log_core_count': int(log_core_count_all / core_count_all),
        'log_core_count_socket': int(log_core_count_all / socket_count),
        'core_count_all': core_count_all,
        'log_core_count_all': log_core_count_all
    }

    return topology


def get_elapsed_time_from_result_config(result_path):
    config_path = os.path.join(result_path, 'config', 'context_values.cfg')
    elapsed_time = 0.0
    with open(config_path, 'r') as config_file:
        for line in config_file:
            if 'id="totalElapsedTime" double' in line:
                elapsed_time = float(re.findall(r"double:value=\"(\d.+)\"", line)[0])
                break

    return "{0:.2f}".format(elapsed_time)


def parse_affinity(affinity, cpu_num_to_name, topology):
    st = 0
    end = topology['log_core_count_all']
    if affinity not in ["Not set", "N/A"]:
        raw_list = affinity.split(':')
        if len(raw_list) == 1:
            socket = int(raw_list[0][1:])
            st = topology['log_core_count_socket'] * socket
            end = st + topology['log_core_count_socket']
        elif len(raw_list) == 2:
            socket = int(raw_list[0][1:])
            core = int(raw_list[1][1:])
            core = core % topology['core_count']
            # st = topology['log_core_count_socket'] * socket + (core - topology['core_count'] * socket) * topology['log_core_count']
            st = topology['log_core_count_socket'] * socket + core * topology['log_core_count']
            end = st + topology['log_core_count']
        elif len(raw_list) == 3:
            socket = int(raw_list[0][1:])
            core = int(raw_list[1][1:])
            log = int(raw_list[2][1:])
            st = cpu_num_to_name[log]['index']
            end = st + 1

    return (st, end)


def fill_row(affinity_str, cpu_num_to_name, topology, cpu_usage, thread_remote_accesses=None, cpu_index_to_numa_node=None):
    row = []
    for i in range(topology['log_core_count_all']):
        row.append({'bind': 0, 'socket-border': [], 'core-border': [], 'process-border': [], 'usage': 0, 'remote-accesses': 0, 'numa-node': -1, 'used': 0})
        if cpu_index_to_numa_node:
            if cpu_index_to_numa_node.get(i, None):
                row[-1]['numa-node'] = cpu_index_to_numa_node[i]
    affinities = affinity_str.split(',')
    for affinity in affinities:
        st, end = parse_affinity(affinity, cpu_num_to_name, topology)
        for i in range(st, end):
            row[i]['bind'] = 1

    for cpu_index, usage in cpu_usage.items():
        if cpu_index != 'total':
            row[cpu_index]['usage'] = float("{0:.1f}".format(usage))

    if thread_remote_accesses is not None:
        for cpu_index, remote_accesses in thread_remote_accesses.items():
            row[cpu_index]['remote-accesses'] = float("{0:.1f}".format(remote_accesses))
    return row


def add_border_info(data, axis_map, axis, processes, topology):
    socket_left = []
    socket_right = []

    core_border = []

    sockets = []
    for i in range(topology['socket_count']):
        sockets.append('S' + str(i))

    for socket in sockets:
        tmp = [axis_map[el] for el in axis if el.startswith(socket)]
        for i in tmp[1:-2:2]:
            core_border.append(i)
        socket_left.append(tmp[0])
        socket_right.append(tmp[-1])

    for cell in data[0]:
        cell['socket-border'].append('top')
    for cell in data[-1]:
        cell['socket-border'].append('bottom')

    for row in data:
        for i in socket_left:
            row[i]['socket-border'].append('left')
        for i in socket_right:
            row[i]['socket-border'].append('right')
        for i in core_border:
            row[i]['core-border'].append('right')

    processes_set = list(set(processes))
    process_border = []
    for process in processes_set:
        process_border.append(len(processes) - 1 - processes[::-1].index(process))
    process_border.remove(len(processes) - 1)
    for i in process_border:
        for cell in data[i]:
            cell['process-border'].append('bottom')
    return


def add_additional_info_to_data(data, used_cores, axis_map):
    for row in data:
        for i, cell in enumerate(row):
            core_num_str = re.findall(r'S(\d+):C(\d+):', axis_map[i])[0]
            core_num = (int(core_num_str[0]), int(core_num_str[1]))
            # core_num = int(re.findall(r':C(\d+):', axis_map[i])[0])
            if core_num in used_cores:
                cell['used'] = 1
    return


def generate_affinity_csv_report(result_path, bin_dir):
    amplxe_cl = get_runtool_path(bin_dir)

    args = [
        amplxe_cl,
        '-R', 'affinity',
        '-format', 'csv',
        '-csv-delimiter', 'semicolon',
        '-r', result_path
    ]

    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()
    rc = process.returncode
    if rc != 0:
        if stderr:
            stderr = stderr.splitlines()
            if stderr:
                print(stderr[-1])
    elif stdout:
        stdout = stdout.splitlines()
        return stdout
    return []


def generate_timeline_csv_report(result_path, bin_dir):
    os.environ["AMPLXE_EXPERIMENTAL"] = "time-cl"
    amplxe_cl = get_runtool_path(bin_dir)
    args = [
        amplxe_cl,
        '-R', 'time',
        '-report-knob', 'column-by=CPUTime',
        '-report-knob', 'group-by=Thread/PMUHWContext',
        '-report-knob', 'bin-count=1',
        '-format', 'csv',
        '-csv-delimiter', 'semicolon',
        '-r', result_path
    ]

    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()
    rc = process.returncode

    if rc != 0:
        if stderr:
            stderr = stderr.splitlines()
            if stderr:
                print(stderr[-1])
    elif stdout:
        stdout = stdout.splitlines()
        return stdout
    return []


def generate_numa_csv_report(result_path, bin_dir):
    amplxe_cl = get_runtool_path(bin_dir)
    args = [
        amplxe_cl,
        '-R', 'hotspots',
        '-group-by=process,thread,cpuid',
        '-column', r"NUMA: % of Remote Accesses:Self",
        '-format', 'csv',
        '-csv-delimiter', 'semicolon',
        '-r', result_path
    ]

    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()
    rc = process.returncode

    if rc != 0:
        if stderr:
            stderr = stderr.splitlines()
            if stderr:
                print(stderr[-1])
    elif stdout:
        stdout = stdout.splitlines()
        return stdout
    return []


def generate_hotspots_confidence_report(result_path, bin_dir):
    amplxe_cl = get_runtool_path(bin_dir)
    args = [
        amplxe_cl,
        '-R', 'hotspots',
        '-group-by=process,thread',
        '-column', r"CPU Time:Self",
        '-format', 'csv',
        '-csv-delimiter', 'semicolon',
        '-rep-knob', 'data-as=confidence',
        '-rep-knob', 'show-issues=false',
        '-r', result_path
    ]

    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()
    rc = process.returncode

    if rc != 0:
        if stderr:
            stderr = stderr.splitlines()
            if stderr:
                print(stderr[-1])
    elif stdout:
        stdout = stdout.splitlines()
        return stdout
    return []


def get_axisx(topology):
    axisX = []
    axis_map = {}
    cpu_num_to_name = {}
    cpu_index_to_core = {}

    for s in range(topology['socket_count']):
        for c in range(topology['core_count']):
            core_num = c
            for l in range(topology['log_core_count']):
                log_core_num = c + topology['core_count'] * s + topology['core_count_all'] * l
                log_core_name = 'S{}:C{}:L{}'.format(s, core_num, log_core_num)
                axisX.append(log_core_name)
                axis_map[log_core_name] = axisX.index(log_core_name)
                cpu_num_to_name[log_core_num] = {
                    'name': log_core_name,
                    'index': axisX.index(log_core_name),
                    'core_num': core_num,
                }
                cpu_index_to_core[axisX.index(log_core_name)] = (s, c)

    return axisX, axis_map, cpu_num_to_name, cpu_index_to_core


def get_socket_axis(topology):
    socket_axis = []
    st_pos = 0
    for i in range(topology['socket_count']):
        cell = ['Socket ' + str(i), st_pos, topology['log_core_count_socket']]
        socket_axis.append(cell)
        st_pos += topology['log_core_count_socket']
    return socket_axis


def get_core_axis(topology):
    core_axis = []
    st_pos = 0
    for s in range(topology['socket_count']):
        for c in range(topology['core_count']):
            cell = ['C' + str(c), st_pos, topology['log_core_count']]
            core_axis.append(cell)
            st_pos += topology['log_core_count']
    return core_axis


def get_process_axis(processes, threads, process_thread_confidence):
    process_axis = {}
    cur_process = processes[0]
    cur_process_count = 0
    cur_process_pos = 0
    cur_process_show_by_default = 'true'
    for i in range(len(processes)):
        if processes[i] == cur_process:
            cur_process_count += 1
        else:
            cell = [cur_process, cur_process_pos, cur_process_count, cur_process_show_by_default]
            process_axis[cur_process_pos] = cell
            cur_process_count = 1
            cur_process = processes[i]
            cur_process_pos = i
            cur_process_show_by_default = 'true'

        if process_thread_confidence.get((processes[i], threads[i]), None) == 'false':
            cur_process_show_by_default = 'false'

    cell = [cur_process, cur_process_pos, cur_process_count, cur_process_show_by_default]
    process_axis[cur_process_pos] = cell
    return process_axis


def get_cpu_usage_from_timeline_report(
        timeline_report,
        thread_header_nums,
        cpu_num_to_name):
    tid_cpu_usage = {}

    thread_context_units = []
    for i in range(len(thread_header_nums) - 1):
        st = thread_header_nums[i]
        end = thread_header_nums[i + 1]
        tmp = timeline_report[st: end]
        thread_context_units.append(tmp)
    st = thread_header_nums[-1]
    tmp = timeline_report[st:]
    thread_context_units.append(tmp)

    for unit in thread_context_units:
        tid = re.findall(r'\(TID: (\d+)\)', unit[0][0])[0]
        tid_total_cpu_usage = float(unit[2][3])
        tid_cpu_usage[tid] = {'total': tid_total_cpu_usage}
        for i in range(3, len(unit), 3):
            cpu_num = int(re.findall(r'cpu_(\d+)', unit[i][0])[0])
            cpu_index = cpu_num_to_name[cpu_num]['index']
            cpu_usage = float(unit[i + 2][3])
            tid_cpu_usage[tid][cpu_index] = cpu_usage

    return tid_cpu_usage


def get_remote_accesses_from_hotspots_report(hotspots_report, cpu_num_to_name):
    tid_cpuid_remote_accesses = {}
    for line in hotspots_report:
        if len(line) == 4 and 'TID' in line[1]:
            tid = re.findall(r'\(TID: (\d+)\)', line[1])[0]
            cpuid = int(line[2][4:])
            cpu_index = cpu_num_to_name[cpuid]['index']
            remote_accesses = line[3]
            if tid_cpuid_remote_accesses.get(tid, None) is None:
                tid_cpuid_remote_accesses[tid] = {}
            tid_cpuid_remote_accesses[tid][cpu_index] = float(remote_accesses)
    return tid_cpuid_remote_accesses


def get_used_cores(data, cpu_index_to_core):
    used_cores = set()
    for thread_row in data:
        cores_for_thread = set()
        for cpu_num, thread_cpu in enumerate(thread_row):
            if thread_cpu['bind'] == 1:
                core_num = cpu_index_to_core[cpu_num]
                cores_for_thread.add(core_num)
        for used_core in cores_for_thread:
            used_cores.add(used_core)
        # if len(cores_for_thread) == 1:
        #     used_cores.add(cores_for_thread.pop())

    return list(used_cores)


def get_cpu_index_to_numa_node(numa_info, cpu_num_to_name):
    numa_node_to_cpu = {}
    cpu_index_to_numa_node = {}
    for line in numa_info:
        node_name_string, node_cpus_string = line.split(':')
        node_num = re.findall(r'node(\d+)', node_name_string.strip())[0]
        numa_node_to_cpu[node_num] = []
        cpu_nums_string = node_cpus_string.strip().split(',')
        for cpu_nums in cpu_nums_string:
            if '-' in cpu_nums:
                nums = cpu_nums.split('-')
                for num in range(int(nums[0]), int(nums[-1]) + 1):
                    cpu_index_to_numa_node[cpu_num_to_name[num]['index']] = node_num
                    numa_node_to_cpu[node_num].append(int(num))
            else:
                cpu_index_to_numa_node[cpu_num_to_name[num]['index']] = node_num
                numa_node_to_cpu[node_num].append(int(cpu_nums))

    return cpu_index_to_numa_node


def create_html_file(
        script_dir,
        cur_dir,
        axisX,
        axisY,
        threads,
        processes,
        data,
        topology,
        html_file_name,
        socket_axis,
        process_axis,
        core_axis,
        used_cores,
        elapsed_time):
    json_string = "var json={"
    json_string += "axisX:{}".format(axisX)
    json_string += ",axisY:{}".format(axisY)
    json_string += ",threads:{}".format(threads)
    json_string += ",processes:{}".format(processes)
    json_string += ",data:{}".format(data)
    json_string += ",socketAxis:{}".format(socket_axis)
    json_string += ",processAxis:{}".format(process_axis)
    json_string += ",coreAxis:{}".format(core_axis)
    json_string += ",usedCores:{}".format(used_cores)
    json_string += ",resultInfo:{}".format({"name": html_file_name, "elapsed_time": elapsed_time})
    json_string += "};"
    html_lines = []
    template_path = os.path.join(script_dir, 'html_affinity_matrix.t')
    with open(template_path, 'r') as tmpl_file:
        for line in tmpl_file:
            if '</style><script src="data.js"></script><script>' in line:
                json_line = '</style><script>{}</script><script>'.format(json_string)
                html_lines.append(json_line)
            elif 'Number of sockets: 2' in line:
                num_sockets = 'Number of sockets: 2'
                num_cores = 'Number of physical cores per socket: 22'
                num_cpus = 'Number of logical cores per physical core: 2'
                topology_line = line.replace(num_sockets, num_sockets[:-1] + str(topology['socket_count']))
                topology_line = topology_line.replace(num_cores, num_cores[:-2] + str(topology['core_count']))
                topology_line = topology_line.replace(num_cpus, num_cpus[:-1] + str(topology['log_core_count']))
                html_lines.append(topology_line)
            else:
                html_lines.append(line)

    html_file_path = os.path.join(cur_dir, '{}.html'.format(html_file_name))

    with open(html_file_path, 'w') as html_file:
        for line in html_lines:
            html_file.write(line)

    print('Process/Thread Affinity View is here: {}.html'.format(os.path.abspath(html_file_name)))


def get_cpu_usage_for_tids(result_path, bin_dir, cpu_num_to_name):
    timeline_report = []
    thread_header_nums = []
    cpu_usage_csv_report = generate_timeline_csv_report(result_path, bin_dir)
    if not cpu_usage_csv_report:
        print('Error: cannot get timeline report.')
        print('Review errors in the output above to fix a problem or contact Intel technical support.')
        return None
    csv_reader = csv.reader(cpu_usage_csv_report, delimiter=';')
    for line in csv_reader:
        if line:
            timeline_report.append(line)
            if len(line) == 1 and 'TID:' in line[0]:
                thread_header_nums.append(len(timeline_report) - 1)

    tid_cpu_usage = get_cpu_usage_from_timeline_report(timeline_report, thread_header_nums, cpu_num_to_name)

    return tid_cpu_usage


def get_remote_accesses(result_path, bin_dir, cpu_num_to_name):
    remote_accesses_report = []
    remote_accesses_csv_report = generate_numa_csv_report(result_path, bin_dir)
    if not remote_accesses_csv_report:
        print('Error: cannot get remote accesses report.')
        print('An unknown failure has occurred. Disable Numa Remote Accesses for threads (set "-disable-r-a" to "True") or contact Intel technical support.')
        return None
    csv_reader = csv.reader(remote_accesses_csv_report, delimiter=';')
    next(csv_reader, None)  # skip header
    for line in csv_reader:
        remote_accesses_report.append(line)

    tid_cpu_remote_accesses = get_remote_accesses_from_hotspots_report(remote_accesses_report, cpu_num_to_name)
    return tid_cpu_remote_accesses


def get_affinity_report(result_path, bin_dir):
    affinity_report = []
    affinity_csv_report = generate_affinity_csv_report(result_path, bin_dir)
    if not affinity_csv_report:
        print('Error: cannot get affinity report.')
        return None
    csv_reader = csv.reader(affinity_csv_report, delimiter=';')
    next(csv_reader, None)  # skip header
    for line in csv_reader:
        affinity_report.append(line)
    return affinity_report


def get_confidence_for_processes(result_path, bin_dir):
    confidence_report = generate_hotspots_confidence_report(result_path, bin_dir)
    process_thread_confidence = {}
    if not confidence_report:
        print('Error: cannot get hotspots report.')
        print('Review errors in the output above to fix a problem or contact Intel technical support.')
        return None
    csv_reader = csv.reader(confidence_report, delimiter=';')
    for line in csv_reader:
        if len(line) == 4 and line[0] != 'Process':
            process_thread_confidence[(line[0], line[1])] = line[2]

    return process_thread_confidence


def fill_data(
        affinity_report,
        topology,
        cpu_num_to_name,
        cpu_index_to_numa_node,
        tid_cpu_usage,
        tid_cpu_remote_accesses):
    axisY = []
    threads = []
    processes = []
    # data with marks where thread was binded
    # input for rendering
    # [[1,0,0,0],[0,1,0,0],[1,0,0,0],[0,1,0,0]]
    data = []
    if len(affinity_report) == 1:
        if affinity_report[0][0] and "Thread affinity information was not collected" in affinity_report[0][0]:
            print("Error: result does not contain Thread affinity information so the affinity report cannot be generated for the result.\nUse 'vtune -collect hpc-performance -knob collect-affinity=true' to collect thread affinity information.")
            return None, None, None, None
    for row in affinity_report:
        process, thread, affinity = row
        tid = re.findall(r'\(TID: (\d+)\)', thread)[0]
        axisY.append(tid)
        threads.append(thread)
        processes.append(process)
        thread_remote_accesses = tid_cpu_remote_accesses.get(tid, None)
        filled_row = fill_row(affinity, cpu_num_to_name, topology, tid_cpu_usage[tid], thread_remote_accesses, cpu_index_to_numa_node)
        data.append(filled_row)

    return data, axisY, threads, processes


def main():
    parser = argparse.ArgumentParser(description="", prog="aff_matrix_report.sh")
    parser.add_argument("-r", dest="result",
                        help="path to HPC Performance result collected with option '-knob collect-affinity=true'",
                        default=None)
    parser.add_argument("-vtune-bindir", dest="bin_dir",
                        help=argparse.SUPPRESS,
                        default=None)
    parser.add_argument("-script-dir", dest="script_dir",
                        help=argparse.SUPPRESS,
                        default=None)
    parser.add_argument("-cur-dir", dest="cur_dir",
                        help=argparse.SUPPRESS,
                        default=None)
    parser.add_argument("-add-numa", dest="add_numa",
                        help=argparse.SUPPRESS,
                        default=False)

    parser.add_argument("-disable-r-a", dest="not_show_remote_accesses",
                        help="set 'True' to disable show of Numa Remote Accesses for threads",
                        default=False)
    args = parser.parse_args()

    affinity_report = []
    topology = []

    if ((args.cur_dir is None) or
        (args.script_dir is None) or
            (args.bin_dir is None)):
        print("Error: please use 'vtune -R affinity -format html -r my_result' to run report")
        return

    if args.result is not None:
        result_path = os.path.abspath(args.result)
        config_path = os.path.join(result_path, 'config', 'context_values.cfg')
        if not os.path.isfile(config_path):
            print('Error: not valid path to result')
            return

        topology = get_topology_from_result_config(result_path)
        axisX, axis_map, cpu_num_to_name, cpu_index_to_core = get_axisx(topology)
        elapsed_time = get_elapsed_time_from_result_config(result_path)

        tid_cpu_usage = get_cpu_usage_for_tids(result_path, args.bin_dir, cpu_num_to_name)
        if tid_cpu_usage is None:
            return

        if args.not_show_remote_accesses is False:
            tid_cpu_remote_accesses = get_remote_accesses(result_path, args.bin_dir, cpu_num_to_name)
            if tid_cpu_remote_accesses is None:
                return
        else:
            tid_cpu_remote_accesses = dict()

        affinity_report = get_affinity_report(result_path, args.bin_dir)
        if affinity_report is None:
            return

        process_thread_confidence = get_confidence_for_processes(result_path, args.bin_dir)
    else:
        parser.print_help()
        return

    axisY = []
    threads = []
    processes = []

    # Concept of add numa info
    if args.add_numa:
        numa_info = ["NUMA node0 CPU(s):     0-21,44-65", "NUMA node1 CPU(s):     22-43,66-87"]
        cpu_index_to_numa_node = get_cpu_index_to_numa_node(numa_info, cpu_num_to_name)
    else:
        cpu_index_to_numa_node = {}

    socket_axis = get_socket_axis(topology)
    core_axis = get_core_axis(topology)

    data, axisY, threads, processes = fill_data(affinity_report, topology, cpu_num_to_name, cpu_index_to_numa_node, tid_cpu_usage, tid_cpu_remote_accesses)
    if data is None:
        return

    used_cores = get_used_cores(data, cpu_index_to_core)

    process_axis = get_process_axis(processes, threads, process_thread_confidence)

    add_border_info(data, axis_map, axisX, processes, topology)

    add_additional_info_to_data(data, used_cores, axisX)

    html_file_name = 'affinity_matrix'
    if args.result is not None:
        html_file_name = os.path.basename(os.path.abspath(args.result))

    if (args.cur_dir is not None) and (args.script_dir is not None):
        create_html_file(args.script_dir, args.cur_dir, axisX, axisY, threads, processes, data, topology, html_file_name, socket_axis, process_axis, core_axis, used_cores, elapsed_time)
    else:
        print("Error: please use 'vtune -R affinity -format html -r my_result' to run report")


if __name__ == "__main__":
    ret_code = main()
    sys.exit(ret_code)
