#!/bin/bash
#
# Copyright (C) 2020 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you ("License"). Unless
# the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or implied
# warranties, other than those that are expressly stated in the License.
#

TOOL_NAME_LONG="Intel(R) VTune(TM) Profiler - Platform Profiler"
COLLECTOR_DATA_VERSION=6
COLLECTOR_SCRIPTS_DIR=$( dirname "${BASH_SOURCE[0]}" )
# The VPP_COLLECTOR_DIR AND DSTAT_PLUGINS_DIR variables are location-dependent, i.e.,
# if the location of this script or the VPP Collector scripts change, then they
# must be adjusted accordingly
VPP_COLLECTOR_DIR="$COLLECTOR_SCRIPTS_DIR/../../../vpp/collector"
DSTAT_PLUGINS_DIR="$VPP_COLLECTOR_DIR/bin/plugins"

function usage {
    echo ""
    echo "Usage: collect-os-counters [-d --dry-run -h --help]"
    echo ""
    echo "Starts a data collection session. To stop an active data collection session, "
    echo "press Ctrl + C"
    echo ""
    echo "Optional parameters: "
    echo -e "  -d <path to results dir>: Directory that stores data collection results"
    echo -e "  --dry-run Check if dstat can collect data"
    echo -e "  --help: \t\t    Display this help message and exit"
    echo ""

}

# Modifies OS_NAME
function get_os_details {
    OS_VERSION="Unknown"
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ -n $PRETTY_NAME ]]; then
            OS_NAME=$PRETTY_NAME
        fi
        if [[ -n $VERSION_ID ]]; then
            OS_VERSION=$VERSION_ID
        fi
    elif [[ -f /etc/redhat-release ]]; then
        OS_NAME=$(cat /etc/redhat-release | sed -n '1p')
    elif [[ -f /etc/SuSE-release ]]; then
        OS_NAME=$(cat /etc/SuSE-release | sed -n '1p')
    elif [[ -f /etc/lsb-release ]]; then
        OS_NAME=$(cat /etc/lsb-release | grep "CHROMEOS_RELEASE_NAME" | cut -d "=" -f1 --complement)
    else
        OS_NAME="Unknown Linux"
    fi
}

# Sets the result_location and isCheck
function parse_command_options {
    result_location=""
    isCheck=false
    local OPTIND=1
    while getopts "d:-:h" opt; do
        case "$opt" in
        # Save off the result location using the command readlink if it exists
        # otherwise build the absolute path with pwd
        d) if [[ -z $( which readlink ) ]]; then
               if [[ $OPTARG == /* ]] || [[ $OPTARG == ~* ]]; then
                   result_location="${OPTARG}/"
               else
                   result_location="`pwd -P`/${OPTARG}/"
               fi
           else
               result_location=`readlink -f "$OPTARG/"`
               result_location="${result_location}/"
           fi
           ;;
        # Abbreviated help option
        h) usage
           exit;;
        -)
            case ${OPTARG} in
                help) usage
                      exit ;;
                dry-run) isCheck=true ;;
                *) usage
                   exit;;
            esac
            ;;
        *) usage
           exit
           ;;
        esac
    done

    bad_param=${@:$OPTIND:1}
    if [[ -n $bad_param ]]; then
        usage
        exit
    fi
}

function get_temp_dir {
    local TMP_DIR=""${TMPDIR}""
    if [[ ! -d $TMP_DIR ]] ; then
        if [[ ! -d /tmp ]] ; then
            echo "ERROR: The $TOOL_NAME_LONG collector requires a temporary directory, but the TMPDIR environment variable is not set and /tmp does not exist." >&2
            exit 1
        else
            TMP_DIR="/tmp"
        fi
    fi
    echo $TMP_DIR
}

function get_full_temp_dir {
    local TMP_DIR=$(get_temp_dir)
    PGX_DIR="/.vpp-collector/"
    USR_DIR=$USER
    # The full temp directory is /$TMP/.vpp-collector/<username>
    local FULL_TMP_DIR="$TMP_DIR$PGX_DIR$USR_DIR"
    echo $FULL_TMP_DIR
}

function get_and_make_full_temp_dir {
    local FULL_TMP_DIR=$(get_full_temp_dir)
    local PARENT_DIR=$(dirname $FULL_TMP_DIR)

    if [[ ! -d $PARENT_DIR ]] ; then
        mkdir ""$PARENT_DIR""
        chmod a+w "$PARENT_DIR"
    fi

    # Make the full temp directory if it doesn't exist
    mkdir -p ""${FULL_TMP_DIR}""
    echo $FULL_TMP_DIR
}

function ensure_location_is_writable {
    local location="$1"
    if ! [[ -w $location ]]; then
        echo "ERROR: Unable to write to result directory: $location. Collection aborted." >&2
        exit 1
    fi
}

function check_version() {
    test "$(echo "$@" | tr " " "\n" | sort --version-sort | head -n 1)" != "$1"
}

function find_pid {
    local image_name=$1
    local extra=$2
    echo $( ps -ef | grep $image_name | grep $extra | grep -v grep | cut -d \  -f 2- | sed -e 's/^[[:space:]]*//' | cut -d \  -f 1 )
}

function find_uid {
    local pid=$1
    echo $( ps -fp $pid | cut -d \  -f 1 ) | awk '{print $2}'
}

function pid_is_running {
    local pid=$1
    local count=$(ps -A| grep $pid |wc -l)
    test $count -gt 0
}

function clean_up {
    rm -f "$RESULT_LOCATION_FILE"
    if [[ -d $FULL_TMP_DIR ]]; then
        rmdir "$FULL_TMP_DIR"
    fi
}

# sets TMP_DIR, PGX_DIR, USR_DIR, FULL_TMP_DIR
function create_temp_directory {
    TMP_DIR=$(get_temp_dir)
    FULL_TMP_DIR=$(get_and_make_full_temp_dir)
}

# Modifies result_location
function prepare_result_location {
    # If result_location is not given, assign it under the current dir
    if [[ -z $result_location ]]; then
        result_location="$PWD/"
    fi

    ensure_location_is_writable "$result_location"
}

# Depends on $FULL_TMP_DIR
function set_globals_to_start {
    local HOSTNAME=.$( hostname -s )
    DSTAT_TMP="_tmp_storage"
    DSTAT_TMP_DEST="$FULL_TMP_DIR/$HOSTNAME$DSTAT_TMP"
    DSTAT_QUEUE=''
    DSTAT_TIME=''
}

function pcp_dstat_is_available {
    local result=1
    if command -v pcp > /dev/null 2>&1; then
        PCP_DSTAT=$( dstat -V | grep pcp-dstat | cut -f1 -d" " )
        if [[ $PCP_DSTAT == "pcp-dstat" ]]; then
	    result=0
        fi
    fi
    
    return $result
}

function ensure_dstat_is_installed {
    dstat_missing_msg="Error: $TOOL_NAME_LONG requires dstat version >= 0.7.2"
    MIN_UBUNTU_VERSION_FOR_PCP_DSTAT="19.10"
    if [[ $OS_NAME =~ .*"Ubuntu".* ]] && check_version $OS_VERSION $MIN_UBUNTU_VERSION_FOR_PCP_DSTAT; then
        dstat_missing_msg="Error: $TOOL_NAME_LONG requires pcp (Performance Co-Pilot tools)"
    fi
    if ! pcp_dstat_is_available; then
        if [[ -z $( which dstat ) ]]; then
            echo $dstat_missing_msg
            exit 1
        fi
        DSTAT_VERSION=$( dstat -V | grep Dstat | cut -f2 -d" " )
        DSTAT_MINIMUM_VERSION="0.7.0"
        if [[ $DSTAT_VERSION == "0.8.0" ]]; then
            echo "Error: dstat version $DSTAT_VERSION is not supported."
            echo "Please install pcp (Performance Co-Pilot tools) instead."
            exit 1
        fi
        if check_version $DSTAT_MINIMUM_VERSION $DSTAT_VERSION; then
            echo $dstat_missing_msg
            echo "This system has dstat version $DSTAT_VERSION installed."
            exit 1
        fi
    fi
}

function ensure_dstat_plugins_are_installed {
    if ! pcp_dstat_is_available; then
        # Check if the plugins are installed in the ~/.dstat directory
        if [[ -d $DSTAT_PLUGINS_DIR ]] ; then
            if [[ ! -d ~/.dstat ]] ; then
                mkdir -p ~/.dstat
            fi
            for dstat_plugin in ${DSTAT_PLUGINS_DIR}/* ; do
                dstat_plugin_base=`basename ${dstat_plugin}`
                if [[ ! -f ~/.dstat/${dstat_plugin_base} ]] ; then
                    cp ${dstat_plugin} ~/.dstat
                else
                    diff_result=$( diff -q ${dstat_plugin} ~/.dstat/${dstat_plugin_base} > /dev/null )
                    if [ $? -ne 0 ] ; then
                        cp ${dstat_plugin} ~/.dstat
                    fi
                fi
            done
            DSTAT_QUEUE='--disk-queue'
            DSTAT_TIME='--disk-time'
        fi
    fi
}

function ensure_dstat_is_not_running {
    # For systems using pcp-dstat, the 'dstat' command is present as a symbolic link
    # This allows the 'find_pid' function to return a pid for either dstat or pcp-dstat
    DSTAT_PID=$( find_pid dstat $DSTAT_TMP_DEST )

    if [[ -n $DSTAT_PID ]]; then
        echo "ERROR: An instance of dstat is running. Stop dstat and retry." >&2
        exit 1
    fi
}

# Depends on $FULL_TMP_DIR
function create_result_location {
    local RESULT_LOCATION_FILE
    RESULT_LOCATION_FILE="$FULL_TMP_DIR/.result_location"

    #remove any existing .result_location file
    if [[ -e $RESULT_LOCATION_FILE ]]; then
        rm $RESULT_LOCATION_FILE
    fi

    if ! mkdir -p "$result_location"; then
        echo "ERROR: Unable to create $result_location. Collection aborted." >&2
        exit 1
    fi

    echo "$result_location" > $RESULT_LOCATION_FILE

    local BASENAME=.$( hostname -s )
    DSTAT_CSV="_dstat.csv"
    DEST="$result_location/$BASENAME$DSTAT_CSV"
}

function init_output_file {
    # Delete the csv file before starting dstat, since dstat appends to any
    # existing file instead of always creating a new file
    rm -f "$DEST"
}

# if the given device name is a block device, add it to LIST_OF_DISKS
# Modifies LIST_OF_DISKS
function blockdevices {
    declare -a BLOCK_DEVICES=($(ls /sys/block))
    for DEVICE_NAME in ${BLOCK_DEVICES[@]} ; do
        if [[ $DEVICE_NAME == "$1" ]]; then
            if [[ -z $LIST_OF_DISKS ]]; then
                LIST_OF_DISKS="$DEVICE_NAME"
            else
                LIST_OF_DISKS="$DEVICE_NAME,$LIST_OF_DISKS"
            fi
        fi
    done
}

# Fetch information about the network interface. This is truly
# ugly. The file is showing as readable, but attempting to read it
# gives an invalid argument error. So attempt to read it into a
# temporary variable, then see if we got anything. Bletch!
#
# NET_SPEED and NET_DUPLEX and NET_DEVICES are arrays, since we are
# keeping track of separate network devices.
# NET_DEVICES_CSV is a csv in the same order as NET_SPEED, NET_DUPLEX
# and NET_DEVICES and is used as an argument to dstat
#
#
# Modifies NET_DEVICES_CSV, RDMA_DEVICES, NET_DEVICES, NET_SPEED, NET_DUPLEX, DSTAT_RDMA
function gather_network_device_info {
    NET_DEVICES_CSV=""
    DSTAT_RDMA=''
    index=0
    declare -a RDMA_DEVICES
    x=0
    for DEV in $( ls /sys/class/net ); do
        # Don't record the "lo" network interface
        if [[ $DEV != "lo" ]]; then
            NET_DEVICES_CSV="$NET_DEVICES_CSV$DEV,"
            NET_DEVICES[$index]=$DEV
            TMP=""
            TMP=$( cat /sys/class/net/$DEV/speed 2> /dev/null )
            # -1 indicates an unknown network speed. Ignore it.
            if [[ $TMP == "-1" ]]; then
                TMP=""
            fi

            # Some distros report the network speed as an unsigned 32-bit integer, so 4294967295 is -1, which indicates an unknown network speed. Ignore it also.
            if [[ $TMP == "4294967295" ]]; then
                TMP=""
            fi

            # Some distros report the network speed as an unsigned 16-bit value (65535). Ignore it.
            if [[ $TMP == "65535" ]]; then
                TMP=""
            fi

            if [[ -n $TMP ]]; then
                NET_SPEED[$index]=$TMP
            else
                NET_SPEED[$index]="0"
            fi

            TMP=""
            TMP=$( cat /sys/class/net/$DEV/duplex 2> /dev/null )
            if [[ -n $TMP ]]; then
                NET_DUPLEX[$index]=$TMP
            else
                NET_DUPLEX[$index]="none"
            fi


            # Include RDMA plugin in dstat if RDMA devices exist
            if [[ -d /sys/class/net/$DEV/device/infiniband ]]; then
		        if ! pcp_dstat_is_available; then
                    if [[ -f ~/.dstat/dstat_net_rdma.py ]]; then
                        DSTAT_RDMA='--net-rdma'
                    fi
                fi
                for i in "$(ls /sys/class/net/$DEV/device/infiniband)"; do
                    RDMA_DEVICES[${#RDMA_DEVICES[@]}+1]=$DEV/$i
                done
            fi

            let "index++"
        fi
    done
    NET_DEVICES_CSV="${NET_DEVICES_CSV}total"
}

function gather_cpu_info {
    CPU_CORES=$( grep -c processor /proc/cpuinfo )
    CPU_SOCKETS=$( grep "physical id" /proc/cpuinfo | sort -n | uniq | wc --lines )
    CPU_CORES_PER_SOCKET=$( grep "cpu cores" /proc/cpuinfo | uniq | awk '{print $NF}' )
    if [[ -z $CPU_CORES_PER_SOCKET ]]; then
        CPU_CORES_PER_SOCKET=1
    fi
    CPU_MODEL=$( grep "model name" /proc/cpuinfo | uniq | cut -f 2 | cut -d \  -f 2- )
    CPU_THREADS_PER_CORE=$(( $CPU_CORES / ($CPU_SOCKETS * $CPU_CORES_PER_SOCKET) ))
}

function gather_memory_info {
    MEMORY_SIZE_IN_KB=$( grep "MemTotal" /proc/meminfo | cut -d \  -f 2- | rev | cut -d \  -f 2- | rev | tr -d '[[:space:]]' )
    SWAP_SIZE_IN_KB=$( grep "SwapTotal" /proc/meminfo | cut -d \  -f 2- | rev | cut -d \  -f 2- | rev | tr -d '[[:space:]]' )
}

function gather_disk_info {
    # Get the list of disks from lsblk
    DISK_NAMES_STRING=$( lsblk --nodeps --list --output NAME,TYPE| grep "disk" | awk '{printf ("%s, ", $1)}' )
    IFS=', ' read -r -a DISK_NAMES_ARRAY <<< "$DISK_NAMES_STRING"
    for NAME in "${DISK_NAMES_ARRAY[@]}" ; do
        blockdevices $NAME
    done

    # Disk information - we're just interested in the physical disks
    SYSTEM_DISKS={}
    DISK_NAME={}
    DISK_ROTATION={}
    DISK_INDEX=0
    while read MAJOR MINOR BLOCKS DEVICE; do
        if [[ ${LIST_OF_DISKS/$DEVICE} != "$LIST_OF_DISKS" ]]; then
            MODEL_PATH="/sys/block/$DEVICE/device/model"
            if [[ -r $MODEL_PATH ]]; then
                NAME=$( cat $MODEL_PATH )
            else
                NAME="unknown model"
            fi

            # Save the information for future usage.. We haven't used them yet.
            SYSTEM_DISKS[$DISK_INDEX]=$DEVICE
            DISK_NAME[$DISK_INDEX]=$NAME
            DISK_ROTATION[$DISK_INDEX]=$( cat /sys/block/$DEVICE/queue/rotational )

            # So far we wrap all the disk information in this part.
            if [[ ${DISK_ROTATION[$DISK_INDEX]} -eq 1 ]]; then
                if [[ -z $LIST_OF_HDD ]]; then
                    LIST_OF_HDD="$DEVICE($NAME)"
                else
                    LIST_OF_HDD="$DEVICE($NAME), $LIST_OF_HDD"
                fi
            elif [[ ${DISK_ROTATION[$DISK_INDEX]} -eq 0 ]]; then
                device_root=/sys/block/$DEVICE
                if [[ -e $device_root/device ]]; then
                    device_uevent=$device_root/device/uevent
                else
                    device_uevent=$device_root/uevent
                fi
                DISK_PCI_MODEL=$( grep PCI_ID $device_uevent | cut -f2 -d"=" )
                DISK_PCI_SLOT=$( grep PCI_SLOT_NAME $device_uevent | cut -f2 -d"=" )
                if [[ -z $DISK_PCI_MODEL ]]; then
                    PRINT_NAME="$NAME"
                else
                    PRINT_NAME="$NAME,$DISK_PCI_MODEL,$DISK_PCI_SLOT"
                fi
                if [[ -z $LIST_OF_SSD ]]; then
                    LIST_OF_SSD="$DEVICE($PRINT_NAME)"
                else
                    LIST_OF_SSD="$DEVICE($PRINT_NAME), $LIST_OF_SSD"
                fi
            fi

            DISK_INDEX=$(( $DISK_INDEX + 1 ))
        fi
    done < /proc/partitions

    if [[ -z $LIST_OF_SSD ]]; then
        LIST_OF_SSD="none"
    fi
    if [[ -z $LIST_OF_HDD ]]; then
        LIST_OF_HDD="none"
    fi
}

function gather_configuration_info {
    gather_network_device_info
    gather_cpu_info
    gather_memory_info
    gather_disk_info
}

# Writes to the $DEST file
function write_configuration_info {
    set -e
    echo "/*** CONFIGURATION INFORMATION ***/" >> "$DEST"
    echo "\"Linux dstat\"" >> "$DEST"

    # Get the number of network interfaces by checking the size of one of the arrays.
    max_net=${#NET_SPEED[@]}

    # The network speed is given in megabits/sec
    # Since the data given us by dstat is in bytes, multiply by 1,000,000 and
    # then divide by 8. Then divide by 100 to get percent.

    # Have a default network information entry for now, since the server code expects it.
    # Note this may seem clunky, but it is basically what the code always did before, stopping after reading
    # the first good value. This code will be removed soon.
    i=0
    while [[ $i -lt $max_net ]]; do
        if [[ ${NET_SPEED[$i]} -gt 0 ]]; then
            NET_BANDWIDTH=$(( (${NET_SPEED[$i]} * 1000 * 1000 / 8) / 100 ))
            echo "\"netSpeed = ${NET_SPEED[$i]}\"" >> "$DEST"
            echo "\"netBandwidth = $NET_BANDWIDTH\"" >> "$DEST"
            echo "\"netFullDuplex = $(echo "${NET_DUPLEX[$i]}" | tr '[:upper:]' '[:lower:]')\"" >> "$DEST"
            break
        fi
        let "i++"
    done

    # Write the network information for each separate interface.
    i=0
    while [[ $i -lt $max_net ]]; do
        NET_BANDWIDTH=$(( (${NET_SPEED[$i]} * 1000 * 1000 / 8) / 100 ))
        echo "\"netSpeed.${NET_DEVICES[$i]} = ${NET_SPEED[$i]}\"" >> "$DEST"
        echo "\"netBandwidth.${NET_DEVICES[$i]} = $NET_BANDWIDTH\"" >> "$DEST"
        echo "\"netFullDuplex.${NET_DEVICES[$i]} = $(echo "${NET_DUPLEX[$i]}" | tr '[:upper:]' '[:lower:]')\"" >> "$DEST"
        let "i++"
    done

    # Write the OS and CPU information
    echo "\"os_name = $OS_NAME\"" >> "$DEST"
    echo "\"cpu_model = $CPU_MODEL\"" >> "$DEST"
    echo "\"cpu_cores = $CPU_CORES\"" >> "$DEST"
    echo "\"cpu_sockets = $CPU_SOCKETS\"" >> "$DEST"
    echo "\"cpu_cores_per_socket = $CPU_CORES_PER_SOCKET\"" >> "$DEST"
    echo "\"cpu_threads_per_core = $CPU_THREADS_PER_CORE\"" >> "$DEST"

    # Write the memory information
    echo "\"memory_size = $MEMORY_SIZE_IN_KB\"" >> "$DEST"
    echo "\"swap_size = $SWAP_SIZE_IN_KB\"" >> "$DEST"

    # Timezone information
    echo "\"timezoneOffset = $( date +%:z )\"" >> "$DEST"
    echo "\"timezoneAbbrev = $( date +%Z )\"" >> "$DEST"

    # Disk information from gather_disk_info
    echo "\"list_of_ssd = $LIST_OF_SSD\""    >> "$DEST"
    echo "\"list_of_hdd = $LIST_OF_HDD\""    >> "$DEST"
    echo "\"pagesize = `getconf PAGESIZE`\"" >> "$DEST"

    # mapping  of logical volumes to physical volume
    # reverse map the logical device to the associated physical device using lsblk
    LOG_DEV=()
    phy_dev_final=()
    single_device=()

    if [[ -f /proc/mdstat ]]; then
        no_of_lines=$( cat /proc/mdstat | grep "md" | wc -l)
        for l in `seq 1 $no_of_lines`; do
            raid[l]=$(cat /proc/mdstat | grep "md" | sed -n "${l}p" | tr ":" "\n" | sed 's/\<active\>//')
            raid1[l]=$(echo ${raid[l]} | cut -d ' ' -f2 --complement )
            md_device=$(echo ${raid1[l]} | awk '{print $1}')
            LOG_DEV[l]=$(echo ${raid1[l]} | cut -d ' ' -f1 --complement | sed -e 's/\[[^][]*\]//g')
            for k in $seq 0 1 ; do
                single_device=(${LOG_DEV[l]})
                phy_dev[k]=$(lsblk | grep -B 1 ${single_device[k]} | grep "disk" | awk '{print $1}')
            done
            if [[ -z $LIST_OF_MD ]]; then
                LIST_OF_MD="$md_device(${phy_dev[@]})"
            else
                LIST_OF_MD="$md_device(${phy_dev[@]}), $LIST_OF_MD"
            fi
        done
        echo "\"list_of_md = $LIST_OF_MD\"" >> "$DEST"
    fi

    echo "\"list_of_rdma = ${RDMA_DEVICES[@]}\"" >> "$DEST"
    # Version that (hopefully) will allow us to change the data and verify that
    # the Javascript understands what it's seeing
    echo "\"dataVersion = $COLLECTOR_DATA_VERSION\"" >> "$DEST"
    set +e
}

# Gather dstat information we need for analysis
#
# dstat options used:
#
# --nocolor knocks out the escape sequences to color the data
#
# --noheaders knocks out the periodic repetition of the headers, as well as
#   updates every second for intermediate values
#
# --epoch - displays the time for each sample as seconds since 1-Jan-1970
#
# --cpu - displays CPU stats for the total system (all CPUs). The data
#   includes system (kernel) time, idle time, io wait time, and time spent
#   servicing hard and soft interrupts
#
# --net - displays bytes sent and received
#
# -N <netdevicelist> - displays stats for each network device separately
#
# -dD <disklist> - displays disk stats for the specified disks
#
# --io - displays I/O requests completed
#
# --disk-queue - displays the instantaneous queue depth at the moment of collection
#
# --disk-time - displays the amount of time spent in disk accesses for the last epoch
#
# --output file - writes CSV output to file
#
# By default dstat samples the information once per second
function start_dstat_collection {
    rm -f $DSTAT_TMP_DEST
    dstat --nocolor --noheaders --epoch --cpu --net -N $NET_DEVICES_CSV -dD $LIST_OF_DISKS $DSTAT_QUEUE $DSTAT_TIME --io --mem --page --vm $DSTAT_RDMA --output $DSTAT_TMP_DEST > /dev/null &
    child_pid=$!
    wait $child_pid
}

function save_result {
    local input="$1"
    local output="$2"
    if [[ -f $input ]]; then mv "$input" "$output"; fi
}

function check_if_sudo_privilege_is_necessary_to_stop {
    local dstat_pid=$( pidof dstat)
    if [[ -n $dstat_pid ]]; then
        dstat_uid=$(find_uid "$dstat_pid")
    fi
    if [[ $dstat_uid == "root" && $( whoami ) != "root" ]]; then
        echo "ERROR: The current dstat collection was started with elevated (sudo) privileges.">&2
        exit 1
    fi
}

function check_if_collection_is_in_progress {
    FULL_TMP_DIR=$(get_full_temp_dir)
    RESULT_LOCATION_FILE="$FULL_TMP_DIR/.result_location"
    result_location=$(cat "$RESULT_LOCATION_FILE" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "ERROR: No active data collection session detected." >&2
        exit 1
    fi
}

function set_globals_to_stop {
    check_if_collection_is_in_progress

    HOSTNAME=.$( hostname -s )
    DSTAT_CSV="_dstat.csv"
    DSTAT_TMP="_tmp_storage"
    DEST="$result_location/$HOSTNAME$DSTAT_CSV"
    DSTAT_TMP_DEST="$FULL_TMP_DIR/$HOSTNAME$DSTAT_TMP"
}

function stop_dstat {
    DSTAT_PID=$(find_pid dstat "$DSTAT_TMP_DEST")

    if [[ -n $DSTAT_PID ]]; then
        kill -9 $DSTAT_PID > /dev/null 2>&1
    fi
}

function ensure_result_dir_exists {
    # Exit if RESULT_DIR does not exist.
    if [[ ! -d $RESULT_DIR ]]; then
        echo "ERROR: Result directory ${RESULT_DIR} does not exist. Results not saved." >&2
        clean_up
        exit 1
    fi
}

function ensure_result_dir_is_writable {
    # Exit if RESULT_DIR is not writable.
    if [[ ! -w $RESULT_DIR ]] ; then
        echo "ERROR: Result directory ${RESULT_DIR} is not writable. Results not saved." >&2
        clean_up
        exit 1
    fi
}

function finalize_collection_results {
    # cat dstat output in temp file to dstat.csv
    echo "\"comment = $1\"" >> "$DEST"
    echo "" >> "$DEST"
    echo "/*** START OF PROFILING OUTPUT ***/" >> "$DEST"
    cat $DSTAT_TMP_DEST >> "$DEST"
    rm -f $DSTAT_TMP_DEST

    STORAGE_FILENAME=storage.dat

    save_result "$DEST" "$RESULT_DIR/$STORAGE_FILENAME"
}

function control_c {
    check_if_sudo_privilege_is_necessary_to_stop &&
    set_globals_to_stop &&
    stop_dstat &&
    RESULT_DIR="$result_location" &&
    ensure_result_dir_exists &&
    ensure_result_dir_is_writable &&
    finalize_collection_results &&
    clean_up
}

get_os_details
parse_command_options "$@"

if [ "$isCheck" = true ]; then
    ensure_dstat_is_installed &&
    ensure_dstat_plugins_are_installed &&
    ensure_dstat_is_not_running
    exit
else
    create_temp_directory &&
    prepare_result_location &&
    ensure_dstat_is_installed &&
    ensure_dstat_plugins_are_installed &&
    ensure_dstat_is_not_running &&
    create_result_location &&
    init_output_file &&
    gather_configuration_info &&
    write_configuration_info &&
    echo "Collection in progress. Press Ctrl + C to stop." &&
    # Exit script and clean-up when Control + C is pressed
    trap control_c SIGINT &&
    trap control_c SIGTERM &&
    start_dstat_collection
fi
