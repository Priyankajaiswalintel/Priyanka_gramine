#!/bin/sh
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

#
# File: prepare-debugfs
#
# Description: script which either installs bootscript which prepares
#     debugfs for Intel(R) VTune(TM) Profiler, or performs this operation once
#
# Version: 1.2
#

PATH="/sbin:/usr/sbin:/bin:/usr/bin/:/usr/local/sbin:/usr/local/bin:/usr/local/gnu/bin:.:"${PATH}
export PATH

# ------------------------------- OUTPUT -------------------------------------
print_msg()
{
    MSG="$*"
    echo "$MSG"
}

print_nnl()
{
    MSG="$*"
    echo -n "$MSG"
}

print_err()
{
    MSG="$*"
    if [ -w /dev/stderr ] ; then
        echo "$MSG" >> /dev/stderr
    else
        echo "$MSG"
    fi
}

# ------------------------------ COMMANDS ------------------------------------
GREP="grep"
LN="ln"
RM="rm"
SED="sed"
SU="su"
WHICH="which"
MOUNT="mount"
UMOUNT="umount"
CHMOD="chmod"
CHGRP="chgrp"
AWK="awk"
HEAD="head"
FIND="find"
PKG_CONFIG="pkg-config"

COMMANDS_TO_CHECK="${LN} ${RM} ${SED} ${WHICH} ${MOUNT} ${UMOUNT} ${CHMOD} ${CHGRP} ${AWK} ${HEAD} ${FIND} ${PKG_CONFIG}"

#
# Note: Busybox has a restricted shell environment, and
#       conventional system utilities may not be present;
#       so need to account for this ...
#

# busybox binary check
BUSYBOX_SHELL=` ${GREP} --help 2>&1 | ${GREP} BusyBox`

if [ -z "${BUSYBOX_SHELL}" ] ; then
    COMMANDS_TO_CHECK="${SU} ${COMMANDS_TO_CHECK}"
fi

# if any of the COMMANDS_TO_CHECK are not executable, then exit script
OK="true"
for c in ${COMMANDS_TO_CHECK} ; do
    CMD=`${WHICH} $c 2>&1` ;
    if [ -z "${CMD}" ] ; then
        OK="false"
        print_err "ERROR: unable to find command \"$c\" !"
    fi
done

if [ ${OK} != "true" ] ; then
    print_err "Please add the location to the above commands to your PATH and re-run the script ... exiting."
    exit 255
fi

# ------------------------------ VARIABLES -----------------------------------

SCRIPT=$0
SCRIPT_ARGS="$@"
BOOTSCRIPT_INITD="vtune_debugfs"
BOOTSCRIPT_SYSTEMD="vtune-prepare-debugfs.service"
SELF_INSTALL_NAME="vtune-prepare-debugfs.sh"
PRODUCT_NAME="Intel VTune Profiler"

# ------------------------------ FUNCTIONS -----------------------------------

# function to show usage and exit
default_group='vtune'

print_usage_and_exit()
{
    err=${1:-0}
    print_msg ""
    print_msg "Usage: $0 [ option ]"
    print_msg ""
    print_msg " where \"option\" is one of the following:"
    print_msg ""
    print_msg "    -h | --help"
    print_msg "      Prints out usage."
    print_msg ""
    print_msg "    -i | --install"
    print_msg "      Configures the autoload debugfs boot script and then installs it in the "
    print_msg "      appropriate system directory."
    print_msg ""
    print_msg "    --user <user>"
    print_msg "      Adds the specified user to the group with debugFS access permissions. "
    print_msg ""
    print_msg "    -u | --uninstall"
    print_msg "      Uninstalls a previously installed debugfs boot script and "
    print_msg "      reverts configuration."
    print_msg ""
    print_msg "    -g | --group <group>"
    print_msg "      Specifies the group other than '$default_group' to access debugFS."
    print_msg ""
    print_msg "    -c | --check"
    print_msg "      Performs mount and permisions check."
    print_msg ""
    print_msg "    -r | --revert"
    print_msg "      Reverts debugfs configuration."
    print_msg ""
    print_msg "    -b | --batch"
    print_msg "      Run in non-interactive mode (exit in case of already changed permissions)."
    print_msg ""
    print_msg " Without options, script will configure debugfs."
    exit $err
}

# --------------------------------- MAIN -------------------------------------

# if only help option specified, then show options
if [ $# -eq 1 ] ; then
    case "$1" in
        -h | --help)
        print_usage_and_exit 0
        ;;
    esac
fi

# check if USER is root
if [ -z "${BUSYBOX_SHELL}" ] ; then
    if [ "$(id -u)" -ne 0 ] ; then
        if [ ! -w /dev ] ; then
            print_msg "NOTE:  super-user or \"root\" privileges are required in order to continue."
            print_nnl "Please enter \"root\" "
            exec ${SU} -c "/bin/sh ${SCRIPT} ${SCRIPT_ARGS}"
            print_msg ""
            exit 0
        fi
    fi
fi

# parse the options
install_boot_script=0
uninstall_boot_script=0
configure_debugfs=1
exit_after_check=0
interactive=1
username=""

while [ $# -gt 0 ] ; do
    case "$1" in
        -i | --install)
            install_boot_script=1
            interactive=0
            ;;
        -u | --uninstall)
            configure_debugfs=0
            uninstall_boot_script=1
            interactive=0
            ;;
        -c | --check)
            exit_after_check=1
            interactive=0
            ;;
        -r | --revert)
            configure_debugfs=0
            ;;
        -g | --group)
            default_group="$2"
            shift
            ;;
        -b | --batch)
            interactive=0
            ;;
        --user)
            username="$2"
            shift
            ;;
        *)
            print_err ""
            print_err "ERROR: unrecognized option $1"
            print_usage_and_exit 3
            ;;
    esac
    shift
done

check_mounts_and_perms()
{
    print_msg "Checking if kernel supports debugfs"
    kernel_config="/boot/config-$(uname -r)"
    if [ -f "$kernel_config" ]; then
        if [ -z "$(${GREP} 'CONFIG_DEBUG_FS=y' $kernel_config)" ]; then
            print_err "ERROR: Your kernel does not support debugfs"
            exit 23
        fi
    else
        print_msg "Kernel config file is absent, skipping check"
    fi
    print_msg "debugfs is supported"

    print_msg "Checking if debugfs is mounted on /sys/kernel/debug"
    if [ -z "$(${MOUNT} | ${GREP} debugfs)" ]; then
        if [ -d "/sys/kernel/debug/tracing" ]; then
            print_msg "Already mounted on /sys/kernel/debug"
        else
            print_msg "Not mounted, mounting to check"
            mount -t debugfs none /sys/kernel/debug
            if [ $? -ne 0 ]; then
                print_err "Failed to mount debugfs"
                exit 24
            fi
        fi
    fi
    print_msg "debugfs is mounted"

    found_changed=0
    mountpoint=$(${MOUNT} | ${GREP} debugfs | ${AWK} '{print $3};' | ${HEAD} -n1)
    if [ -z "$mountpoint" ]; then
        mountpoint="/sys/kernel/debug"
    fi
    print_msg "Mount point is $mountpoint, checking group ownership"
    for entryinfo in $(${FIND} $mountpoint -maxdepth 1 -printf "%p,%g\n"); do
        name=$(echo $entryinfo | cut -d, -f1)
        group=$(echo $entryinfo | cut -d, -f2)
        if [ "$group" != "${default_group}" ] && [ "$group" != "root" ]; then
            print_msg "WARNING: entry $name is owned by group '$group' which is different than 'root' and '$default_group'"
            found_changed=1
        fi
    done
    print_msg "group ownership is ok"

    if [ $found_changed -eq 1 ]; then
        if [ $interactive -eq 0 ]; then
            print_err "Some entries have changed permissions. Mode is non-interactive so just exiting"
            exit 25
        else
            print_msg "Some entries have changed permissions. Continue at your own risk. "
            print_msg "Some software relying on debugfs may become unstable. "
            print_nnl "Continue? ( y/n ) ? [n] "
            read answer
            if [ -z "$answer" ] || [ "n" = "$answer" ]; then
                print_err "Exiting per user decision"
                exit 26
            fi
        fi
    fi
}

configure_debugfs()
{
    if [ -z "$(${MOUNT} | ${GREP} ' /sys/kernel/debug ')" ] && [ ! -d "/sys/kernel/debug" ]; then
        print_msg "Mounting debugfs to /sys/kernel/debug"
        ${MOUNT} -t debugfs none /sys/kernel/debug
        if [ $? -ne 0 ]; then
            print_err "Failed to mount debugfs"
            exit 27
        fi
    fi

    print_msg "Changing group ownership"
    ${CHGRP} -R $default_group /sys/kernel/debug
    if [ $? -ne 0 ]; then
        print_err "Failed to change group ownership"
        exit 28
    fi

    print_msg "Changing permissions"
    ${CHMOD} -R g+rwx /sys/kernel/debug/
    if [ $? -ne 0 ]; then
        print_err "Failed to change permissions"
        exit 29
    fi
}

revert_debugfs()
{
    print_msg "Reverting debugfs access permissions"
    ${CHMOD} -R g-rwx /sys/kernel/debug
    if [ $? -ne 0 ]; then
        print_err "Failed to change permissions"
        exit 30
    fi

    print_msg "Reverting group ownership"
    ${CHGRP} -R root /sys/kernel/debug
    if [ $? -ne 0 ]; then
        print_err "Failed to change group ownership"
        exit 31
    fi
}

distro=
has_systemd=no
DEFAULT_REDHAT_BOOT_INSTALL="/etc/rc.d/init.d"
DEFAULT_SUSE_BOOT_INSTALL="/etc/init.d"
DEFAULT_DEBIAN_BOOT_INSTALL="/etc/init.d"
BOOT_INSTALL_DIR=
BOOT_INSTALL_DIR_INITD=
DEFAULT_SYSTEMD_SELF_INSTALL="/usr/local/sbin"
SELF_INSTALL_DIR=
SELF_INSTALL_DIR_INITD=
LSB_BIN=
RUNLEVEL_DIR=
RELATIVE_BOOT_INSTALL=
BOOTSCRIPT=
BOOTSCRIPT_PATH=

check_distro()
{
    if [ -f "/etc/redhat-release" ]; then
        distro="redhat"
    elif [ -f "/etc/SuSE-release" ]; then
        distro="suse"
    else
        distro="debian"
    fi

    if [ "redhat" = "$distro" ]; then
        BOOT_INSTALL_DIR_INITD=${DEFAULT_REDHAT_BOOT_INSTALL}
        RUNLEVEL_DIR=/etc/rc.d
        RELATIVE_BOOT_INSTALL=../init.d
    else
        LSB_BIN=/usr/lib/lsb
        if [ "suse" = "$distro" ]; then
            BOOT_INSTALL_DIR_INITD=${DEFAULT_SUSE_BOOT_INSTALL}
            RUNLEVEL_DIR=/etc/init.d
            RELATIVE_BOOT_INSTALL=.
        else
            BOOT_INSTALL_DIR_INITD=${DEFAULT_DEBIAN_BOOT_INSTALL}
            RUNLEVEL_DIR=/etc
            RELATIVE_BOOT_INSTALL=../init.d
        fi
    fi

    SELF_INSTALL_DIR_INITD=${BOOT_INSTALL_DIR_INITD}

    # https://www.freedesktop.org/software/systemd/man/sd_booted.html
    if [ -d /run/systemd/system ] && systemctl --version > /dev/null ; then
        has_systemd=yes
        BOOTSCRIPT=${BOOTSCRIPT_SYSTEMD}
        BOOT_INSTALL_DIR=$(${PKG_CONFIG} systemd --variable=systemdsystemunitdir)
        SELF_INSTALL_DIR=${DEFAULT_SYSTEMD_SELF_INSTALL}
    else
        has_systemd=no
        BOOTSCRIPT=${BOOTSCRIPT_INITD}
        BOOT_INSTALL_DIR=${BOOT_INSTALL_DIR_INITD}
        SELF_INSTALL_DIR=${BOOT_INSTALL_DIR}
    fi

    BOOTSCRIPT_PATH=${BOOT_INSTALL_DIR}/${BOOTSCRIPT}
}

create_initd_boot_script()
{
    ${RM} -f $BOOTSCRIPT_PATH
    cat > $BOOTSCRIPT_PATH <<EOF
#!/bin/sh

#
# File: $BOOTSCRIPT
#
# Description: script to configure debugfs at boot time
#
# Version: 1.0
#
# """
# Copyright 2014-2021 Intel Corporation.
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you (License).
# Unless the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
# This software and the related documents are provided as is, with no express or implied warranties,
# other than those that are expressly stated in the License.
# """
#

### BEGIN INIT INFO ###
# Provides: $BOOTSCRIPT
# Required-Start: \$syslog
# Required-Stop: \$syslog
# Default-Start: 2 3 4 5
# Default-Stop: 0
# Short-Description: configures the debugfs at boot/shutdown time
# Description: configures the debugfs at boot/shutdown time
### END INIT INFO ###

# source the function library, if it exists

[ -r /etc/rc.d/init.d/functions ] && . /etc/rc.d/init.d/functions

if [ ! -d ${SELF_INSTALL_DIR} ] ; then
  echo "Unable to access the script directory \"${SELF_INSTALL_DIR}\" !"
  exit 101
fi

if [ ! -f ${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME} ] ; then
  echo "The boot script \"${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME}\" does not exist!"
  exit 102
fi

# define function to configure the debugfs
start() {
    echo "Configuring debugfs access permissions for ${PRODUCT_NAME}"
    (cd ${SELF_INSTALL_DIR} && ./${SELF_INSTALL_NAME} --batch --group ${default_group})
    RETVAL=\$?
    return \$RETVAL
}

# define function to unconfigure the debugfs
stop() {
    echo "Unconfiguring debugfs access permissions for ${PRODUCT_NAME}"
    (cd ${SELF_INSTALL_DIR} && ./${SELF_INSTALL_NAME} --revert)
    RETVAL=\$?
    return \$RETVAL
}

# define function to query whether debugfs is configured
# actually does nothing
status() {
    return 0
}

# parse command-line options and execute

RETVAL=0

case "\$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        exit 1
esac

exit \$RETVAL
EOF
    chmod a+rx $BOOTSCRIPT_PATH
}


create_systemd_boot_script()
{
    ${RM} -f $BOOTSCRIPT_PATH
    cat > $BOOTSCRIPT_PATH <<EOF
#
# File: $BOOTSCRIPT
#
# Description: VTune systemd service to configure debugfs access permissions
#
# Version: 1.0
#
# """
# Copyright 2021 Intel Corporation.
#
# This software and the related documents are Intel copyrighted materials, and your use of them
# is governed by the express license under which they were provided to you (License).
# Unless the License provides otherwise, you may not use, modify, copy, publish, distribute, disclose
# or transmit this software or the related documents without Intel's prior written permission.
# This software and the related documents are provided as is, with no express or implied warranties,
# other than those that are expressly stated in the License.
# """
#

[Unit]
Description=VTune service to configure debugfs access permissions
After=sys-kernel-debug.mount local-fs.target nss-user-lookup.target

[Service]
Type=oneshot
ExecStart=${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME} --batch --group ${default_group}
ExecStop=${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME} --revert
RemainAfterExit=true
Restart=no

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

configure_boot_script()
{
    # configure autoload ...
    if [ "yes" = "${has_systemd}" ]; then
        print_nnl "Configuring autoload of ${BOOTSCRIPT} service ... "
        systemctl enable ${BOOTSCRIPT}
        err=$?
        if [ $err -ne 0 ] ; then
            print_nnl "WARNING: systemctl enable returned error $err ... "
        fi

        systemctl start ${BOOTSCRIPT}
        err=$?
        if [ $err -ne 0 ] ; then
            print_nnl "WARNING: systemctl start returned error $err ... "
        fi
    else
        print_nnl "Configuring autoload of ${BOOTSCRIPT} service for runlevels 2 through 5 ... "
        if [ "suse" = "${distro}" ]; then
            ${LSB_BIN}/install_initd ${BOOTSCRIPT_PATH}
        elif [ "redhat" = "${distro}" -o "debian" = "${distro}" ]; then
            [ -w ${RUNLEVEL_DIR}/rc2.d ] && ${LN} -sf ${RELATIVE_BOOT_INSTALL}/${BOOTSCRIPT} ${RUNLEVEL_DIR}/rc2.d/S99${BOOTSCRIPT}
            [ -w ${RUNLEVEL_DIR}/rc3.d ] && ${LN} -sf ${RELATIVE_BOOT_INSTALL}/${BOOTSCRIPT} ${RUNLEVEL_DIR}/rc3.d/S99${BOOTSCRIPT}
            [ -w ${RUNLEVEL_DIR}/rc4.d ] && ${LN} -sf ${RELATIVE_BOOT_INSTALL}/${BOOTSCRIPT} ${RUNLEVEL_DIR}/rc4.d/S99${BOOTSCRIPT}
            [ -w ${RUNLEVEL_DIR}/rc5.d ] && ${LN} -sf ${RELATIVE_BOOT_INSTALL}/${BOOTSCRIPT} ${RUNLEVEL_DIR}/rc5.d/S99${BOOTSCRIPT}
        else
            print_nnl "WARNING: unable to create symlinks ... "
        fi
    fi

    print_msg "done."
}

install_boot_script()
{
    check_distro
    if [ -w ${SELF_INSTALL_DIR} ] ; then
        print_nnl "Installing this script to ${SELF_INSTALL_DIR} as ${SELF_INSTALL_NAME} ... "
        cp ${SCRIPT} ${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME}
        if [ -f ${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME} ] ; then
            print_msg "done."
        else
            print_err "Unable to install the script ... exiting."
            exit 32
        fi
    fi

    if [ -w ${BOOT_INSTALL_DIR} ] ; then
        print_nnl "Creating boot script ${BOOT_INSTALL_DIR}/${BOOTSCRIPT} ... "
        if [ "yes" = "${has_systemd}" ]; then
            create_systemd_boot_script
        else
            create_initd_boot_script
        fi

        if [ -r ${BOOT_INSTALL_DIR}/${BOOTSCRIPT} ] ; then
            print_msg "done."
        else
            print_err "Unable to create boot script ... exiting."
            exit 33
        fi
    else
        print_err "Unable to write to ${BOOT_INSTALL_DIR} ... exiting."
        exit 34
    fi

    configure_boot_script
}

uninstall_initd_boot_script()
{
    # Use INITD specific variables here because uninstall_initd is also invoked in systemd path
    if [ -f ${BOOT_INSTALL_DIR_INITD}/${BOOTSCRIPT_INITD} ] ; then
        print_nnl "Removing ${BOOTSCRIPT_INITD} boot script and symlinks for runlevels 2 through 5 ... "
        if [ "suse" = "${distro}" ]; then
            # remove_initd is absent on modern distros, we just need to remove BOOTSCRIPT_INITD then
            if [ -x ${LSB_BIN}/remove_initd ] ; then
                ${LSB_BIN}/remove_initd ${BOOT_INSTALL_DIR_INITD}/${BOOTSCRIPT_INITD}
                err=$?
                if [ $err -ne 0 ] ; then
                    print_err "${LSB_BIN}/remove_initd returned error $err ... exiting."
                    exit 35
                fi
            fi
        elif [ "redhat" = "${distro}" -o "debian" = "${distro}" ] ; then
            [ -w ${RUNLEVEL_DIR}/rc2.d ] && ${RM} -f ${RUNLEVEL_DIR}/rc2.d/S99${BOOTSCRIPT_INITD}
            [ -w ${RUNLEVEL_DIR}/rc3.d ] && ${RM} -f ${RUNLEVEL_DIR}/rc3.d/S99${BOOTSCRIPT_INITD}
            [ -w ${RUNLEVEL_DIR}/rc4.d ] && ${RM} -f ${RUNLEVEL_DIR}/rc4.d/S99${BOOTSCRIPT_INITD}
            [ -w ${RUNLEVEL_DIR}/rc5.d ] && ${RM} -f ${RUNLEVEL_DIR}/rc5.d/S99${BOOTSCRIPT_INITD}
        else
            print_nnl "WARNING: unable to remove symlinks ... "
        fi
        [ -w ${BOOT_INSTALL_DIR_INITD} ] && ${RM} -f ${BOOT_INSTALL_DIR_INITD}/${BOOTSCRIPT_INITD}
        print_msg "done."
    else
        print_msg "No previously installed init.d ${BOOTSCRIPT_INITD} boot script was found."
    fi

    if [ -f ${SELF_INSTALL_DIR_INITD}/${SELF_INSTALL_NAME} ] ; then
        print_nnl "Removing ${SELF_INSTALL_DIR_INITD}/${SELF_INSTALL_NAME} script ... "
        [ -w ${SELF_INSTALL_DIR_INITD} ] && ${RM} -f ${SELF_INSTALL_DIR_INITD}/${SELF_INSTALL_NAME}
        print_msg "done."
    fi
}

uninstall_systemd_boot_script()
{
    # systemctl may complain on uninstalled remains of generated init.d script with the same name
    systemctl daemon-reload

    # Query the actual location of already installed script instead of assuming BOOT_INSTALL_DIR
    installed_bootscript=$(systemctl show -p FragmentPath ${BOOTSCRIPT} | cut -d= -f2)
    if [ $? -eq 0 -a -n "${installed_bootscript}" ] ; then
        print_nnl "Stopping and removing ${BOOTSCRIPT} service ... "
        systemctl stop ${BOOTSCRIPT}
        err=$?
        if [ $err -ne 0 ] ; then
            print_err "systemctl stop ${BOOTSCRIPT} returned error $err ... exiting."
            exit 36
        fi

        systemctl disable ${BOOTSCRIPT}
        err=$?
        if [ $err -ne 0 ] ; then
            print_err "systemctl disable ${BOOTSCRIPT} returned error $err ... exiting."
            exit 37
        fi
        [ -w "$(dirname ${installed_bootscript})" ] && ${RM} -f ${installed_bootscript}
        systemctl daemon-reload
        print_msg "done."
    else
        print_msg "No previously installed systemd ${BOOTSCRIPT} boot script was found."
    fi

    if [ -f ${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME} ] ; then
        print_nnl "Removing ${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME} script ... "
        [ -w ${SELF_INSTALL_DIR} ] && ${RM} -f ${SELF_INSTALL_DIR}/${SELF_INSTALL_NAME}
        print_msg "done."
    fi
}

uninstall_boot_script()
{
    check_distro

    # Always invoke legacy uninstall in case of script upgrade
    uninstall_initd_boot_script

    if [ "yes" = "${has_systemd}" ]; then
        uninstall_systemd_boot_script
    fi
}

if [ ! `groups ${username} | ${GREP} ${default_group} > /dev/null` ]  && [ ${username} ] ; then
    `usermod -a -G ${default_group} ${username}`
fi

if [ $configure_debugfs -eq 1 ]; then
    check_mounts_and_perms
    result=$?
    if [ $exit_after_check -eq 1 ]; then
        exit $result
    fi
    configure_debugfs
    if [ $install_boot_script -eq 1 ]; then
        uninstall_boot_script
        install_boot_script
    fi
else
    revert_debugfs
    if [ $uninstall_boot_script -eq 1 ]; then
        uninstall_boot_script
    fi
fi
