#! /bin/bash
#
# Administer LIO iSCSI targets
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
# Copyrignt (c) 2014-2016 john.cooper@third-harmonic.com
#
# Inspired by the work of Christophe Vu-Brugier
#

usage="$0 [ create | delete | delete_all | ls | help ] ..."

# %% helpdoc %%
#
# operation modes:
#
#   create <backing_file> [<options>]
#                           allocate a new target for <backing_file>
#   delete <backing_file>   remove an existing target
#   delete_all              remove all existing targets
#   ls [-l]                 produce a configfs summary for each existing target
#   help                    generates this information
#
# where:
#
#   <backing_file>          may be a plain file or block device name.
#                           In the case of a plain file, a LIO fileio
#                           target is created.  In the case a block device
#                           name is given, a LIO iblock target is created
#
#   <options>               one or more whitespace separated flags of the form:
#      ro                   target will be read-only (create)
#      rw                   target will be read-write (create)
#      demo_wp=[0|1]        set demo mode write protect (create)
#      duser=*              set discovery user id to "*" (create)
#      dpass=*              set discovery password to "*" (create)
#      dauth=*              set discovery authentication method to "*" (create)
#      portal=<ip>:<port>   create portal with ip address <ip> port <port>
#      debug                enable internal debug
#
# %% helpdoc %%

# generaate one-liner usage message with optional preceeding diagnostic
#
function usage()
	{
	if [ -n "$1" ]; then
		echo "$0: $@" > /dev/stderr
	fi
	echo "usage: $usage" > /dev/stderr
	}

# generate diagnostic and error exit
#
function bail
	{
	usage $1
	exit 1
	}

# parse options and capture in cliopts[] associative array. 'format'
# specifies all permitted options and option_list is that present on the
# command line.  For convenience cliopts[##] enumerates all discovered tags
#
#   parseopts(format, option_list)
#
function parseopts()
	{
	local fmt=" $1 debug " opt tag arg

	for opt in $2
		do
		tag=${opt%=*}
		arg=${opt#${tag}}
		arg=${arg#=}
		if ! [[ $fmt =~ " "$tag" " ]]; then
			echo "unrecognized option \"$opt\""
		else
			if [ -z "$arg" ]; then
				arg=1
			fi
			cliopts[$tag]="$arg"
			cliopts[##]="${cliopts[##]} $tag"
		fi 
		done
	if [ -n "${cliopts[debug]}" ]; then
		echo "discovered args: ${cliopts[##]}"
	fi
	}

# delete_all targets
#
function delete_all()
	{
	rm -rf $CORE_DIR/{fileio,iblock}_* $ISCSI_DIR/${iqn%:*}:* 2> /dev/null
	rm -rf $CORE_DIR/{fileio,iblock}_* $ISCSI_DIR/${iqn%:*}:* 2> /dev/null
	}
		
# create backing file entry in configfs
#
#	create_backfile(typename)
#
function create_backfile()
	{
	local typename=$1
	local i=0;

	while [ -d $CORE_DIR/${typename}_$i ];
		do
		i=$((i + 1))
		done
	backstore_dir=$CORE_DIR/${typename}_$i/data
	mkdir -p $backstore_dir
	}

# find existing backing file entry in configfs, return info path
#
#	find_backfile(filename)
#
function find_backfile()
	{
	local i name

	for i in $CORE_DIR/{iblock,fileio}_*/data/info
		do
		if [ -d ${i%/info} ]; then
			name=`awk '/File: /{print $6} /UDEV PATH: /{print $6}' $i`
			if [ "$name" == "$1" ]; then
				echo ${i%/data/info}
			fi
		fi
		done
	}

# create fileio backing store
#
#	fileio(filename)
#
function fileio()
	{
	local filename=$1
	local dev_size=`du -s $filename | awk '{print $1 * 1024}'`

	if [ "$dev_size" -eq 0 ]; then
		echo "$0: warning: $filename reports zero length, reading to determine length" 
		dev_size=`wc $filename | awk '{print $3}'`
	fi
	create_backfile fileio
    if [ -n "${cliopts[debug]}" ]; then
		echo "creating FILEIO control: fd_dev_name=$filename,fd_dev_size=$dev_size -> $backstore_dir/control"
	fi
	echo "fd_dev_name=$filename,fd_dev_size=$dev_size" > $backstore_dir/control
	}

# create block dev backing store
#
#	blkio(blkdevname)
#
function blkio()
	{
	local blkdev=$1 blkdev_opts

	if [ -n "${cliopts[ro]}" ]; then
		blkdev_opts=",readonly=1"
	elif [ -n "${cliopts[rw]}" ]; then
		blkdev_opts=",readonly=0"
	fi
	create_backfile iblock
    if [ -n "${cliopts[debug]}" ]; then
		echo "creating IBLOCK control: udev_path=$blkdev$blkdev_opts -> $backstore_dir/control"
    fi
	echo "udev_path=$blkdev$blkdev_opts" > $backstore_dir/control
	}

# create iscsi target, target portal group, LUN
#
#	create_target(dev_or_file_name)
#
function create_target()
	{
	local dev=$1 tag opt arg readonly ipaddr port portal

	# setup backing storage
	if [ -b $dev ]; then
		blkio $dev
		tag="block device"
	else
		fileio $dev
		tag="file"
	fi
	echo 1 > $backstore_dir/enable

	# create iscsi target, target portal group, LUN
	mkdir -p $ISCSI_DIR/$iqn/$TPG/lun/$LUN
	ln -s $backstore_dir $ISCSI_DIR/$iqn/$TPG/lun/$LUN/data
	echo 1 > $ISCSI_DIR/$iqn/$TPG/enable

	if [ -n "${cliopts[portal]}" ]; then
		ipaddr=${cliopts[portal]%:*}
		port=${cliopts[portal]#*:}
		if [ -z "$ipaddr$port" ]; then
			bail "invalid \"portal=\" argument"
		elif [ -z "$ipaddr" ]; then
			ipaddr="0.0.0.0"
		elif [ -z "$port" ]; then
			port=3260
		fi
		portal="$ipaddr:$port"
	fi

	# create network portal, disable authentication
	if [ ! -d $ISCSI_DIR/$iqn/$TPG/np/$portal ]; then
		mkdir $ISCSI_DIR/$iqn/$TPG/np/$portal
		echo 0 > $ISCSI_DIR/$iqn/$TPG/attrib/authentication
		echo 1 > $ISCSI_DIR/$iqn/$TPG/attrib/generate_node_acls
		echo 1 > $ISCSI_DIR/$iqn/$TPG/attrib/cache_dynamic_acls
		check_netfilter $ipaddr $port
	fi

	# implement options
	for opt in $cliopts[##]
		do
		arg=${cliopts[$opt]}
		case $opt in

		(demo_wp=*)
			echo $arg  > $ISCSI_DIR/$iqn/$TPG/attrib/demo_mode_write_protect
			;;

		(duser=*)
			echo $arg > $ISCSI_DIR/discovery_auth/userid
			;;

		(dpass=*)
			echo $arg > $ISCSI_DIR/discovery_auth/password
			;;
		
		(dauth=*)
			echo $arg > $ISCSI_DIR/$iqn/$TPG/param/AuthMethod
			;;
		esac
		done
	echo "Created target $iqn, portal $portal, backing $tag: $dev"
	}

# delete iscsi target
#
#	delete_target(dev_or_file_name)
#
function delete_target()
	{
	local dev=$1
	local backfile=`find_backfile $dev`
	target=$ISCSI_DIR/$iqn

	if [ ! -d $target ]; then
		bail "can't find target device: $dev"
	fi
	if [ ! -d $backfile ]; then
		bail "can't find backing file/device mapping: $backfile"
	fi 
	# recursive deletion ordering may attempt to remove some dependant files
	# before its dependencies.  So we cleanup with a second invocation.
	rm -rf $backfile $target 2> /dev/null
	rm -rf $backfile $target 2> /dev/null
	}

# print a synopsys of all targets
#
function ls_targets()
	{
	local i backfile wp

	for i in $ISCSI_DIR/$iqn*
		do
		if [ -d $i ]; then
			backfile=$(readlink -f $i/tpgt_1/lun/lun_0/data)
			if [ "$1" == "-l" ]; then
				echo $i:
				echo "    ${backfile%/data}"
				awk '{sub(/^ */,"");print "    " $0}' $i/tpgt_1/lun/lun_0/data/info
			else
				wp=`cat $i/tpgt_1/attrib/demo_mode_write_protect`
				awk -v wp=$wp '\
					BEGIN {wp = wp ? "ro" : "rw"} \
					/FILEIO/ {print "fileio " wp " " $6} \
					/UDEV PATH/ {print "iblock " wp " " $6} \
					' $i/tpgt_1/lun/lun_0/data/info
			fi
		fi
		done
	}


# best effort to assure if netfilter is configured, portal is accessible.
# If netfilter present and no accept rule for portal, add rule to INPUT,
# otherwise do nothing.
#
#	check_netfilter(ipaddr, port)
#
function check_netfilter()
	{
	local ipaddr=$1 port=$2

	if [ -d /proc/sys/net/netfilter/nf_log ] && ! iptables -n -L | awk -v pat="ACCEPT.*dpt:$port" '$0 ~ pat{rv = 1} END {exit !rv}'; then
    	iptables -A INPUT -i eth0  -p tcp -m tcp  --dport $port  -j ACCEPT
		if [ -n "${cliopts[debug]}" ]; then
			echo "opened port $port"
		fi
	fi
	}

# execution starts here, setup static paths & defaults
#
CONFIGFS_DIR=/sys/kernel/config
CORE_DIR=$CONFIGFS_DIR/target/core
ISCSI_DIR=$CONFIGFS_DIR/target/iscsi
DEF_PORTAL="0.0.0.0:3260"
TPG="tpgt_1"
LUN="lun_0"
declare -A cliopts

# prepare system
#
if ! mount | grep -q configfs; then
	mount -t configfs configfs $CONFIGFS_DIR
fi

# launder args
#
cmd=$1
arg=$2
if [ -z "$cmd" ]; then
	bail
fi

iqn="iqn.2003-01.org.linux-iscsi.$(hostname):${arg##*/}"

case $cmd in

(create|new|export)
	[ -z "$arg" ] && bail "device arg required"
	shift 2
	parseopts "ro rw demo_wp duser dpass dauth portal" "$*"
	create_target $arg
	;;

(delete|remove|free)
	[ -z "$arg" ] && bail "device arg required"
	delete_target $arg
	;;

(delete[-_]all|remove[-_]all|free[-_]all)
	delete_all
	;;

(ls|list)
	iqn="${iqn%:*}:"
	ls_targets $2
	;;

(*help*)
	echo > /dev/stderr
	usage
	awk '/%% helpdoc %%/{++p;next}{if(p==1){sub(/^#/,"");print}}' $0 > /dev/stderr
	;;

("")
	bail
	;;

(*)
	bail "unrecognized command: $cmd"
	;;
esac

exit 0

# vi:set ts=4:
