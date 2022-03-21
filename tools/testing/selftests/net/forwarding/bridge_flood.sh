#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Verify per-port flood control flags of unknown BUM traffic.
#
#             br0
#            /   \
#          p1    p2    h2   h1
#           |    '-----'    |
#           '---------------'
#
# We inject bc/uc/mc on h1, toggle the three flood flags for both br0
# and p2, then verify that traffic is flooded as per the flags, and
# nowhere else.
#
# Nomenclature:
#    brN - Bridge N
#    pN  - Bridge port N
#    hN  - End Host N, connected via cable/veth to bridge port N
#

ALL_TESTS="br_flood_unknown_bc_test br_flood_unknown_uc_test br_flood_unknown_mc_test"
NUM_NETIFS=4

SRC_MAC="00:de:ad:be:ef:00"

BC_PKT="ff:ff:ff:ff:ff:ff $SRC_MAC 00:04 48:45:4c:4f"
UC_PKT="02:00:01:c0:ff:ee $SRC_MAC 00:04 48:45:4c:4f"
MC_PKT="01:00:5e:01:02:03 $SRC_MAC 08:00 45:00 00:20 c2:10 00:00 ff 11 12:b2 \
	01:02:03:04 e1:01:02:03 04:d2 10:e1 00:0c 6e:84 48:45:4c:4f"

# Disable promisc to ensure we only receive flooded frames
TCPDUMP_EXTRA_FLAGS="-pl"

source lib.sh

h1=${NETIFS[p1]}
h2=${NETIFS[p3]}
p1=${NETIFS[p2]}
p2=${NETIFS[p4]}

#
# Port mappings and flood flag pattern to set/detect
#
# We inject traffic (one of three classes) on $p1 and
# then verify it egresses on ports $p2 or br0 as the
# matrix below defines (on: flood, off: block)
#
declare -A bridged_ports=([$p1]=$h1 [$p2]=$h2 [br0]=br0)
declare -A flood_matrix1=([$p1]=off [$p2]=off [br0]=off)
declare -A flood_matrix2=([$p1]=off [$p2]=on  [br0]=off)
declare -A flood_matrix3=([$p1]=off [$p2]=on  [br0]=on )
declare -A flood_matrix4=([$p1]=off [$p2]=off [br0]=on )

switch_create()
{
	ip link add dev br0 type bridge

	for port in "${!bridged_ports[@]}"; do
		[ "$port" != "br0" ] && ip link set dev "$port" master br0
		ip link set dev "$port" up
	done
}

switch_destroy()
{
	for port in "${!bridged_ports[@]}"; do
		ip link set dev "$port" down
	done
	ip link del dev br0
}

setup_prepare()
{
	vrf_prepare

	((i=1))
	for iface in "${bridged_ports[@]}"; do
		[ "$iface" = "br0" ] && continue
		simple_if_init "$iface" 192.0.2.$i/24 2001:db8:1::$i/64
		((i++))
	done

	switch_create
}

cleanup()
{
	pre_cleanup
	switch_destroy

	((i=1))
	for iface in "${bridged_ports[@]}"; do
		[ "$iface" = "br0" ] && continue
		simple_if_fini "$iface" 192.0.2.$i/24 2001:db8:1::$i/64
		((i++))
	done

	vrf_cleanup
}

xlate()
{
	if [ "$1" = "on" ]; then
		echo 1
	else
		echo 0
	fi
}

do_flood_unknown()
{
	local type=$1
	local pass=$2
	local pkt=$3
	local flag=$4
	local -n flags=$5

	RET=0
	for port in "${!bridged_ports[@]}"; do
		if [ "$port" = "br0" ]; then
			ip link set $port type bridge $flag $(xlate ${flags[$port]})
		else
			bridge link set dev $port $flag ${flags[$port]}
		fi
		check_err $? "Failed setting $port $flag ${flags[$port]}"
	done

	for iface in "${bridged_ports[@]}"; do
		tcpdump_start $iface
	done

	$MZ -q $h1 "$pkt"
	sleep 1

	for iface in "${bridged_ports[@]}"; do
		tcpdump_stop $iface
	done

	for port in "${!bridged_ports[@]}"; do
		iface="${bridged_ports[$port]}"

		tcpdump_show $iface | grep -q "$SRC_MAC"
		rc=$?

		[ "${flags[$port]}" = "on"  ] && check_err  $rc "flooding from $h1 to port $port"
		[ "${flags[$port]}" = "off" ] && check_fail $rc "blocking from $h1 to port $port"
	done

	for iface in "${bridged_ports[@]}"; do
		tcpdump_cleanup $iface
	done

	log_test "flood unknown $type pass $pass/4"
}

br_flood_unknown_bc_test()
{
	do_flood_unknown BC 1 "$BC_PKT" bcast_flood flood_matrix1
	do_flood_unknown BC 2 "$BC_PKT" bcast_flood flood_matrix2
	do_flood_unknown BC 3 "$BC_PKT" bcast_flood flood_matrix3
	do_flood_unknown BC 4 "$BC_PKT" bcast_flood flood_matrix4
}

br_flood_unknown_uc_test()
{
	do_flood_unknown UC 1 "$UC_PKT" flood flood_matrix1
	do_flood_unknown UC 2 "$UC_PKT" flood flood_matrix2
	do_flood_unknown UC 3 "$UC_PKT" flood flood_matrix3
	do_flood_unknown UC 4 "$UC_PKT" flood flood_matrix4
}

br_flood_unknown_mc_test()
{
	do_flood_unknown MC 1 "$MC_PKT" mcast_flood flood_matrix1
	do_flood_unknown MC 2 "$MC_PKT" mcast_flood flood_matrix2
	do_flood_unknown MC 3 "$MC_PKT" mcast_flood flood_matrix3
	do_flood_unknown MC 4 "$MC_PKT" mcast_flood flood_matrix4
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
