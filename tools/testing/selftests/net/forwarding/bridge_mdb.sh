#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Verify that adding host mdb entries work as intended for all types of
# multicast filters: ipv4, ipv6, and mac
#
# Verify forwarding (default flooding behavior) to all ports of unknown
# multicast: MAC, IPv4, IPv6.
#
# Verify selective multicast forwarding (strict mdb), when bridge port
# mcast_flood is disabled, of known MAC, IPv4, IPv6 traffic.
#
# Verify flooding towards mcast_router ports of known IP multicast.
#
# Note: this test completely disables IPv6 auto-configuration to avoid
#       any type of dynamic behavior outside of MLD and IGMP protocols.
#       Static IPv6 addresses are used to ensure consistent behavior,
#       even in the startup phase when multicast snooping is enabled.
#

ALL_TESTS="mdb_add_del_test mdb_compat_fwd_test mdb_rport_fwd_test \
	   mdb_mac_fwd_test mdb_ip4_fwd_test mdb_ip6_fwd_test"
NUM_NETIFS=6

SRC_PORT="1234"
DST_PORT="4321"

SRC_ADDR_IP4="1.2.3.4"
PASS_GRP_IP4="225.1.2.3"
FAIL_GRP_IP4="225.1.2.4"

SRC_ADDR_MAC="00:de:ad:be:ef:00"
PASS_GRP_MAC="01:00:01:c0:ff:ee"
FAIL_GRP_MAC="01:00:01:c0:ff:ef"

PASS_PKT_MAC="$PASS_GRP_MAC $SRC_ADDR_MAC 00:04 48:45:4c:4f"
FAIL_PKT_MAC="$FAIL_GRP_MAC $SRC_ADDR_MAC 00:04 46:41:49:4c"

PASS_PKT_IP4="01:00:5e:01:02:03 $SRC_ADDR_MAC 08:00 45:00 00:20 c2:10 00:00 ff 11 12:b2 01:02:03:04 e1:01:02:03 04:d2 10:e1 00:0c 6e:84 48:45:4c:4f"
FAIL_PKT_IP4="01:00:5e:01:02:04 $SRC_ADDR_MAC 08:00 45:00 00:20 dc:e4 00:00 ff 11 f7:dc 01:02:03:04 e1:01:02:04 04:d2 10:e1 00:0c 73:8a 46:41:49:4c"

SRC_ADDR_IP6="ff2e::42"
PASS_GRP_IP6="ff02::42"
FAIL_GRP_IP6="ff02::43"

PASS_PKT_IP6="33 33 00 00 00 42 36 1e b4 04 cd e8 86 dd 60 00 01 01 00 08 11 ff ff 2e 00 00 00 00 00 00 00 00 00 00 00 00 00 42 ff 02 00 00 00 00 00 00 00 00 00 00 00 00 00 42 04 d2 10 e1 00 08 eb 75"
FAIL_PKT_IP6="33 33 00 00 00 43 36 1e b4 04 cd e8 86 dd 60 00 01 01 00 08 11 ff ff 2e 00 00 00 00 00 00 00 00 00 00 00 00 00 42 ff 02 00 00 00 00 00 00 00 00 00 00 00 00 00 43 04 d2 10 e1 00 08 eb 74"

# Disable promisc to ensure we only receive $TEST_GROUP*
export TCPDUMP_EXTRA_FLAGS="-pl"

source lib.sh

require_command tcpdump

h1_create()
{
	simple_if_init $h1 192.0.2.1/24 2001:db8:1::1/64
}

h1_destroy()
{
	simple_if_fini $h1 192.0.2.1/24 2001:db8:1::1/64
}

h2_create()
{
	simple_if_init $h2 192.0.2.2/24 2001:db8:1::2/64
}

h2_destroy()
{
	simple_if_fini $h2 192.0.2.2/24 2001:db8:1::2/64
}

h3_create()
{
	simple_if_init $h3 192.0.2.3/24 2001:db8:1::3/64
}

h3_destroy()
{
	simple_if_fini $h3 192.0.2.3/24 2001:db8:1::3/64
}

switch_create()
{
	# Enable multicast filtering w/ querier, reduce query response
	# and startup interval to speed up test a bit.
	ip link add dev br0 type bridge mcast_snooping 1 \
	   mcast_startup_query_interval 400 mcast_query_response_interval 200

	# Set static IPv6 address before we enable the multicast querier
	# function.  This, along with disabling IPv6 address auto config
	# (previously), ensures correct forwarding according to the MDB
	# even when per-port flooding is disabled, *after* the initial
	# startup phase when the bridge floods all multicast (according
	# to its per-port mcast_flood settings.
	ip addr add 2001:db8:1::42/64 dev br0
	ip link set br0 type bridge mcast_querier 1

	ip link set dev $swp1 master br0
	ip link set dev $swp2 master br0
	ip link set dev $swp3 master br0

	ip link set dev br0 up
	ip link set dev $swp1 up
	ip link set dev $swp2 up
	ip link set dev $swp3 up

	# Initial delay, when bridge floods all mcast, is set to 200
	# above (2 sec.)  We wait 3 sec to handle the case when a single
	# strict fwd test is run directly after the initial setup, e.g.,
	# TESTS=mdb_ip6_fwd_test
	sleep 3
}

switch_destroy()
{
	ip link set dev $swp3 down
	ip link set dev $swp2 down
	ip link set dev $swp1 down

	ip link del dev br0
}

setup_prepare()
{
	h1=${NETIFS[p1]}
	swp1=${NETIFS[p2]}

	swp2=${NETIFS[p3]}
	h2=${NETIFS[p4]}

	swp3=${NETIFS[p5]}
	h3=${NETIFS[p6]}

	# Disable all IPv6 autoconfiguration during test, we want
	# full control of when MLD queries start etc.
	sysctl_set net.ipv6.conf.default.accept_ra 0
	vrf_prepare

	h1_create
	h2_create
	h3_create

	switch_create
}

cleanup()
{
	pre_cleanup

	switch_destroy

	h3_destroy
	h2_destroy
	h1_destroy

	vrf_cleanup
	sysctl_restore net.ipv6.conf.default.accept_ra
}

do_mdb_add_del()
{
	local group=$1
	local flag=$2

	RET=0
	bridge mdb add dev br0 port br0 grp $group $flag 2>/dev/null
	check_err $? "Failed adding $group to br0, port br0"

	if [ -z "$flag" ]; then
	    flag="temp"
	fi

	bridge mdb show dev br0 | grep $group | grep -q $flag 2>/dev/null
	check_err $? "$group not added with $flag flag"

	bridge mdb del dev br0 port br0 grp $group 2>/dev/null
	check_err $? "Failed deleting $group from br0, port br0"

	bridge mdb show dev br0 | grep -q $group >/dev/null
	check_err_fail 1 $? "$group still in mdb after delete"

	log_test "MDB add/del group $group to bridge port br0"
}

mdb_add_del_test()
{
	do_mdb_add_del $PASS_GRP_MAC permanent
	do_mdb_add_del $PASS_GRP_IP4
	do_mdb_add_del $PASS_GRP_IP6
}

do_compat_fwd()
{
	port=$1
	RET=0

	# Ensure default settings, regardless of test start order
	bridge link set dev "$swp1" mcast_flood on
	bridge link set dev "$swp2" mcast_flood on
	bridge link set dev "br0"   mcast_flood on self

	tcpdump_start "$port"

	$MZ -q $h1 "$PASS_PKT_MAC"
	$MZ -q $h1 "$FAIL_PKT_MAC"

	$MZ -q $h1 "$PASS_PKT_IP4"
	$MZ -q $h1 "$FAIL_PKT_IP4"

	$MZ -q $h1 "$PASS_PKT_IP6"
	$MZ -q $h1 "$FAIL_PKT_IP6"

	sleep 1
	tcpdump_stop "$port"

	tcpdump_show "$port" |grep -q "${SRC_ADDR_MAC} > ${PASS_GRP_MAC}"
	check_err $? "Failed forwarding multicast group $PASS_GRP_MAC from $h1 to port $port"

	tcpdump_show "$port" |grep -q "${SRC_ADDR_MAC} > ${FAIL_GRP_MAC}"
	check_err $? "Failed forwarding multicast group ${FAIL_GRP_MAC} from $h1 to port $port"

	tcpdump_show "$port" |grep -q "${SRC_ADDR_IP4}.${SRC_PORT} > ${PASS_GRP_IP4}.${DST_PORT}"
	check_err $? "Failed forwarding multicast group $PASS_GRP_IP4 from $h1 to port $port"

	tcpdump_show "$port" |grep -q "${SRC_ADDR_IP4}.${SRC_PORT} > ${FAIL_GRP_IP4}.${DST_PORT}"
	check_err $? "Failed forwarding multicast group ${FAIL_GRP_IP4} from $h1 to port $port"

	tcpdump_show "$port" |grep -q "${SRC_ADDR_IP6}.${SRC_PORT} > ${PASS_GRP_IP6}.${DST_PORT}"
	check_err $? "Failed forwarding multicast group $PASS_GRP_IP6 from $h1 to port $port"

	tcpdump_show "$port" |grep -q "${SRC_ADDR_IP6}.${SRC_PORT} > ${FAIL_GRP_IP6}.${DST_PORT}"
	check_err $? "Failed forwarding multicast group ${FAIL_GRP_IP6} from $h1 to port $port"

	log_test "MDB forward unknown MAC/IPv4/IPv6 multicast to port $port"
	tcpdump_cleanup "$port"
}

#
# Verify default behavior, unknown multicast is flooded, to both
# regular bridge ports and the bridge itself (also a port).
#
mdb_compat_fwd_test()
{
	do_compat_fwd "$h2"
	do_compat_fwd "br0"
}

#
# Verify fwd of IP multicast to router ports.  A detected multicast
# router should always receive both known and unknown multicast.
#
mdb_rport_fwd_test()
{
	pass_grp=$PASS_GRP_IP4
	fail_grp=$FAIL_GRP_IP4
	pass_pkt=$PASS_PKT_IP4
	fail_pkt=$FAIL_PKT_IP4
	decoy="br0"
	port=$h1
	type="IPv4"

	# Disable flooding of unknown multicast, strict MDB forwarding
	bridge link set dev "$swp1" mcast_flood off
	bridge link set dev "$swp2" mcast_flood off
	bridge link set dev "br0"   mcast_flood off self

	# Let h2 act as a multicast router
	ip link set dev "$swp1" type bridge_slave mcast_router 2

	# Static filter only to this decoy port
	bridge mdb add dev br0 port $decoy grp "$pass_grp"
	check_err $? "Failed adding multicast group $pass_grp to bridge port $decoy"

	tcpdump_start "$port"

	# Real data we're expecting
	$MZ -q "$h2" "$pass_pkt"
	# This should not pass
	$MZ -q "$h2" "$fail_pkt"

	sleep 1
	tcpdump_stop "$port"

	tcpdump_show "$port" |grep -q "$src$spt > $pass_grp$dpt"
	check_err $? "Failed forwarding $type multicast $pass_grp from $h2 to port $port"

	tcpdump_show "$port" |grep -q "$src$spt > $fail_grp$dpt"
	check_err $? "Failed forwarding $type multicast $fail_grp from $h2 to port $port"

	bridge mdb del dev br0 port br0 grp "$pass_grp"
	ip link set dev "$swp1" type bridge_slave mcast_router 1

	log_test "MDB forward all $type multicast to multicast router on $port"
	tcpdump_cleanup "$port"
}

do_mdb_fwd()
{
	type=$1
	port=$2
	swp=$port
	src=$3
	pass_grp=$4
	fail_grp=$5
	pass_pkt=$6
	fail_pkt=$7
	RET=0

	if [ "$type" = "MAC" ]; then
		flag="permanent"
	else
		flag=""
		spt=".$SRC_PORT"
		dpt=".$DST_PORT"
	fi
	if [ "$port" = "$h2" ]; then
		swp=$swp2
		nop="$h3"
	else
		nop="$h2"
	fi

	# Disable flooding of unknown multicast, strict MDB forwarding
	bridge link set dev "$swp1" mcast_flood off
	bridge link set dev "$swp2" mcast_flood off
	bridge link set dev "$swp3" mcast_flood off
	bridge link set dev "br0"   mcast_flood off self

	# Static filter only to this port
	bridge mdb add dev br0 port "$swp" grp "$pass_grp" $flag
	check_err $? "Failed adding $type multicast group $pass_grp to bridge port $swp"

	tcpdump_start "$port"
	tcpdump_start "$nop"

	# Real data we're expecting
	$MZ -q "$h1" "$pass_pkt"
	# This should not pass
	$MZ -q "$h1" "$fail_pkt"

	sleep 1
	tcpdump_stop "$nop"
	tcpdump_stop "$port"

	tcpdump_show "$port" |grep -q "$src$spt > $pass_grp$dpt"
	check_err $? "Failed forwarding $type multicast $pass_grp from $h1 to port $port"

	tcpdump_show "$port" |grep -q "$src$spt > $fail_grp$dpt"
	check_err_fail 1 $? "Received $type multicast group $fail_grp from $h1 to port $port"

	# Verify we don't get multicast to the canary port
	tcpdump_show "$nop" |grep -q "$src$spt > $pass_grp$dpt"
	check_err_fail 1 $? "Received $type multicast group $pass_grp from $h1 to port $nop"
	tcpdump_show "$nop" |grep -q "$src$spt > $fail_grp$dpt"
	check_err_fail 1 $? "Received $type multicast group $fail_grp from $h1 to port $nop"

	bridge mdb del dev br0 port "$swp" grp "$pass_grp"

	log_test "MDB forward $type multicast to bridge port $port"
	tcpdump_cleanup "$port"
}

#
# Forwarding of known MAC multicast according to mdb, verify blocking
# unknown MAC multicast (flood off)
#
mdb_mac_fwd_test()
{
	do_mdb_fwd MAC "br0" $SRC_ADDR_MAC $PASS_GRP_MAC $FAIL_GRP_MAC "$PASS_PKT_MAC" "$FAIL_PKT_MAC"
	do_mdb_fwd MAC "$h2" $SRC_ADDR_MAC $PASS_GRP_MAC $FAIL_GRP_MAC "$PASS_PKT_MAC" "$FAIL_PKT_MAC"
}

#
# Forwarding of known IPv4 UDP multicast according to mdb, verify
# blocking unknown IPv4 UDP multicast (flood off)
#
mdb_ip4_fwd_test()
{
	do_mdb_fwd IPv4 br0 $SRC_ADDR_IP4 $PASS_GRP_IP4 $FAIL_GRP_IP4 "$PASS_PKT_IP4" "$FAIL_PKT_IP4"
	do_mdb_fwd IPv4 $h2 $SRC_ADDR_IP4 $PASS_GRP_IP4 $FAIL_GRP_IP4 "$PASS_PKT_IP4" "$FAIL_PKT_IP4"
}

#
# Forwarding of known IPv6 UDP multicast according to mdb, verify
# blocking unknown IPv6 UDP multicast (flood off)
#
mdb_ip6_fwd_test()
{
	do_mdb_fwd IPv6 br0 $SRC_ADDR_IP6 $PASS_GRP_IP6 $FAIL_GRP_IP6 "$PASS_PKT_IP6" "$FAIL_PKT_IP6"
	do_mdb_fwd IPv6 $h2 $SRC_ADDR_IP6 $PASS_GRP_IP6 $FAIL_GRP_IP6 "$PASS_PKT_IP6" "$FAIL_PKT_IP6"
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
