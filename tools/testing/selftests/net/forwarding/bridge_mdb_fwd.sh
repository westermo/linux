#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# This is a three-part test of multicast forwarding in the bridge,
# between bridge ports and to the bridge itself.
#
#             br0
#            / | \
#          p1 p2 p3 h3 h2 h1
#           | |  '---'  |  |
#           | '---------'  |
#           '--------------'
#
# 1) Verify forwarding (default flooding behavior) to all ports of
#    unknown multicast: MAC, IPv4, IPv6.  Even after the initial
#    startup-phase while the bridge floods all multicast.
#
# 2) Verify flooding towards mcast_router ports of both known and
#    unknown IP multicast.
#
# 3) Verify selective multicast forwarding (strict mdb) of known MAC,
#    IPv4, IPv6 traffic with bridge port mcast_flood disabled and a
#    multicast router is known.
#
# Note: this test completely disables IPv6 auto-configuration to avoid
#       any type of dynamic behavior outside of MLD and IGMP protocols.
#       Static IPv6 addresses are used to ensure consistent behavior,
#       even in the startup phase when multicast snooping is enabled.
#
# Nomenclature:
#    brN - Bridge N
#    pN  - Bridge port N
#    hN  - End Host N, connected via cable/veth to bridge port N
#

ALL_TESTS="mdb_compat_fwd_test mdb_rport_fwd_test \
	mdb_mac_fwd_test mdb_ip4_fwd_test mdb_ip6_fwd_test"
NUM_NETIFS=6

SRC_PORT="1234"
DST_PORT="4321"

SRC_ADDR_IP4="1.2.3.4"
PASS_GRP_IP4="225.1.2.3"
FAIL_GRP_IP4="225.1.2.4"

SRC_ADDR_IP6="ff2e::42"
PASS_GRP_IP6="ff02::42"
FAIL_GRP_IP6="ff02::43"

SRC_ADDR_MAC="00:de:ad:be:ef:00"
PASS_GRP_MAC="01:00:01:c0:ff:ee"
FAIL_GRP_MAC="01:00:01:c0:ff:ef"

PASS_PKT_MAC="$PASS_GRP_MAC $SRC_ADDR_MAC 00:04 48:45:4c:4f"
FAIL_PKT_MAC="$FAIL_GRP_MAC $SRC_ADDR_MAC 00:04 46:41:49:4c"

PASS_PKT_IP4="01:00:5e:01:02:03 $SRC_ADDR_MAC 08:00 45:00 00:20 c2:10 00:00 \
		ff 11 12:b2 01:02:03:04 e1:01:02:03 04:d2 10:e1 00:0c 6e:84 48:45:4c:4f"
FAIL_PKT_IP4="01:00:5e:01:02:04 $SRC_ADDR_MAC 08:00 45:00 00:20 dc:e4 00:00 \
		ff 11 f7:dc 01:02:03:04 e1:01:02:04 04:d2 10:e1 00:0c 73:8a 46:41:49:4c"

PASS_PKT_IP6="33:33:00:00:00:42 $SRC_ADDR_MAC 86:dd 60 00 01 01 00 08 11 ff \
		ff 2e 00 00 00 00 00 00 00 00 00 00 00 00 00 42 ff 02 00 00 \
		00 00 00 00 00 00 00 00 00 00 00 42 04 d2 10 e1 00 08 eb 75"
FAIL_PKT_IP6="33:33.00:00:00:43 $SRC_ADDR_MAC 86:dd 60 00 01 01 00 08 11 ff \
		ff 2e 00 00 00 00 00 00 00 00 00 00 00 00 00 42 ff 02 00 00 \
		00 00 00 00 00 00 00 00 00 00 00 43 04 d2 10 e1 00 08 eb 74"

# Disable promisc to ensure we only receive flooded or subscribed traffic
TCPDUMP_EXTRA_FLAGS="-pl"

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
	# Enable multicast filtering w/ querier, allow flooding even
	# after we've detected an mrouted, reduce query response and
	# startup interval to speed up test a bit.
	ip link add dev br0 type bridge mcast_snooping 1 mcast_flood_mrouters_only 0 \
           mcast_startup_query_interval 400 mcast_query_response_interval 200

	# Set static IPv6 address before we enable the multicast querier
	# function.  This, along with disabling IPv6 address auto config
	# (previously), ensures correct forwarding according to the MDB
	# even when per-port flooding is disabled, *after* the initial
	# startup phase when the bridge floods all multicast (according
	# to its per-port mcast_flood settings.
	ip addr add 2001:db8:1::42/64 dev br0
	ip link set br0 type bridge mcast_querier 1

        ip link set dev $p1 master br0
	ip link set dev $p2 master br0
	ip link set dev $p3 master br0

        ip link set dev br0 up
        ip link set dev $p1 up
	ip link set dev $p2 up
	ip link set dev $p3 up

	# Initial delay, when bridge floods all mcast, is set to 200
	# above (2 sec.)  We wait 3 sec to handle the case when a single
	# strict fwd test is run directly after the initial setup, e.g.,
	# TESTS=mdb_ip6_fwd_test
	sleep 3
}

switch_destroy()
{
	ip link set dev $p3 down
	ip link set dev $p2 down
	ip link set dev $p1 down
	ip link del dev br0
}

setup_prepare()
{
	h1=${NETIFS[p1]}
	p1=${NETIFS[p2]}

	p2=${NETIFS[p3]}
	h2=${NETIFS[p4]}

	p3=${NETIFS[p5]}
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

do_compat_fwd()
{
	port=$1
	RET=0

	# Ensure default settings, regardless of test start order
	bridge link set dev "$p1" mcast_flood on
	bridge link set dev "$p2" mcast_flood on
	ip link set "br0" type bridge mcast_flood 1

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
# regular bridge ports and the bridge itself.
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
	iface=$h1
	type="IPv4"

	# Disable flooding of unknown multicast, strict MDB forwarding
	bridge link set dev "$p1" mcast_flood off
	bridge link set dev "$p2" mcast_flood off
	ip link set "br0" type bridge mcast_flood 0

	# Let h2 act as a multicast router
	ip link set dev "$p1" type bridge_slave mcast_router 2

	# Static filter only to this decoy port
	bridge mdb add dev br0 port $decoy grp "$pass_grp"
	check_err $? "Failed adding multicast group $pass_grp to bridge port $decoy"

	tcpdump_start "$iface"

	# Real data we're expecting
	$MZ -q "$h2" "$pass_pkt"
	# This should not pass
	$MZ -q "$h2" "$fail_pkt"

	sleep 1
	tcpdump_stop "$iface"

	tcpdump_show "$iface" |grep -q "$src$spt > $pass_grp$dpt"
	check_err $? "Failed forwarding $type multicast $pass_grp from $h2 to port $iface"

	tcpdump_show "$iface" |grep -q "$src$spt > $fail_grp$dpt"
	check_err $? "Failed forwarding $type multicast $fail_grp from $h2 to port $iface"

	bridge mdb del dev br0 port br0 grp "$pass_grp"
	ip link set dev "$p1" type bridge_slave mcast_router 1

	log_test "MDB forward all $type multicast to multicast router on $iface"
	tcpdump_cleanup "$iface"
}

do_mdb_fwd()
{
	type=$1
	iface=$2
	port=$iface
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
	if [ "$iface" = "$h2" ]; then
		port=$p2
		nop=$h3
	else
		nop=$h2
	fi

	# Disable flooding of unknown multicast, strict MDB forwarding
	bridge link set dev "$p1" mcast_flood off
	bridge link set dev "$p2" mcast_flood off
	bridge link set dev "$p3" mcast_flood off
	ip link set "br0" type bridge mcast_flood 0

	# Static filter only to this port
	bridge mdb add dev br0 port "$port" grp "$pass_grp" $flag
	check_err $? "Failed adding $type multicast group $pass_grp to bridge port $port"

	tcpdump_start "$iface"
	tcpdump_start "$nop"

	# Real data we're expecting
	$MZ -q "$h1" "$pass_pkt"
	# This should not pass
	$MZ -q "$h1" "$fail_pkt"

	sleep 1
	tcpdump_stop "$iface"
	tcpdump_stop "$nop"

	tcpdump_show "$iface" |grep -q "$src$spt > $pass_grp$dpt"
	check_err $? "Failed forwarding $type multicast $pass_grp from $h1 to port $port"

	tcpdump_show "$iface" |grep -q "$src$spt > $fail_grp$dpt"
	check_err_fail 1 $? "Received $type multicast group $fail_grp from $h1 to port $port"

	# Verify we don't get multicast to the canary port
	tcpdump_show "$nop" |grep -q "$src$spt > $pass_grp$dpt"
	check_err_fail 1 $? "Received $type multicast group $pass_grp from $h1 to port $nop"
	tcpdump_show "$nop" |grep -q "$src$spt > $fail_grp$dpt"
	check_err_fail 1 $? "Received $type multicast group $fail_grp from $h1 to port $nop"

	bridge mdb del dev br0 port "$port" grp "$pass_grp"

	log_test "MDB forward $type multicast to bridge port $port"
	tcpdump_cleanup "$iface"
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
