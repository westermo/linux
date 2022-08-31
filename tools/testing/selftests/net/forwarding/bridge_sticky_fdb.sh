#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ALL_TESTS="sticky sticky_no_roaming"
NUM_NETIFS=4
TEST_MAC=de:ad:be:ef:13:37
source lib.sh

switch_create()
{
	ip link add dev br0 type bridge

	ip link set dev $swp1 master br0
	ip link set dev $swp2 master br0

	ip link set dev br0 up
	ip link set dev $h1 up
	ip link set dev $swp1 up
	ip link set dev $h2 up
	ip link set dev $swp2 up
}

switch_destroy()
{
	ip link set dev $swp2 down
	ip link set dev $h2 down
	ip link set dev $swp1 down
	ip link set dev $h1 down

	ip link del dev br0
}

setup_prepare()
{
	h1=${NETIFS[p1]}
	swp1=${NETIFS[p2]}
	h2=${NETIFS[p3]}
	swp2=${NETIFS[p4]}

	switch_create
}

cleanup()
{
	pre_cleanup
	switch_destroy
}

sticky()
{
	bridge fdb add $TEST_MAC dev $swp1 master static sticky
	check_err $? "Could not add fdb entry"
	bridge fdb del $TEST_MAC dev $swp1 vlan 1 master static sticky
	$MZ $h2 -c 1 -a $TEST_MAC -t arp "request" -q
	bridge -j fdb show br br0 brport $swp1\
		| jq -e ".[] | select(.mac == \"$TEST_MAC\")" &> /dev/null
	check_err $? "Did not find FDB record when should"

	log_test "Sticky fdb entry"
}

# No roaming allowed with the sticky flag set
sticky_no_roaming()
{
	local mac=a8:b4:c2:c2:b4:a8

	RET=0

	bridge link set dev $swp2 learning on
	bridge fdb add $mac dev $swp1 master static sticky
	bridge fdb show dev $swp1 | grep "$mac master br0" | grep -q sticky
	check_err $? "Sticky no roaming: No sticky FDB entry found after adding"

	$MZ $h2 -q -t udp -c 10 -d 100msec -a $mac -b rand
	bridge fdb show dev $swp2 | grep "$mac master br0" | grep -q sticky
	check_fail $? "Sticky no roaming: Sticky entry roamed"

	log_test "Sticky no roaming"
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
