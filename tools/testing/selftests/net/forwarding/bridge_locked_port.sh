#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ALL_TESTS="locked_port_ipv4 locked_port_ipv6 locked_port_vlan locked_port_mab locked_port_station_move locked_port_mab_station_move"
NUM_NETIFS=4
CHECK_TC="no"
source lib.sh

h1_create()
{
	simple_if_init $h1 192.0.2.1/24 2001:db8:1::1/64
	vrf_create "vrf-vlan-h1"
	ip link set dev vrf-vlan-h1 up
	vlan_create $h1 100 vrf-vlan-h1 198.51.100.1/24
}

h1_destroy()
{
	vlan_destroy $h1 100
	simple_if_fini $h1 192.0.2.1/24 2001:db8:1::1/64
}

h2_create()
{
	simple_if_init $h2 192.0.2.2/24 2001:db8:1::2/64
	vrf_create "vrf-vlan-h2"
	ip link set dev vrf-vlan-h2 up
	vlan_create $h2 100 vrf-vlan-h2 198.51.100.2/24
}

h2_destroy()
{
	vlan_destroy $h2 100
	simple_if_fini $h2 192.0.2.2/24 2001:db8:1::2/64
}

switch_create()
{
	ip link add dev br0 type bridge vlan_filtering 1

	ip link set dev $swp1 master br0
	ip link set dev $swp2 master br0

	ip link set dev br0 up
	ip link set dev $swp1 up
	ip link set dev $swp2 up

	bridge link set dev $swp1 learning off
}

switch_destroy()
{
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

	vrf_prepare

	h1_create
	h2_create

	switch_create
}

cleanup()
{
	pre_cleanup

	switch_destroy

	h2_destroy
	h1_destroy

	vrf_cleanup
}

locked_port_ipv4()
{
	RET=0

	check_locked_port_support || return 0

	ping_do $h1 192.0.2.2
	check_err $? "Ping did not work before locking port"

	bridge link set dev $swp1 locked on

	ping_do $h1 192.0.2.2
	check_fail $? "Ping worked after locking port, but before adding FDB entry"

	bridge fdb replace `mac_get $h1` dev $swp1 master static

	ping_do $h1 192.0.2.2
	check_err $? "Ping did not work after locking port and adding FDB entry"

	bridge link set dev $swp1 locked off
	bridge fdb del `mac_get $h1` dev $swp1 master static

	ping_do $h1 192.0.2.2
	check_err $? "Ping did not work after unlocking port and removing FDB entry."

	log_test "Locked port ipv4"
}

locked_port_vlan()
{
	RET=0

	check_locked_port_support || return 0

	bridge vlan add vid 100 dev $swp1
	bridge vlan add vid 100 dev $swp2

	ping_do $h1.100 198.51.100.2
	check_err $? "Ping through vlan did not work before locking port"

	bridge link set dev $swp1 locked on
	ping_do $h1.100 198.51.100.2
	check_fail $? "Ping through vlan worked after locking port, but before adding FDB entry"

	bridge fdb replace `mac_get $h1` dev $swp1 vlan 100 master static

	ping_do $h1.100 198.51.100.2
	check_err $? "Ping through vlan did not work after locking port and adding FDB entry"

	bridge link set dev $swp1 locked off
	bridge fdb del `mac_get $h1` dev $swp1 vlan 100 master static

	ping_do $h1.100 198.51.100.2
	check_err $? "Ping through vlan did not work after unlocking port and removing FDB entry"

	bridge vlan del vid 100 dev $swp1
	bridge vlan del vid 100 dev $swp2
	log_test "Locked port vlan"
}

locked_port_ipv6()
{
	RET=0
	check_locked_port_support || return 0

	ping6_do $h1 2001:db8:1::2
	check_err $? "Ping6 did not work before locking port"

	bridge link set dev $swp1 locked on
	if ! bridge link set dev $swp1 macauth on; return 0

	ping6_do $h1 2001:db8:1::2
	check_fail $? "Ping6 worked after locking port, but before adding FDB entry"

	bridge fdb replace `mac_get $h1` dev $swp1 master static
	ping6_do $h1 2001:db8:1::2
	check_err $? "Ping6 did not work after locking port and adding FDB entry"

	bridge link set dev $swp1 locked off
	bridge fdb del `mac_get $h1` dev $swp1 master static

	ping6_do $h1 2001:db8:1::2
	check_err $? "Ping6 did not work after unlocking port and removing FDB entry"

	log_test "Locked port ipv6"
}

locked_port_mab()
{
	RET=0
	check_locked_port_support || return 0

	ping_do $h1 192.0.2.2
	check_err $? "MAB: Ping did not work before locking port"

	bridge link set dev $swp1 locked on
	check_port_mab_support $swp1 || return 0

	ping_do $h1 192.0.2.2
	check_fail $? "MAB: Ping worked on locked port without FDB entry"

	bridge fdb show | grep `mac_get $h1` | grep -q "locked"
	check_err $? "MAB: No locked fdb entry after ping on locked port"

	bridge fdb replace `mac_get $h1` dev $swp1 master static

	ping_do $h1 192.0.2.2
	check_err $? "MAB: Ping did not work with fdb entry without locked flag"

	bridge fdb del `mac_get $h1` dev $swp1 master
	bridge link set dev $swp1 locked off mab off

	log_test "Locked port MAB"
}

# No roaming allowed to a simple locked port
locked_port_station_move()                                                    
{
	local mac=a0:b0:c0:c0:b0:a0                                           

	RET=0
	check_locked_port_support || return 0

	bridge link set dev $swp1 locked on                                      

	$MZ $h1 -q -t udp -a $mac -b rand
	bridge fdb show dev $swp1 | grep "$mac vlan 1" | grep -q "master br0"
	check_fail $? "Locked port station move: FDB entry on first injection"

	$MZ $h2 -q -t udp -a $mac -b rand
	bridge fdb show dev $swp2 | grep "$mac vlan 1" | grep -q "master br0"
	check_err $? "Locked port station move: Entry not found on unlocked port"

	$MZ $h1 -q -t udp -a $mac -b rand
	bridge fdb show dev $swp1 | grep "$mac vlan 1" | grep -q "master br0"
	check_fail $? "Locked port station move: entry roamed to locked port"

	bridge link set dev $swp1 locked off

	log_test "Locked port station move"
}

# Roaming to and from a MAB enabled port should work if sticky flag is not set
locked_port_mab_station_move()
{
	local mac=10:20:30:30:20:10

	RET=0
	check_locked_port_support || return 0

	bridge link set dev $swp1 locked on

	check_port_mab_support $swp1 || return 0

	$MZ $h1 -q -t udp -a $mac -b rand
	if bridge fdb show dev $swp1 | grep "$mac vlan 1" | grep -q "permanent"; then
		echo "SKIP: Roaming not possible with local flag, skipping test..."
		bridge link set dev $swp1 locked off mab off
		return $ksft_skip
	fi

	bridge fdb show dev $swp1 | grep "$mac vlan 1" | grep -q "locked"
	check_err $? "MAB station move: no locked entry on first injection"

	$MZ $h2 -q -t udp -a $mac -b rand
	bridge fdb show dev $swp1 | grep "$mac vlan 1" | grep -q "locked"
	check_fail $? "MAB station move: locked entry did not move"

	bridge fdb show dev $swp2 | grep "$mac vlan 1" | grep -q "locked"
	check_fail $? "MAB station move: roamed entry to unlocked port had locked flag on"

	bridge fdb show dev $swp2 | grep "$mac vlan 1" | grep -q "master br0"
	check_err $? "MAB station move: roamed entry not found"

	$MZ $h1 -q -t udp -a $mac -b rand
	bridge fdb show dev $swp1 | grep "$mac vlan 1" | grep "master br0" | grep -q "locked"
	check_fail $? "MAB station move: entry roamed back to locked port"

	bridge link set dev $swp1 locked off mab off

	log_test "Locked port MAB station move"
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
