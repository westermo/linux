/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * switchdev.h
 *
 *	Authors:
 *	Hans J. Schultz		<hans.schultz@westermo.com>
 *
 */

#ifndef DRIVERS_NET_DSA_MV88E6XXX_SWITCHDEV_H_
#define DRIVERS_NET_DSA_MV88E6XXX_SWITCHDEV_H_

#include <net/switchdev.h>
#include "chip.h"

#define ATU_LOCKED_ENTRIES_MAX	64

struct mv88e6xxx_atu_locked_entry {
	struct		list_head list;
	struct		mv88e6xxx_chip *chip;
	int		port;
	u8		mac[ETH_ALEN];
	u16		fid;
	u16		vid;
	unsigned long	expires;
};

void mv88e6xxx_add_fdb_synth_learned(struct dsa_switch *ds,
				     int port,
				     const unsigned char *addr,
				     u16 vid);
int mv88e6xxx_handle_violation(struct mv88e6xxx_chip *chip, int port,
			       struct mv88e6xxx_atu_entry *entry,
			       u16 fid, u16 type);
bool mv88e6xxx_atu_locked_entry_find_purge(struct dsa_switch *ds, int port,
					   const unsigned char *addr, u16 vid);
int mv88e6xxx_atu_locked_entry_flush(struct dsa_switch *ds, int port);
int mv88e6xxx_init_violation_handler(struct dsa_switch *ds, int port);
int mv88e6xxx_teardown_violation_handler(struct dsa_switch *ds, int port);

#endif /* DRIVERS_NET_DSA_MV88E6XXX_SWITCHDEV_H_ */
