/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2021 NXP
 */

#ifndef _NET_DSA_TAG_MV88E6XXX_H
#define _NET_DSA_TAG_MV88E6XXX_H

#include <linux/if_vlan.h>
#include <net/dsa.h>

#define MV88E6XXX_VID_STANDALONE	0
#define MV88E6XXX_VID_BRIDGED		(VLAN_N_VID - 1)

/* Global tagger data */
struct mv88e6xxx_tagger_data {
        /* Switch to tagger */
	void (*set_port_mrp_tx_fwd_offload)(struct dsa_switch *ds, int port,
					    bool on);
};

static inline struct mv88e6xxx_tagger_data *
mv88e6xxx_tagger_data(struct dsa_switch *ds)
{
	return ds->tagger_data;
}

#endif
