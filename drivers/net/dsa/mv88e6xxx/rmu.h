/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Marvell 88E6xxx Switch Remote Management Unit Support
 *
 * Copyright (c) 2022 Westermo Teleindustri AB
 *     Mattias Forsblad <mattias.forsblad@westermo.com>
 */

#ifndef _MV88E6XXX_RMU_H_
#define _MV88E6XXX_RMU_H_

#include "chip.h"

int mv88e6xxx_rmu_init(struct mv88e6xxx_chip *chip);

int mv88e6xxx_inband_rcv(struct dsa_switch *ds, struct sk_buff *skb, int seq_no);

#endif /* _MV88E6XXX_RMU_H_ */
