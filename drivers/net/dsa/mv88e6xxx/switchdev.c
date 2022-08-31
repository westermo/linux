// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * switchdev.c
 *
 *	Authors:
 *	Hans J. Schultz		<hans.schultz@westermo.com>
 *
 */

#include <net/switchdev.h>
#include <linux/list.h>
#include "chip.h"
#include "global1.h"
#include "switchdev.h"

static void mv88e6xxx_atu_locked_entry_purge(struct mv88e6xxx_atu_locked_entry *ale, bool notify, bool take_nl_lock)
{
	struct switchdev_notifier_fdb_info info = {
		.addr = ale->mac,
		.vid = ale->vid,
		.locked = true,
		.offloaded = true,
	};
	struct mv88e6xxx_atu_entry entry;
	struct net_device *brport;
	struct dsa_port *dp;

	entry.portvec = MV88E6XXX_G1_ATU_DATA_PORT_VECTOR_NO_EGRESS;
	entry.state = MV88E6XXX_G1_ATU_DATA_STATE_UC_UNUSED;
	entry.trunk = false;
	ether_addr_copy(entry.mac, ale->mac);

	mv88e6xxx_reg_lock(ale->chip);
	mv88e6xxx_g1_atu_loadpurge(ale->chip, ale->fid, &entry);
	mv88e6xxx_reg_unlock(ale->chip);

	dp = dsa_to_port(ale->chip->ds, ale->port);

	if (notify) {
		if (take_nl_lock)
			rtnl_lock();
		brport = dsa_port_to_bridge_port(dp);

		if (brport) {
			call_switchdev_notifiers(SWITCHDEV_FDB_DEL_TO_BRIDGE,
						 brport, &info.info, NULL);
		} else {
			dev_err(ale->chip->dev, "No bridge port for dsa port belonging to port %d\n",
				ale->port);
		}
		if (take_nl_lock)
			rtnl_unlock();
	}

	list_del(&ale->list);
	kfree(ale);
}

static void mv88e6xxx_atu_locked_entry_cleanup(struct work_struct *work)
{
	struct mv88e6xxx_port *p = container_of(work, struct mv88e6xxx_port, ale_work.work);
	struct mv88e6xxx_atu_locked_entry *ale, *tmp;

	mutex_lock(&p->ale_list_lock);
	list_for_each_entry_safe(ale, tmp, &p->ale_list, list) {
		if (time_after(jiffies, ale->expires)) {
			mv88e6xxx_atu_locked_entry_purge(ale, true, true);
			p->ale_cnt--;
		}
	}
	mutex_unlock(&p->ale_list_lock);

	mod_delayed_work(system_long_wq, &p->ale_work, msecs_to_jiffies(100));
}

static int mv88e6xxx_new_atu_locked_entry(struct mv88e6xxx_chip *chip, const unsigned char *addr,
					  int port, u16 fid, u16 vid,
					  struct mv88e6xxx_atu_locked_entry **alep)
{
	struct mv88e6xxx_atu_locked_entry *ale;
	unsigned long now, age_time;

	ale = kmalloc(sizeof(*ale), GFP_ATOMIC);
	if (!ale)
		return -ENOMEM;

	ether_addr_copy(ale->mac, addr);
	ale->chip = chip;
	ale->port = port;
	ale->fid = fid;
	ale->vid = vid;
	now = jiffies;
	age_time = chip->age_time * chip->info->age_time_coeff;
	ale->expires = now + age_time;

	*alep = ale;
	return 0;
}

struct mv88e6xxx_fid_search_ctx {
	u16 fid_search;
	u16 vid_found;
};

static int mv88e6xxx_find_vid_on_matching_fid(struct mv88e6xxx_chip *chip,
					      const struct mv88e6xxx_vtu_entry *entry,
					      void *priv)
{
	struct mv88e6xxx_fid_search_ctx *ctx = priv;

	if (ctx->fid_search == entry->fid) {
		ctx->vid_found = entry->vid;
		return 1;
	}

	return 0;
}

int mv88e6xxx_handle_violation(struct mv88e6xxx_chip *chip, int port,
			       struct mv88e6xxx_atu_entry *entry,
			       u16 fid, u16 type)
{
	struct switchdev_notifier_fdb_info info = {
		.addr = entry->mac,
		.vid = 0,
		.sticky = true,
		.locked = true,
		.blackhole = true,
		.offloaded = true,
	};
	struct mv88e6xxx_atu_locked_entry *ale;
	struct mv88e6xxx_fid_search_ctx ctx;
	struct net_device *brport;
	struct mv88e6xxx_port *p;
	struct dsa_port *dp;
	int err;

	if (!mv88e6xxx_is_invalid_port(chip, port))
		p = &chip->ports[port];
	else
		return -ENODEV;

	ctx.fid_search = fid;
	mv88e6xxx_reg_lock(chip);
	err = mv88e6xxx_vtu_walk(chip, mv88e6xxx_find_vid_on_matching_fid, &ctx);
	mv88e6xxx_reg_unlock(chip);
	if (err < 0)
		return err;
	if (err == 1)
		info.vid = ctx.vid_found;
	else
		return -ENODATA;

	switch (type) {
	case MV88E6XXX_G1_ATU_OP_MISS_VIOLATION:
		mutex_lock(&p->ale_list_lock);
		if (p->ale_cnt >= ATU_LOCKED_ENTRIES_MAX)
			goto exit;
		mutex_unlock(&p->ale_list_lock);
		entry->portvec = MV88E6XXX_G1_ATU_DATA_PORT_VECTOR_NO_EGRESS;
		entry->state = MV88E6XXX_G1_ATU_DATA_STATE_UC_STATIC;
		entry->trunk = false;

		mv88e6xxx_reg_lock(chip);
		err = mv88e6xxx_g1_atu_loadpurge(chip, fid, entry);
		if (err)
			goto fail;
		mv88e6xxx_reg_unlock(chip);

		dp = dsa_to_port(chip->ds, port);
		err = mv88e6xxx_new_atu_locked_entry(chip, entry->mac, port, fid,
						     info.vid, &ale);
		if (err)
			return err;

		mutex_lock(&p->ale_list_lock);
		list_add(&ale->list, &p->ale_list);
		p->ale_cnt++;
		mutex_unlock(&p->ale_list_lock);

		rtnl_lock();
		brport = dsa_port_to_bridge_port(dp);
		if (!brport) {
			rtnl_unlock();
			return -ENODEV;
		}
		err = call_switchdev_notifiers(SWITCHDEV_FDB_ADD_TO_BRIDGE,
					       brport, &info.info, NULL);
		rtnl_unlock();
		break;
	}

	return err;

fail:
	mv88e6xxx_reg_unlock(chip);
	return err;

exit:
	mutex_unlock(&p->ale_list_lock);
	return 0;
}

bool mv88e6xxx_atu_locked_entry_find_purge(struct dsa_switch *ds, int port,
					   const unsigned char *addr, u16 vid)
{
	struct mv88e6xxx_atu_locked_entry *ale, *tmp;
	struct mv88e6xxx_chip *chip = ds->priv;
	struct mv88e6xxx_port *p;
	bool found = false;

	p = &chip->ports[port];
	mutex_lock(&p->ale_list_lock);
	list_for_each_entry_safe(ale, tmp, &p->ale_list, list) {
		if (ether_addr_equal(ale->mac, addr) == 0) {
			if (ale->vid == vid) {
				mv88e6xxx_atu_locked_entry_purge(ale, false, false);
				p->ale_cnt--;
				found = true;
				break;
			}
		}
	}
	mutex_unlock(&p->ale_list_lock);
	return found;
}

int mv88e6xxx_atu_locked_entry_flush(struct dsa_switch *ds, int port)
{
	struct mv88e6xxx_atu_locked_entry *ale, *tmp;
	struct mv88e6xxx_chip *chip = ds->priv;
	struct mv88e6xxx_port *p;

	if (!mv88e6xxx_is_invalid_port(chip, port))
		p = &chip->ports[port];
	else
		return -ENODEV;

	mutex_lock(&p->ale_list_lock);
	list_for_each_entry_safe(ale, tmp, &p->ale_list, list) {
		mv88e6xxx_atu_locked_entry_purge(ale, true, false);
		p->ale_cnt--;
	}
	mutex_unlock(&p->ale_list_lock);

	return 0;
}

int mv88e6xxx_init_violation_handler(struct dsa_switch *ds, int port)
{
	struct mv88e6xxx_chip *chip = ds->priv;
	struct mv88e6xxx_port *p;

	if (!mv88e6xxx_is_invalid_port(chip, port))
		p = &chip->ports[port];
	else
		return -ENODEV;

	INIT_LIST_HEAD(&p->ale_list);
	mutex_init(&p->ale_list_lock);
	p->ale_cnt = 0;
	INIT_DELAYED_WORK(&p->ale_work, mv88e6xxx_atu_locked_entry_cleanup);
	mod_delayed_work(system_long_wq, &p->ale_work, msecs_to_jiffies(500));

	return 0;
}

int mv88e6xxx_teardown_violation_handler(struct dsa_switch *ds, int port)
{
	struct mv88e6xxx_chip *chip = ds->priv;
	struct mv88e6xxx_port *p;

	if (!mv88e6xxx_is_invalid_port(chip, port))
		p = &chip->ports[port];
	else
		return -ENODEV;

	cancel_delayed_work(&p->ale_work);
	mv88e6xxx_atu_locked_entry_flush(ds, port);
	mutex_destroy(&p->ale_list_lock);

	return 0;
}
