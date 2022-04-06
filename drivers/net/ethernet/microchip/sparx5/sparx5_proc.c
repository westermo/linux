// SPDX-License-Identifier: GPL-2.0+
/* Microchip Sparx5 Switch driver
 *
 * Copyright (c) 2020 Microchip Technology Inc. and its subsidiaries.
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sfp.h>

#include "sparx5_main_regs.h"
#include "sparx5_main.h"
#include "sparx5_port.h"

static char get_bool(bool val)
{
	if (val)
		return 'Y';
	return ' ';
}

static void proc_show_portstate(struct seq_file *f,
				struct sparx5_port *port,
				struct ethtool_eeprom *sfp_eeprom)
{
	struct sfp_eeprom_id *id = (struct sfp_eeprom_id *)&sfp_eeprom->data[0];
	struct net_device *ndev = port->ndev;
	struct sparx5_port_status status;
	u32 value;
	bool phy_link = false, aneg_enabled = false, aneg_complete = false;

	if (!ndev)
		return;
	if (ndev->phydev) {
		phy_link = ndev->phydev->link;
		aneg_enabled = ndev->phydev->autoneg;
		aneg_complete = ndev->phydev->autoneg_complete;
	} else {
		value = spx5_rd(port->sparx5, DEV2G5_PCS1G_ANEG_CFG(port->portno));
		aneg_enabled = DEV2G5_PCS1G_ANEG_CFG_ANEG_ENA_GET(value);
		value = spx5_rd(port->sparx5, DEV2G5_PCS1G_ANEG_STATUS(port->portno));
		aneg_complete = DEV2G5_PCS1G_ANEG_STATUS_ANEG_COMPLETE_GET(value);
	}
	sparx5_get_port_status(port->sparx5, port, &status);

	seq_printf(f, " %02d  %-15s %-12s   %c        %c      %c      %c",
		   port->portno,
		   phy_modes(port->conf.portmode),
		   status.speed ? phy_speed_to_str(status.speed) : "",
		   get_bool(status.link),
		   get_bool(phy_link),
		   get_bool(aneg_enabled),
		   get_bool(aneg_complete));
	if (ndev->sfp_bus) {
		struct ethtool_modinfo modinfo;

		if (sfp_get_module_info(ndev->sfp_bus, &modinfo))
			return;
		sfp_eeprom->offset = 0;
		sfp_eeprom->len = modinfo.eeprom_len;
		if (sfp_get_module_eeprom(ndev->sfp_bus, sfp_eeprom,
					  &sfp_eeprom->data[0]) == 0) {
			seq_printf(f, "    SFP: %.16s %.16s",
				   id->base.vendor_name, id->base.vendor_pn);
		}
	}
	if (ndev->phydev)
		seq_printf(f, "    PHY: %-20s", ndev->phydev->drv->name);
	seq_puts(f, "\n");
}

static int proc_portstate_(struct seq_file *f, void *v)
{
	struct sparx5 *sparx5 = f->private;
	struct ethtool_eeprom *sfp_eeprom;
	int idx;

	sfp_eeprom = kzalloc(sizeof(*sfp_eeprom) +
			     ETH_MODULE_SFF_8472_LEN, GFP_KERNEL);
	if (!sfp_eeprom)
		return 0;
	seq_puts(f, "Port Mode            Speed        ");
	seq_puts(f, "PLink   PhyLink ANegEn ANegCp SFP/PHY\n");
	for (idx = 0; idx < SPX5_PORTS; idx++)
		if (sparx5->ports[idx])
			proc_show_portstate(f, sparx5->ports[idx], sfp_eeprom);
	kfree(sfp_eeprom);
	return 0;
}

static int proc_portstate(struct inode *inode, struct file *f)
{
	return single_open(f, proc_portstate_, pde_data(inode));
}

static const struct proc_ops portstate_proc_ops = {
	.proc_open = proc_portstate,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int proc_fdmastate_(struct seq_file *f, void *v)
{
	struct sparx5 *sparx5 = f->private;

	seq_printf(f, "chan: %d: TX: packets: %llu, dropped: %llu\n",
		   sparx5->tx.channel_id,
		   sparx5->tx.packets, sparx5->tx.dropped);
	seq_printf(f, "chan: %d: RX: packets: %llu\n",
		   sparx5->rx.channel_id,
		   sparx5->rx.packets);
	return 0;
}

static int proc_fdmastate(struct inode *inode, struct file *f)
{
	return single_open(f, proc_fdmastate_, pde_data(inode));
}

static const struct proc_ops fdmastate_proc_ops = {
	.proc_open = proc_fdmastate,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static void proc_show_portstats(struct seq_file *f, struct sparx5 *sparx5,
				int portno)
{
	const char *name;
	u64 val;
	int idx;

	seq_printf(f, "Port %u\n", portno);
	for (idx = 0; idx < sparx5->num_stats; ++idx) {
		if (sparx5_get_cpuport_stats(sparx5, portno, idx, &name, &val)) {
			seq_printf(f, "%-*s: %llu\n", ETH_GSTRING_LEN,
				   name, val);
		}
	}
	seq_puts(f, "\n");
}

static int proc_cpuport1_stats_(struct seq_file *f, void *v)
{
	struct sparx5 *sparx5 = f->private;

	sparx5_update_cpuport_stats(sparx5, SPX5_PORT_CPU_1);
	proc_show_portstats(f, sparx5, SPX5_PORT_CPU_1);
	return 0;
}

static int proc_cpuport0_stats_(struct seq_file *f, void *v)
{
	struct sparx5 *sparx5 = f->private;

	sparx5_update_cpuport_stats(sparx5, SPX5_PORT_CPU_0);
	proc_show_portstats(f, sparx5, SPX5_PORT_CPU_0);
	return 0;
}

static int proc_cpuport0_stats(struct inode *inode, struct file *f)
{
	return single_open(f, proc_cpuport0_stats_, pde_data(inode));
}

static int proc_cpuport1_stats(struct inode *inode, struct file *f)
{
	return single_open(f, proc_cpuport1_stats_, pde_data(inode));
}

static const struct proc_ops cpuport0_stat_proc_ops = {
	.proc_open = proc_cpuport0_stats,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops cpuport1_stat_proc_ops = {
	.proc_open = proc_cpuport1_stats,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int proc_mactable_(struct seq_file *f, void *v)
{
	struct sparx5 *sparx5 = f->private;
	unsigned char mac[ETH_ALEN];
	u16 vid;
	u32 cfg2;
	int cnt = 0;

	vid = 0;
	memset(mac, 0, sizeof(mac));

	while (sparx5_mact_getnext(sparx5, mac, &vid, &cfg2)) {
		u16 addr = LRN_MAC_ACCESS_CFG_2_MAC_ENTRY_ADDR_GET(cfg2);
		u16 type = (GENMASK(14, 12) & cfg2) >> 12;
		u16 is_static = LRN_MAC_ACCESS_CFG_2_MAC_ENTRY_LOCKED_GET(cfg2);

		seq_printf(f, "%4d: %pM. Vid %d. Type %d. Addr %d. Static %d. Cfg2 (%08x)\n",
			   cnt++, mac, vid, type, addr, is_static, cfg2);
	}

	return 0;
}

static int proc_mactable(struct inode *inode, struct file *f)
{
	return single_open(f, proc_mactable_, pde_data(inode));
}

static const struct proc_ops mac_proc_ops = {
	.proc_open = proc_mactable,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int proc_port_stats_(struct seq_file *f, void *v)
{
	struct sparx5_port *port = f->private;
	struct sparx5 *sparx5 = port->sparx5;
	struct sparx5_port_stats stats;
	int portno = port->portno;

	sparx5_get_port_stats(sparx5, portno, &stats);
	seq_printf(f, "Port %u\n", portno);
	seq_printf(f, "tx_unicast: %llu\n", stats.tx_unicast);
	seq_printf(f, "tx_multicast: %llu\n", stats.tx_multicast);
	seq_printf(f, "tx_broadcast: %llu\n", stats.tx_broadcast);
	seq_printf(f, "rx_unicast: %llu\n", stats.rx_unicast);
	seq_printf(f, "rx_multicast: %llu\n", stats.rx_multicast);
	seq_printf(f, "rx_broadcast: %llu\n", stats.rx_broadcast);
	seq_puts(f, "\n");
	return 0;
}

static int proc_port_stats(struct inode *inode, struct file *f)
{
	return single_open(f, proc_port_stats_, pde_data(inode));
}

static const struct proc_ops port_stat_proc_ops = {
	.proc_open = proc_port_stats,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

void sparx5_proc_register_dbg(struct sparx5 *sparx5)
{
	char portname[32];
	int portno;

	proc_create_data("sparx5_mac", 0444, NULL, &mac_proc_ops, sparx5);
	proc_create_data("sparx5_cpuport0", 0444, NULL,
			 &cpuport0_stat_proc_ops, sparx5);
	proc_create_data("sparx5_cpuport1", 0444, NULL,
			 &cpuport1_stat_proc_ops, sparx5);
	proc_create_data("sparx5_portstate", 0444, NULL,
			 &portstate_proc_ops, sparx5);
	for (portno = 0; portno < SPX5_PORTS; portno++)
		if (sparx5->ports[portno]) {
			snprintf(portname, sizeof(portname), "sparx5_port%02d", portno);
			proc_create_data(portname, 0444, NULL,
					 &port_stat_proc_ops,
					 sparx5->ports[portno]);
		}
	proc_create_data("sparx5_fdmastate", 0444, NULL,
			 &fdmastate_proc_ops, sparx5);
}

void sparx5_proc_unregister_dbg(void)
{
	remove_proc_entry("sparx5_mac", NULL);
}
