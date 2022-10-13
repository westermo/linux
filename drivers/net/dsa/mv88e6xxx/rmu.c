// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Marvell 88E6xxx Switch Remote Management Unit Support
 *
 * Copyright (c) 2022 Westermo Teleindustri AB
 *     Mattias Forsblad <mattias.forsblad@westermo.com>
 */

#include "rmu.h"
#include "global1.h"

#define MAX_RMON 64
#define RMON_REPLY 2

#define RMU_REQ_GET_ID			1
#define RMU_REQ_DUMP_MIB		2
#define RMU_REQ_DUMP_ATU		3

#define RMU_FORMAT_1			0x0001
#define RMU_FORMAT_2			0x0002
#define RMU_PAD				0x0000

#define RMU_CODE_GOT_ID			0x0000
#define RMU_CODE_DUMP_MIB		0x1020
#define RMU_CODE_DUMP_ATU		0x1000

#define RMU_ATU_ENTRY_STATE		GENMASK(15, 12)
#define RMU_ATU_TRUNK			BIT(11)
#define RMU_ATU_DPV			GENMASK(10, 0)
#define RMU_ATU_PRI			GENMASK(14, 12)
#define RMU_ATU_FID			GENMASK(11, 0)
#define RMU_ATU_PRI			GENMASK(14, 12)
#define RMU_ATU_MAX_ENTRY		48
#define RMU_ATU_CACHE_TIME		(HZ / 10)

#define RMU_STATS_GET_PORT_MASK		GENMASK(7,0)

struct dump_atu_entry {
	__be16 entry_prolog;
	u8 mac[6];
	__be16 entry_epilog;
} __packed;

struct dump_atu {
	struct dump_atu_entry entry[48];
	__be16 ccode;
} __packed;

static void mv88e6xxx_rmu_assert_lock(struct mv88e6xxx_chip *chip)
{
	if (unlikely(!mutex_is_locked(&chip->rmu.mutex))) {
		dev_err(chip->dev, "RMU lock not held!\n");
		dump_stack();
	}
}

int mv88e6xxx_inband_rcv(struct dsa_switch *ds, struct sk_buff *skb, int seq_no)
{
	struct mv88e6xxx_chip *chip = ds->priv;
	struct mv88e6xxx_port *port;
	__be16 prodnum;
	__be16 format;
	__be16 code;
	__be32 *mib_data;
	u8 pkt_dev;
	u8 pkt_prt;
	int i;

	if (!skb || !chip)
		return 0;

	/* Extract response data */
	format = ntohs(*(__be16 *)&skb->data[0]);
	if (format != RMU_FORMAT_1 &&
	    format != RMU_FORMAT_2) {
		dev_err(chip->dev, "RMU: Received unknown format 0x%04x", format);
		goto out;
	}

	code = ntohs(*(__be16 *)&skb->data[4]);
	if (code == 0xffff) {
		netdev_err(skb->dev, "RMU: Error response code 0x%04x", code);
		goto out;
	}

	/* Check sequence number */
	if (seq_no != chip->rmu.seq_no) {
		netdev_err(skb->dev, "RMU: Wrong seqno received %d, expected %d",
			   seq_no, chip->rmu.seq_no);
		goto out;
	}

	/* Check response code */
	switch (chip->rmu.request_cmd) {
	case RMU_REQ_GET_ID: {
		if (code == RMU_CODE_GOT_ID) {
			prodnum = ntohs(*(__be16 *)&skb->data[2]);
			chip->rmu.got_id = prodnum;
			dev_info(chip->dev,
				 "RMU: Received id OK. Prodnr 0x%04x\n",
				 chip->rmu.got_id);
		} else {
			dev_err(chip->dev,
				"RMU: Unknown response for GET_ID format 0x%04x code 0x%04x",
				format, code);
		}
		break;
	}
	case RMU_REQ_DUMP_MIB:
		if (code == RMU_CODE_DUMP_MIB) {
			pkt_dev = skb->data[6] & 0x1f;
			if (pkt_dev >= DSA_MAX_SWITCHES) {
				netdev_err(skb->dev, "RMU: Response from unknown chip %d\n", pkt_dev);
				goto out;
			}

			pkt_prt = (skb->data[7] & 0x78) >> 3;
			mib_data = (__be32 *)&skb->data[12];
			port = &chip->ports[pkt_prt];
			if (!port) {
				dev_err(chip->dev,
					"RMU: Illegal port number in response: %d\n", pkt_prt);
				goto out;
			}

			/* Copy whole array for further
			 * processing according to chip type
			 */
			for (i = 0; i < MAX_RMON; i++)
				port->rmu_raw_stats[i] = ntohl(mib_data[i]);
		}
		break;
	case RMU_REQ_DUMP_ATU:
		if (code == RMU_CODE_DUMP_ATU) {
			skb_pull(skb, 6);
			chip->rmu.resp = skb_get(skb);
			chip->rmu.resp_time = jiffies;
		}
		break;
	default:
		dev_err(chip->dev,
			"RMU: Unknown response format 0x%04x and code 0x%04x from chip %d\n",
			format, code, chip->ds->index);
		break;
}

out:
	complete(&chip->rmu.completion);

	return 0;
}

static int mv88e6xxx_rmu_tx(struct mv88e6xxx_chip *chip, int port,
			    const char *msg, int len)
{
	const struct dsa_device_ops *tag_ops;
	const struct dsa_port *dp;
	unsigned char *data;
	struct sk_buff *skb;

	dp = dsa_to_port(chip->ds, port);
	if (!dp || !dp->cpu_dp)
		return 0;

	tag_ops = dp->cpu_dp->tag_ops;
	if (!tag_ops || !tag_ops->inband_xmit)
		return -ENODEV;

	skb = netdev_alloc_skb(chip->rmu.netdev, 64);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, 2 * ETH_HLEN + tag_ops->needed_headroom);
	skb_reset_network_header(skb);
	skb->pkt_type = PACKET_OUTGOING;
	skb->dev = chip->rmu.netdev;

	/* Create RMU L3 message */
	data = skb_put(skb, len);
	memcpy(data, msg, len);

	return tag_ops->inband_xmit(skb, dp->slave, ++chip->rmu.seq_no);
}

static int mv88e6xxx_rmu_send_wait(struct mv88e6xxx_chip *chip, int port,
				   int request, void *msg, int len)
{
	const struct dsa_port *dp;
	struct net_device *master;
	int ret = 0;

	mv88e6xxx_rmu_assert_lock(chip);

	dp = dsa_to_port(chip->ds, port);
	if (!dp)
		return 0;

	master = dp->master;

	chip->rmu.request_cmd = request;

	reinit_completion(&chip->rmu.completion);

	ret = mv88e6xxx_rmu_tx(chip, port, msg, len);
	if (ret == -ENODEV) {
		/* Device not ready yet? Try again later */
		ret = 0;
		goto out;
	}

	if (ret) {
		dev_err(chip->dev, "RMU: Error transmitting request (%d)", ret);
		goto out;
	}

	ret = wait_for_completion_timeout(&chip->rmu.completion,
					  msecs_to_jiffies(MV88E6XXX_WAIT_POLL_TIME_MS));
	if (ret == 0) {
		dev_err(chip->dev, "RMU: Timeout waiting for request %d (%d) on dev:port %d:%d\n",
			request, ret, chip->ds->index, port);
		ret = -ETIMEDOUT;
	}

out:
	return ret > 0 ? 0 : ret;
}

static int mv88e6xxx_rmu_get_id(struct mv88e6xxx_chip *chip, int port)
{
	__be16 get_id[4] = {0};
	int ret;

	if (chip->rmu.got_id)
		return 0;

	chip->rmu.netdev = dev_get_by_name(&init_net, "chan0");
	if (!chip->rmu.netdev)
		return -ENODEV;

	mutex_lock(&chip->rmu.mutex);
	ret = mv88e6xxx_rmu_send_wait(chip, port, RMU_REQ_GET_ID, get_id, 8);
	if (ret)
		dev_err(chip->dev, "RMU: Error for cmd GET_ID %d index %d\n", ret, chip->ds->index);

	mutex_unlock(&chip->rmu.mutex);

	return 0;
}

int mv88e6xxx_rmu_stats_get(struct mv88e6xxx_chip *chip, int port,
			    uint64_t *data)
{
	__be16 dump_mib[4] = {0};
	int ret;

	if (!chip)
		return 0;

	ret = mv88e6xxx_rmu_get_id(chip, port);
	if (ret)
		return ret;

	dump_mib[0] = cpu_to_be16(RMU_FORMAT_1);
	dump_mib[2] = cpu_to_be16(RMU_CODE_DUMP_MIB);
	dump_mib[3] = cpu_to_be16(FIELD_PREP(RMU_STATS_GET_PORT_MASK, port));

	/* Send a GET_MIB command */
	mutex_lock(&chip->rmu.mutex);
	ret = mv88e6xxx_rmu_send_wait(chip, port, RMU_REQ_DUMP_MIB, dump_mib, 8);
	if (ret)
		dev_err(chip->dev, "RMU: Error for command DUMP_MIB %d dev %d:%d\n", ret,
			chip->ds->index, port);

	mutex_unlock(&chip->rmu.mutex);

	/* Update MIB for port */
	if (chip->info->ops->stats_get_stats)
		return chip->info->ops->stats_get_stats(chip, port, data);

	return ret;
}

static u16 mv88e6xxx_rmu_get_ccode(struct mv88e6xxx_chip *chip)
{
	struct dump_atu *atu;
	u16 prolog;
	int state;
	int i;

	atu = (struct dump_atu *)chip->rmu.resp->data;
	for (i = 0; i < RMU_ATU_MAX_ENTRY; ++i) {
		prolog = be16_to_cpu(atu->entry[i].entry_prolog);
		state = FIELD_GET(RMU_ATU_ENTRY_STATE, prolog);
		if (!state)
			break;
	}

	if (i == RMU_ATU_MAX_ENTRY)
		return be16_to_cpu(atu->ccode);

	return 0;
}

static int mv88e6xxx_port_db_dump_fid_rmu(struct mv88e6xxx_chip *chip,
					  u16 fid, u16 vid, int port,
					  dsa_fdb_dump_cb_t *cb, void *data)
{
	__be16 dump_atu[4] = {0};
	struct dump_atu *atu;
	struct sk_buff *skb;
	u16 entry_fid;
	int is_static;
	u16 prolog;
	u16 epilog;
	u16 ccode;
	u16 state;
	u16 trunk;
	int ret;
	u16 dpv;
	u16 pri;
	int i;

	dump_atu[0] = cpu_to_be16(RMU_FORMAT_1);
	dump_atu[2] = cpu_to_be16(RMU_CODE_DUMP_ATU);

	ret = mv88e6xxx_rmu_get_id(chip, port);
	if (ret)
		return ret;

	mutex_lock(&chip->rmu.mutex);

	if (chip->rmu.resp_time) {
		/* Use cached data if within time limit */
		if (time_after(jiffies, chip->rmu.resp_time + RMU_ATU_CACHE_TIME)) {
			skb_queue_purge(&chip->rmu.atu_skbs);
		} else {
			/* Cache hit */
			goto process;
		}
	}

	chip->rmu.resp = NULL;
	chip->rmu.resp_time = 0;

	do {
		ret = mv88e6xxx_rmu_send_wait(chip, port, RMU_REQ_DUMP_ATU, dump_atu, 8);
		if (ret) {
			dev_err(chip->dev, "RMU: Error for command DUMP_MIB %d dev %d:%d\n", ret,
				chip->ds->index, port);
			ret = -EIO;
			goto out;
		}

		if (!chip->rmu.resp) {
			ret = -EIO;
			goto out;
		}

		__skb_queue_tail(&chip->rmu.atu_skbs, chip->rmu.resp);

		/* Are there more entries to get? */
		ccode = mv88e6xxx_rmu_get_ccode(chip);
		dump_atu[3] = cpu_to_be16(ccode);
	} while(ccode);

process:
	skb_queue_walk(&chip->rmu.atu_skbs, skb) {
		atu = (struct dump_atu *)skb->data;
		for (i = 0; i < RMU_ATU_MAX_ENTRY; ++i) {
			prolog = be16_to_cpu(atu->entry[i].entry_prolog);
			epilog = be16_to_cpu(atu->entry[i].entry_epilog);

			state = FIELD_GET(RMU_ATU_ENTRY_STATE, prolog);
			dpv = FIELD_GET(RMU_ATU_DPV, prolog);
			trunk = FIELD_GET(RMU_ATU_TRUNK, prolog);
			if (!state) {
				break; /* End of frame */
			}

			pri = FIELD_GET(RMU_ATU_PRI, epilog);
			entry_fid = FIELD_GET(RMU_ATU_FID, epilog);
			if (fid != entry_fid)
				continue;

			if (trunk || (dpv & BIT(port)) == 0)
				continue;

			if (!is_unicast_ether_addr(atu->entry[i].mac))
				continue;

			is_static = (state == MV88E6XXX_G1_ATU_DATA_STATE_UC_STATIC);
			ret = cb(atu->entry[i].mac, vid, is_static, data);
			if (ret)
				goto out;
		}
	}

out:
	mutex_unlock(&chip->rmu.mutex);

	return ret;
}

static struct mv88e6xxx_bus_ops mv88e6xxx_bus_ops = {
	.get_rmon = mv88e6xxx_rmu_stats_get,
	.dump_fid = mv88e6xxx_port_db_dump_fid_rmu,
};

int mv88e6xxx_rmu_init(struct mv88e6xxx_chip *chip)
{
	int ret = 0;

	dev_info(chip->dev, "RMU: Setting up for switch@%d", chip->sw_addr);

	init_completion(&chip->rmu.completion);

	mutex_init(&chip->rmu.mutex);
	__skb_queue_head_init(&chip->rmu.atu_skbs);

	chip->rmu.ops = &mv88e6xxx_bus_ops;

	return ret;
}
