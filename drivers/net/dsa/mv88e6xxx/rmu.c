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

#define RMU_RESP_FORMAT_1		0x0001
#define RMU_RESP_FORMAT_2		0x0002

#define RMU_RESP_CODE_GOT_ID		0x0000
#define RMU_RESP_CODE_DUMP_MIB		0x1020

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
	if (format != RMU_RESP_FORMAT_1 &&
	    format != RMU_RESP_FORMAT_2) {
		dev_err(chip->dev, "RMU: Received unknown format 0x%04x", format);
		goto out;
	}

	code = ntohs(*(__be16 *)&skb->data[4]);
	if (code == 0xffff) {
		netdev_err(skb->dev, "RMU: Error response code 0x%04x", code);
		goto out;
	}

	pkt_dev = skb->data[6] & 0x1f;
	if (pkt_dev >= DSA_MAX_SWITCHES) {
		netdev_err(skb->dev, "RMU: Response from unknown chip %d\n", pkt_dev);
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
		if (code == RMU_RESP_CODE_GOT_ID) {
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
		if (code == RMU_RESP_CODE_DUMP_MIB) {
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
	int ret;

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

	ret = tag_ops->inband_xmit(skb, dp->slave, ++chip->rmu.seq_no);
	if (ret)
		netdev_err(chip->rmu.netdev, "RMU: Error sending request (%d)", ret);

	return ret;
}

static int mv88e6xxx_rmu_send_wait(struct mv88e6xxx_chip *chip, int port,
				   int request, const char *msg, int len)
{
	const struct dsa_port *dp;
	struct net_device *master;
	int ret = 0;

	dp = dsa_to_port(chip->ds, port);
	if (!dp)
		return 0;

	master = dp->master;

	mutex_lock(&chip->rmu.mutex);

	chip->rmu.request_cmd = request;

	ret = mv88e6xxx_rmu_tx(chip, port, msg, len);
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
	mutex_unlock(&chip->rmu.mutex);

	return ret > 0 ? 0 : ret;
}

static int mv88e6xxx_rmu_get_id(struct mv88e6xxx_chip *chip, int port)
{
	const u8 get_id[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int ret = -1;

	if (chip->rmu.got_id)
		return 0;

	chip->rmu.netdev = dev_get_by_name(&init_net, "chan0");
	if (!chip->rmu.netdev)
		return -ENODEV;

	ret = mv88e6xxx_rmu_send_wait(chip, port, RMU_REQ_GET_ID, get_id, 8);
	if (ret) {
		dev_err(chip->dev, "RMU: Error for cmd GET_ID %d index %d\n", ret, chip->ds->index);
		return ret;
	}

	return 0;
}

int mv88e6xxx_rmu_stats_get(struct mv88e6xxx_chip *chip, int port,
			    uint64_t *data)
{
	u8 dump_mib[8] = {0x00, 0x01, 0x00, 0x00, 0x10, 0x20, 0x00, 0x00};
	int ret;

	if (!chip)
		return 0;

	ret = mv88e6xxx_rmu_get_id(chip, port);
	if (ret)
		return ret;

	/* Send a GET_MIB command */
	dump_mib[7] = port;
	ret = mv88e6xxx_rmu_send_wait(chip, port, RMU_REQ_DUMP_MIB, dump_mib, 8);
	if (ret) {
		dev_err(chip->dev, "RMU: Error for command DUMP_MIB %d dev %d:%d\n", ret,
			chip->ds->index, port);
		return ret;
	}

	/* Update MIB for port */
	if (chip->info->ops->stats_get_stats)
		return chip->info->ops->stats_get_stats(chip, port, data);

	return 0;
}

static struct mv88e6xxx_bus_ops mv88e6xxx_bus_ops = {
	.get_rmon = mv88e6xxx_rmu_stats_get,
};

int mv88e6xxx_rmu_init(struct mv88e6xxx_chip *chip)
{
	int ret = 0;

	dev_info(chip->dev, "RMU: Setting up for switch@%d", chip->sw_addr);

	init_completion(&chip->rmu.completion);

	mutex_init(&chip->rmu.mutex);

	chip->rmu.ops = &mv88e6xxx_bus_ops;

	return ret;
}
