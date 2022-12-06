// SPDX-License-Identifier: GPL-2.0+
/* Microchip Sparx5 Switch driver
 *
 * Copyright (c) 2022 Microchip Technology Inc. and its subsidiaries.
 */

#include <net/pkt_cls.h>

#include "sparx5_tc.h"
#include "sparx5_main.h"
#include "sparx5_qos.h"

/* tc block handling */
static LIST_HEAD(sparx5_block_cb_list);

static int sparx5_tc_block_cb(enum tc_setup_type type,
			      void *type_data,
			      void *cb_priv, bool ingress)
{
	struct net_device *ndev = cb_priv;

	switch (type) {
	case TC_SETUP_CLSMATCHALL:
		return sparx5_tc_matchall(ndev, type_data, ingress);
	case TC_SETUP_CLSFLOWER:
		return sparx5_tc_flower(ndev, type_data, ingress);
	default:
		return -EOPNOTSUPP;
	}
}

static int sparx5_tc_block_cb_ingress(enum tc_setup_type type,
				      void *type_data,
				      void *cb_priv)
{
	return sparx5_tc_block_cb(type, type_data, cb_priv, true);
}

static int sparx5_tc_block_cb_egress(enum tc_setup_type type,
				     void *type_data,
				     void *cb_priv)
{
	return sparx5_tc_block_cb(type, type_data, cb_priv, false);
}

static int sparx5_tc_setup_block(struct net_device *ndev,
				 struct flow_block_offload *fbo)
{
	flow_setup_cb_t *cb;

	if (fbo->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		cb = sparx5_tc_block_cb_ingress;
	else if (fbo->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS)
		cb = sparx5_tc_block_cb_egress;
	else
		return -EOPNOTSUPP;

	return flow_block_cb_setup_simple(fbo, &sparx5_block_cb_list,
					  cb, ndev, ndev, false);
}

static void sparx5_tc_get_layer_and_idx(u32 parent, u32 portno, u32 *layer,
					u32 *idx)
{
	if (parent == TC_H_ROOT) {
		*layer = 2;
		*idx = portno;
	} else {
		u32 queue = TC_H_MIN(parent) - 1;
		*layer = 0;
		*idx = SPX5_HSCH_L0_GET_IDX(portno, queue);
	}
}

static int sparx5_tc_setup_qdisc_mqprio(struct net_device *ndev,
					struct tc_mqprio_qopt_offload *m)
{
	m->qopt.hw = TC_MQPRIO_HW_OFFLOAD_TCS;

	if (m->qopt.num_tc == 0)
		return sparx5_tc_mqprio_del(ndev);
	else
		return sparx5_tc_mqprio_add(ndev, m->qopt.num_tc);
}

static int sparx5_tc_setup_qdisc_tbf(struct net_device *ndev,
				     struct tc_tbf_qopt_offload *qopt)
{
	struct sparx5_port *port = netdev_priv(ndev);
	u32 layer, se_idx;

	sparx5_tc_get_layer_and_idx(qopt->parent, port->portno, &layer,
				    &se_idx);

	switch (qopt->command) {
	case TC_TBF_REPLACE:
		return sparx5_tc_tbf_add(port, &qopt->replace_params, layer,
					 se_idx);
	case TC_TBF_DESTROY:
		return sparx5_tc_tbf_del(port, layer, se_idx);
	case TC_TBF_STATS:
		return -EOPNOTSUPP;
	default:
		return -EOPNOTSUPP;
	}

	return -EOPNOTSUPP;
}

static int sparx5_tc_setup_qdisc_ets(struct net_device *ndev,
				     struct tc_ets_qopt_offload *qopt)
{
	struct tc_ets_qopt_offload_replace_params *params =
		&qopt->replace_params;
	struct sparx5_port *port = netdev_priv(ndev);
	int i;

	/* Only allow ets on ports  */
	if (qopt->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	switch (qopt->command) {
	case TC_ETS_REPLACE:

		/* We support eight priorities */
		if (params->bands != SPX5_PRIOS)
			return -EOPNOTSUPP;

		/* Sanity checks */
		for (i = 0; i < SPX5_PRIOS; ++i) {
			/* Priority map is *always* reverse e.g: 7 6 5 .. 0 */
			if (params->priomap[i] != (7 - i))
				return -EOPNOTSUPP;
			/* Throw an error if we receive zero weights by tc */
			if (params->quanta[i] && params->weights[i] == 0) {
				pr_err("Invalid ets configuration; band %d has weight zero",
				       i);
				return -EINVAL;
			}
		}

		sparx5_tc_ets_add(port, params);
		break;
	case TC_ETS_DESTROY:

		sparx5_tc_ets_del(port);

		break;
	case TC_ETS_GRAFT:
		return -EOPNOTSUPP;

	default:
		return -EOPNOTSUPP;
	}

	return -EOPNOTSUPP;
}

static const char * const tc_setup_type_strings[] = {
	[TC_SETUP_QDISC_MQPRIO] = "QDISC_MQPRIO",
	[TC_SETUP_CLSU32]       = "CLSU32",
	[TC_SETUP_CLSFLOWER]    = "CLSFLOWER",
	[TC_SETUP_CLSMATCHALL]  = "CLSMATCHALL",
	[TC_SETUP_CLSBPF]       = "CLSBPF",
	[TC_SETUP_BLOCK]        = "BLOCK",
	[TC_SETUP_QDISC_CBS]    = "QDISC_CBS",
	[TC_SETUP_QDISC_RED]    = "QDISC_RED",
	[TC_SETUP_QDISC_PRIO]   = "QDISC_PRIO",
	[TC_SETUP_QDISC_MQ]     = "QDISC_MQ",
	[TC_SETUP_QDISC_ETF]    = "QDISC_ETF",
	[TC_SETUP_ROOT_QDISC]   = "ROOT_QDISC",
	[TC_SETUP_QDISC_GRED]   = "QDISC_GRED",
	[TC_SETUP_QDISC_TAPRIO] = "QDISC_TAPRIO",
	[TC_SETUP_FT]           = "FT",
	[TC_SETUP_QDISC_ETS]    = "QDISC_ETS",
	[TC_SETUP_QDISC_TBF]    = "QDISC_TBF",
	[TC_SETUP_QDISC_FIFO]   = "QDISC_FIFO",
	[TC_SETUP_QDISC_HTB]    = "QDISC_HTB",
	[TC_SETUP_ACT]          = "ACT"

};

const char *tc_dbg_tc_setup_type(enum tc_setup_type type)
{
	if (type > TC_SETUP_ACT)
		return "INVALID TC_SETUP_TYPE!";
	return tc_setup_type_strings[type];
}

static int sparx5_tc_setup_qdisc_taprio(struct sparx5_port *port,
					struct tc_taprio_qopt_offload *qopt)
{
	int i, err;

	netdev_dbg(port->ndev,
		   "port %u enable %d\n",
		   port->portno, qopt->enable);
	if (qopt->enable) {
		netdev_dbg(port->ndev,
			   "base_time %lld cycle_time %llu cycle_time_extension %llu\n",
			   qopt->base_time, qopt->cycle_time,
			   qopt->cycle_time_extension);
		for (i = 0; i < qopt->num_entries; i++) {
			netdev_dbg(port->ndev,
				   "[%d]: command %u gate_mask %x interval %u\n",
				   i, qopt->entries[i].command,
				   qopt->entries[i].gate_mask,
				   qopt->entries[i].interval);
		}
		err = sparx5_tas_enable(port, qopt);
	} else {
		err = sparx5_tas_disable(port);
	}

	return err;
}

int sparx5_port_setup_tc(struct net_device *ndev, enum tc_setup_type type,
			 void *type_data)
{
	switch (type) {
	case TC_SETUP_BLOCK:
		return sparx5_tc_setup_block(ndev, type_data);
	case TC_SETUP_QDISC_MQPRIO:
		return sparx5_tc_setup_qdisc_mqprio(ndev, type_data);
	case TC_SETUP_QDISC_TBF:
		return sparx5_tc_setup_qdisc_tbf(ndev, type_data);
	case TC_SETUP_QDISC_ETS:
		return sparx5_tc_setup_qdisc_ets(ndev, type_data);
	case TC_SETUP_QDISC_TAPRIO:
		return sparx5_tc_setup_qdisc_taprio(port, type_data);
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}
