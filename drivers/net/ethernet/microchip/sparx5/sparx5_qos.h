/* SPDX-License-Identifier: GPL-2.0+ */
/* Microchip Sparx5 Switch driver
 *
 * Copyright (c) 2022 Microchip Technology Inc. and its subsidiaries.
 */

#ifndef __SPARX5_QOS_H__
#define __SPARX5_QOS_H__

#include <linux/netdevice.h>
#include <linux/types.h>
#include <net/pkt_sched.h>

#include "sparx5_ui_qos.h"

/* Number of priority queues */
#define SPX5_PRIOS 8

/* Number of Layers */
#define SPX5_HSCH_LAYER_CNT 3

/* Scheduling elements per layer */
#define SPX5_HSCH_L0_SE_CNT 5040
#define SPX5_HSCH_L1_SE_CNT 64
#define SPX5_HSCH_L2_SE_CNT 64

/* Calculate Layer 0 Scheduler Element when using normal hierarchy */
#define SPX5_HSCH_L0_GET_IDX(port, queue) ((64 * (port)) + (8 * (queue)))

/* Number of leak groups */
#define SPX5_HSCH_LEAK_GRP_CNT 4

/* Scheduler modes */
#define SPX5_SE_MODE_LINERATE 0
#define SPX5_SE_MODE_DATARATE 1

/* Rate and burst */
#define SPX5_SE_RATE_MAX 262143
#define SPX5_SE_BURST_MAX 127
#define SPX5_SE_RATE_MIN 1
#define SPX5_SE_BURST_MIN 1
#define SPX5_SE_BURST_UNIT 4096

/* Dwrr */
#define SPX5_DWRR_COST_MAX 63

struct sparx5;
struct sparx5_port;

struct sparx5_shaper {
	u32 mode;
	u32 rate;
	u32 burst;
};

struct sparx5_lg {
	u32 max_rate;
	u32 resolution;
	u32 leak_time;
	u32 max_ses;
};

struct sparx5_layer {
	struct sparx5_lg leak_groups[SPX5_HSCH_LEAK_GRP_CNT];
};

struct sparx5_dwrr {
	u32 count; /* Number of inputs running dwrr */
	u8 cost[SPX5_PRIOS];
};

int sparx5_qos_init(struct sparx5 *sparx5);

/* Multi-Queue Priority */
int sparx5_tc_mqprio_add(struct net_device *ndev, u8 num_tc);
int sparx5_tc_mqprio_del(struct net_device *ndev);

/* Token Bucket Filter */
struct tc_tbf_qopt_offload_replace_params;
int sparx5_tc_tbf_add(struct sparx5_port *port,
		      struct tc_tbf_qopt_offload_replace_params *params,
		      u32 layer, u32 idx);
int sparx5_tc_tbf_del(struct sparx5_port *port, u32 layer, u32 idx);

/* Enhanced Transmission Selection */
struct tc_ets_qopt_offload_replace_params;
int sparx5_tc_ets_add(struct sparx5_port *port,
		      struct tc_ets_qopt_offload_replace_params *params);

int sparx5_tc_ets_del(struct sparx5_port *port);

/*******************************************************************************
 * FP (Frame Preemption - 802.1Qbu/802.3br)
 ******************************************************************************/
struct sparx5_fp_port_conf {
	u8 admin_status;        /* IEEE802.1Qbu: framePreemptionStatusTable */
	bool enable_tx;         /* IEEE802.3br: aMACMergeEnableTx */
	bool verify_disable_tx; /* IEEE802.3br: aMACMergeVerifyDisableTx */
	u8 verify_time;         /* IEEE802.3br: aMACMergeVerifyTime [msec] */
	u8 add_frag_size;       /* IEEE802.3br: aMACMergeAddFragSize */
};

int sparx5_fp_set(struct sparx5_port *port,
		   struct sparx5_fp_port_conf *conf);

int sparx5_fp_get(struct sparx5_port *port,
		   struct sparx5_fp_port_conf *conf);

int sparx5_fp_status(struct sparx5_port *port,
		      struct sparx5_qos_fp_port_status *status);

/*******************************************************************************
 * QoS port notification
 ******************************************************************************/
int sparx5_qos_port_event(struct net_device *dev, unsigned long event);

/*******************************************************************************
 * QOS Port configuration
 ******************************************************************************/
int sparx5_qos_port_conf_get(const struct sparx5_port *const port,
			     struct sparx5_qos_port_conf *const conf);
int sparx5_qos_port_conf_set(struct sparx5_port *const port,
			     struct sparx5_qos_port_conf *const conf);

/*******************************************************************************
 * TAS (Time Aware Shaper - 802.1Qbv)
 ******************************************************************************/
int sparx5_tas_enable(struct sparx5_port *port,
		      struct tc_taprio_qopt_offload *qopt);

int sparx5_tas_disable(struct sparx5_port *port);

/* The current speed is needed in order to calculate the guard band */
void sparx5_tas_speed(struct sparx5_port *port, int speed);

/*******************************************************************************
 * QoS Initialization
 ******************************************************************************/
int sparx5_qos_init(struct sparx5 *sparx5);

#endif /* _SPARX5_QOS_H_ */
