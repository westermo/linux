/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (C) 2020 Microchip Technology Inc. */

/* This file must be copied to the qos_utils/src folder before building the QOS tools */

#ifndef _SPARX5_UI_QOS_H_
#define _SPARX5_UI_QOS_H_

#include "sparx5_main.h"

#define SPARX5_QOS_NETLINK "sparx5_qos_nl"

enum sparx5_qos_attr {
	SPARX5_QOS_ATTR_NONE,
	SPARX5_QOS_ATTR_DEV,
	SPARX5_QOS_ATTR_PORT_CFG,
	SPARX5_QOS_ATTR_DSCP,
	SPARX5_QOS_ATTR_DSCP_PRIO_DPL,

	/* This must be the last entry */
	SPARX5_QOS_ATTR_END,
};

#define SPARX5_QOS_ATTR_MAX (SPARX5_QOS_ATTR_END - 1)

enum sparx5_qos_genl {
	SPARX5_QOS_GENL_PORT_CFG_SET,
	SPARX5_QOS_GENL_PORT_CFG_GET,
	SPARX5_QOS_GENL_DSCP_PRIO_DPL_SET,
	SPARX5_QOS_GENL_DSCP_PRIO_DPL_GET,
};

/* QOS port configuration */
#define DEI_COUNT 2
#define DPL_COUNT 2
#define PCP_COUNT 8
#define PRIO_COUNT 8

struct sparx5_qos_i_mode {
	bool tag_map_enable;
	bool dscp_map_enable;
};

enum sparx5_qos_e_mode {
	SPARX5_E_MODE_CLASSIFIED = 0, /* Use ingress classified PCP,DEI as TAG PCP,DEI */
	SPARX5_E_MODE_DEFAULT    = 2, /* Use default PCP,DEI as TAG PCP,DEI */
	SPARX5_E_MODE_MAPPED     = 3  /* Use mapped (SKB)Priority and DPL as TAG PCP,DEI */
};

struct sparx5_pcp_dei_prio_dpl {
	u8 prio;
	u8 dpl;
};

struct sparx5_prio_dpl_pcp_dei {
	u8 pcp;
	u8 dei;
};

struct sparx5_qos_port_conf {
	u8 i_default_prio;
	u8 i_default_dpl;
	u8 i_default_pcp;
	u8 i_default_dei;
	struct sparx5_pcp_dei_prio_dpl i_pcp_dei_prio_dpl_map[PCP_COUNT][DEI_COUNT];
	struct sparx5_qos_i_mode i_mode;

	u8 e_default_pcp;
	u8 e_default_dei;
	struct sparx5_prio_dpl_pcp_dei e_prio_dpl_pcp_dei_map[PRIO_COUNT][DPL_COUNT];
	enum sparx5_qos_e_mode e_mode;

	bool dwrr_enable;
	u8 dwrr_count;
	u8 dwrr_queue_pct[PRIO_COUNT];

	u8 pfc_enable;
};

/* QOS DSCP configuration */
struct sparx5_qos_dscp_prio_dpl {
	/* Only trusted DSCP values are used for QOS class and DP level classification  */
	bool trust;
	u8 prio;
	u8 dpl;
};

enum sparx5_qos_fp_port_attr {
	SPARX5_QOS_FP_PORT_ATTR_NONE,
	SPARX5_QOS_FP_PORT_ATTR_CONF,
	SPARX5_QOS_FP_PORT_ATTR_STATUS,
	SPARX5_QOS_FP_PORT_ATTR_IDX,

	/* This must be the last entry */
	SPARX5_QOS_FP_PORT_ATTR_END,
};

#define SPARX5_QOS_FP_PORT_ATTR_MAX		(SPARX5_QOS_FP_PORT_ATTR_END - 1)

enum sparx5_qos_fp_port_genl {
	SPARX5_QOS_FP_PORT_GENL_CONF_SET,
	SPARX5_QOS_FP_PORT_GENL_CONF_GET,
	SPARX5_QOS_FP_PORT_GENL_STATUS_GET,
};

struct sparx5_qos_fp_port_conf {
	u8  admin_status;      // IEEE802.1Qbu: framePreemptionStatusTable
	u8  enable_tx;         // IEEE802.3br: aMACMergeEnableTx
	u8  verify_disable_tx; // IEEE802.3br: aMACMergeVerifyDisableTx
	u8  verify_time;       // IEEE802.3br: aMACMergeVerifyTime [msec]
	u8  add_frag_size;     // IEEE802.3br: aMACMergeAddFragSize
};

enum sparx5_mm_status_verify {
	SPARX5_MM_STATUS_VERIFY_INITIAL,   /**< INIT_VERIFICATION */
	SPARX5_MM_STATUS_VERIFY_IDLE,      /**< VERIFICATION_IDLE */
	SPARX5_MM_STATUS_VERIFY_SEND,      /**< SEND_VERIFY */
	SPARX5_MM_STATUS_VERIFY_WAIT,      /**< WAIT_FOR_RESPONSE */
	SPARX5_MM_STATUS_VERIFY_SUCCEEDED, /**< VERIFIED */
	SPARX5_MM_STATUS_VERIFY_FAILED,    /**< VERIFY_FAIL */
	SPARX5_MM_STATUS_VERIFY_DISABLED   /**< Verification process is disabled */
};

struct sparx5_qos_fp_port_status {
	u32 hold_advance;      // TBD: IEEE802.1Qbu: holdAdvance [nsec]
	u32 release_advance;   // TBD: IEEE802.1Qbu: releaseAdvance [nsec]
	u8 preemption_active; // IEEE802.1Qbu: preemptionActive, IEEE802.3br: aMACMergeStatusTx
	u8 hold_request;      // TBD: IEEE802.1Qbu: holdRequest
	enum sparx5_mm_status_verify status_verify;     // IEEE802.3br: aMACMergeStatusVerify
};

#endif /* _SPARX5_UI_QOS_H_ */
