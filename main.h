/*-
 *   BSD LICENSE
 * 
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MAIN_H_
#define _MAIN_H_

#ifdef RTE_EXEC_ENV_BAREMETAL
#define MAIN _main
#else
#define MAIN main
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <sys/time.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_string_fns.h>
#include <rte_rwlock.h>

#define Aok	1	
#define Nok	0
/*bit manipulation defines*/
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
#define BIT_0_TO_15 0x0000ffff
#define IPV6_ADDR_LEN                   4

static __m128i ipV4HashMask0;
static __m128i ipV4HashMask1;
static __m128i ipV4HashMask2;
static __m128i ipV4HashMask3;
static __m128i ipV4HashMask4;
static __m128i ipV4HashMask5;

static __m128i ipV6HashMask0;
static __m128i ipV6HashMask1;
static __m128i ipV6HashMask2;
static __m128i ipV6HashMask3;


struct rte_ring *pUserRing;
struct rte_ring *pControlRing;
struct rte_ring *pSessionIdV4ControlRing;
struct rte_ring *pSessionIdV6ControlRing;
struct rte_ring *pTransmitRing;
struct rte_ring *pFragRing;
struct rte_ring *pIdrUserRing;
struct rte_ring *pIdrControlRing;


//#include "linux_compat.h"

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1
//#define  RTE_LIBRTE_IXGBE_DEBUG_RX

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
//#define NB_MBUF 4096 
#define NB_MBUF 8192 

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;

struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf = {
	.rxmode = {
                .mq_mode        = ETH_MQ_RX_RSS,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
        .rx_adv_conf = {
        		.rss_conf = {
        		.rss_key = NULL,
        		.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV6,
        		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
	/*
	* As the example won't handle mult-segments and offload cases,
	* set the flag by default.
	*/
	.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};


/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

/* A tsc-based timer responsible for triggering statistics printout */
#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define RETRY_TIMEOUT 10000000000ULL /* around 5s at 2 Ghz */
//#define RETRY_TIMEOUT 1000000ULL /* around 5s at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
#define TIMER_RESOLUTION_CYCLES 20000000ULL /* around 10ms at 2 Ghz */

static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000; /* default period is 10 seconds */

#define USERPLANE_GTP_PORT		2152
#define CONTROLPLANE_GTP_PORT		2123
#define LTEPROBE_HASH_ENTRIES		10*1024*1024	//1  million hash entries
#define MAX_HASH_OBJECT_PER_REQUEST	100		//queue upto 100 entries in the sessionId ring before deleting buffers.
#define DELETE_GTPV1_SESSION_NO_TEARDOWN	0x0F
#define ADD_GTPV1_SESSION		0x01
#define DELETE_GTPV1_SESSION_TEARDOWN	0x02
#define ADD_GTPV2_SESSION               0x03
#define ADD_BEARER_GTPV2_SESSION        0x04
#define RELEASE_BEARER_GTPV2_SESSION	0x05


static struct timeval start_time;
static uint64_t start_cycles;
static uint64_t hz;

struct GtpV1Header {
        u_int8_t flags;
        u_int8_t msgtype;
        u_int16_t length;
        u_int32_t teid;
	}__attribute__((__packed__));;

struct GtpV2Header {
        u_int8_t flags;
        u_int8_t msgtype;
        u_int16_t length;
        u_int32_t teid;
	u_int32_t seqNumAndspare;
        }__attribute__((__packed__));;

struct GtpV2Header_noTeid {
        u_int8_t flags;
        u_int8_t msgtype;
        u_int16_t length;
	u_int32_t seqNumAndspare;
        }__attribute__((__packed__));;

struct sessionIdIpV4HashObject {
	uint32_t ipControl;
	uint32_t ipUser;
	uint32_t ipUserV6[IPV6_ADDR_LEN];
	uint32_t controlTeid;
	uint32_t dataTeid;
	uint32_t sessionId;
	int	 addDeleteFlag;//0x01 to add 0x00 to delete
	};

struct sessionIdIpV6HashObject {
        uint32_t  ipControl[IPV6_ADDR_LEN];
        uint32_t  ipUser[IPV6_ADDR_LEN];
	uint32_t ipUserV4;
        uint32_t controlTeid;
        uint32_t dataTeid;
        uint32_t sessionId;
        int      addDeleteFlag;//0x01 to add 0x00 to delete
        };


struct sessionIdIpV4HashTableContent {
	uint32_t ipControl;
	uint32_t ipUser;
	uint32_t controlTeid;
	uint32_t userTeid;
	uint32_t sessionId;
	uint8_t outputInterface;
	};

struct sessionIdIpV6HashTableContent {
        uint32_t  ipControl[IPV6_ADDR_LEN];
        uint32_t  ipUser[IPV6_ADDR_LEN];
        uint32_t controlTeid;
        uint32_t userTeid;
        uint32_t sessionId;
        uint8_t  outputInterface;
        };


struct gtpV2IpBearerList {
	uint8_t	 ipType;
        uint32_t  ipV6User[IPV6_ADDR_LEN];
	uint32_t ipV4User;
        uint32_t userTeid;
        struct   gtpV2IpBearerList *pNextBearer;
        };


struct sessionIdIpV4GtpV2HashTableContent {
        uint32_t ipControl;
        uint32_t controlTeid;
        uint32_t sessionId;
	struct   gtpV2IpBearerList *pBearerList;
        uint8_t  outputInterface;
        };

struct sessionIdIpV6GtpV2HashTableContent {
        uint32_t  ipControl[IPV6_ADDR_LEN];
	struct 	 gtpV2IpBearerList *pBearerList;
        uint32_t controlTeid;
        uint32_t sessionId;
        uint8_t  outputInterface;
        };


struct sessionIdIpV4UserHashTableContent {
        uint32_t ipUser;
        uint32_t userTeid;
        uint32_t sessionId;
        uint8_t  outputInterface;
        };

struct sessionIdIpV6UserHashTableContent {
        uint32_t  ipUserV6[IPV6_ADDR_LEN];
        uint32_t userTeid;
        uint32_t sessionId;
        uint8_t  outputInterface;
        };

struct fragIdHashObject {
	uint32_t	fragId;
	uint32_t	sessionId;
	uint32_t	ipV4DstAddr;
	uint32_t	ipV6DstAddr[IPV6_ADDR_LEN];
	};

struct fragIdHashTableContent {
	uint32_t	fragId;
	uint32_t	sessionId;
	};

struct idrHashObject {
	uint32_t	sessionId;
	uint32_t	msgType;
	uint32_t	origMsgType;
	uint32_t	ipV4SrcAddr;
	uint32_t	ipV4DstAddr;
	uint32_t	ipV6SrcAddr[IPV6_ADDR_LEN];
	uint32_t	ipV6DstAddr[IPV6_ADDR_LEN];
	uint32_t	secs;
	uint32_t	usecs;
        uint64_t 	imsi;
        uint8_t     	msisdn[128];
        uint64_t 	imeisv;
        uint32_t 	msip;
        uint32_t 	pTMSI;
        uint8_t 	apn[128];
        uint64_t 	uli;
        uint8_t 	rat;
        uint16_t 	gtpVersion;
        char     	direction[2];
        uint8_t  	causeCode;
	uint32_t	timeoutIndicator;
	};

union ipv4_2tuple_host {
	struct {
		uint32_t	fragId;
		uint32_t	ip_addr;
		};
	uint64_t  xmm;
	};

union ipv6_2tuple_host {
        struct {
                uint32_t        fragId;
                uint32_t        ip_addr[IPV6_ADDR_LEN];
		uint32_t	pad0;
                };
        uint64_t xmm[3];
        };


union ipv4_3tuple_host {
	struct {
		uint8_t		pad0;
		uint8_t		pad1;//proto
		uint16_t	pad2;
		uint32_t	ip_src;
		uint32_t	ip_dst;
		uint16_t	pad3;
		uint16_t	pad4;//dst port
		uint16_t	pad5;//dgram len
       	        uint16_t	pad6;//cksum
		uint32_t	flagsMsgTypeAndLen; 
               	uint32_t	teid;
		uint32_t	pad7;
		};

	__m128i xmm[2];
	};

union ipv6_3tuple_host {
        struct {
                uint16_t	pad0;
                uint8_t		pad1;//proto
                uint8_t		pad2;
                uint32_t	ip_src[IPV6_ADDR_LEN];
                uint32_t	ip_dst[IPV6_ADDR_LEN];
                uint16_t	pad3;
                uint16_t	pad4;//dst port
                uint16_t	pad5;//dgram len
                uint16_t	pad6;//cksum
                uint32_t	flagsMsgTypeAndLen;
                uint32_t	teid;
		uint32_t	pad9;
		uint32_t	pad10;
		uint32_t	pad11;
                };

        __m128i xmm[4];
        };

struct gtpStatistics
		{
		uint32_t	lcoreid;
		uint64_t	gtpV1IpV4CtrlPkt;
		uint64_t	gtpV1IpV6CtrlPkt;
		uint64_t	gtpV1V2IpV4UserPkt;
		uint64_t	gtpV1V2IpV6UserPkt;
		uint64_t	gtpV1V2IpV6UserPktFragment;
		uint64_t	gtpV1V2IpV4UserPktFragment;
		uint64_t	gtpV2IpV4CtrlPkt;
		uint64_t	gtpV2IpV6CtrlPkt;
		uint64_t	gtpV2IpV6UserPkt;
		uint64_t	gtpV1CtrlPktDiscards;
		uint64_t	gtpV1UserPktDiscards;
		uint64_t	gtpV2CtrlPktDiscards;
		uint64_t	gtpV1V2IpV6UserPktDiscards;
		uint64_t	gtpV1V2IpV4UserPktDiscards;
		uint64_t	gtpV1IpV4ControlPktDiscards;
		uint64_t	gtpV1IpV6ControlPktDiscards;
		uint64_t	gtpV2IpV4ControlPktDiscards;
		uint64_t	gtpV2IpV6ControlPktDiscards;
		uint64_t	gtpV1V2IpV6UserPktFragmentDiscards;
		uint64_t	gtpV1V2IpV4UserPktFragmentDiscards;
		};

struct ipV6FragmentHeader
		{
		uint32_t	nextHdrPlusOffset;
		uint32_t	fragmentId;
		};

struct gtpStatistics gtpStats;
struct controlIdr  {
        uint32_t startmSecs;
        uint32_t startuSecs;
        uint32_t endmSecs;
        uint32_t enduSecs;
        uint16_t ifType;
        uint32_t srcIp;
        uint32_t dstIp;
        uint16_t srcIpV6[IPV6_ADDR_LEN];
        uint16_t dstIpV6[IPV6_ADDR_LEN];
        uint16_t srcPort;
        uint16_t dstPort;
        uint64_t imsi;
	char	 msisdn[128];
        uint64_t imeisv;
        uint32_t msip;
        uint32_t pTMSI;
        uint8_t  apn[128];
        uint64_t uli;
        uint32_t rat;
        uint16_t gtpVersion;
        char     direction[2];
        uint8_t  causeCode;
        uint16_t timeoutIndicator;
        };


struct rte_hash * pSessionIdV4ControlHashTable;
struct rte_hash * pSessionIdV4GtpV2ControlHashTable;
struct rte_hash * pSessionIdV6GtpV2ControlHashTable;
struct rte_hash * pSessionIdV6ControlHashTable;
struct rte_hash * pSessionIdV4UserHashTable;
struct rte_hash * pSessionIdV6UserHashTable;
struct rte_hash * pIpV4FragIdHashTable;
struct rte_hash * pIpV6FragIdHashTable;
struct rte_hash * pCtrlIdrHashTable;

struct sessionIdIpV4HashObject *pIpV4ControlHashObjectArray[RTE_MAX_LCORE][MAX_HASH_OBJECT_PER_REQUEST];
//struct sessionIdIpV4GtpV2HashObject *pIpV4GtpV2ControlHashObjectArray[RTE_MAX_LCORE][MAX_HASH_OBJECT_PER_REQUEST];
struct sessionIdIpV6HashObject *pIpV6ControlHashObjectArray[RTE_MAX_LCORE][MAX_HASH_OBJECT_PER_REQUEST];
struct fragIdHashObject *pFragIdHashObjectArray[RTE_MAX_LCORE][MAX_HASH_OBJECT_PER_REQUEST];
struct idrHashObject *pIdrHashObjectArray[RTE_MAX_LCORE][MAX_HASH_OBJECT_PER_REQUEST];

#define XMM_NUM_IN_IPV6_3TUPLE  4
#define SESSION_HASH_ENTRIES    1024*512

static struct sessionIdIpV4HashTableContent sessionIdControlHashTableIPV4[SESSION_HASH_ENTRIES] __rte_cache_aligned;
static struct sessionIdIpV4GtpV2HashTableContent sessionIdControlHashTableIPV4GTPV2[SESSION_HASH_ENTRIES] __rte_cache_aligned;
static struct sessionIdIpV6HashTableContent sessionIdControlHashTableIPV6[SESSION_HASH_ENTRIES] __rte_cache_aligned;
static struct sessionIdIpV6GtpV2HashTableContent sessionIdControlHashTableIPV6GTPV2[SESSION_HASH_ENTRIES] __rte_cache_aligned;
static struct sessionIdIpV4UserHashTableContent sessionIdUserHashTableIPV4[SESSION_HASH_ENTRIES] __rte_cache_aligned;
static struct sessionIdIpV6UserHashTableContent sessionIdUserHashTableIPV6[SESSION_HASH_ENTRIES] __rte_cache_aligned;
static struct fragIdHashTableContent ipV4fragIdHashTable[SESSION_HASH_ENTRIES] __rte_cache_aligned;
static struct fragIdHashTableContent ipV6fragIdHashTable[SESSION_HASH_ENTRIES] __rte_cache_aligned;
static struct controlIdr ctrlIdrHashTable[SESSION_HASH_ENTRIES] __rte_cache_aligned;

//static struct sessionIdHashObject sessionIdHashTableIPV6[SESSION_HASH_ENTRIES] __rte_cache_aligned;

//Global sessionid per box, if multiple boxes, this id needs to have meaning spread across boxes.  is a TODO
static uint32_t globalSessionId = 0xFABFABFA;
static uint16_t	lastInterfaceUsed;  //keep track of tx interface for load balancing across tx

//Define minimal set of GTP message types for the load balancer to work

#define GTP_PDP_CONTEXT_REQUEST		0x00100000
#define GTP_PDP_CONTEXT_RESPONSE	0x00110000
#define GTP_PDP_UPDATE_REQUEST		0x00120000
#define GTP_PDP_UPDATE_RESPONSE		0x00130000
#define GTP_PDP_DELETE_CONTEXT_REQUEST	0x00140000
#define GTP_PDP_DELETE_CONTEXT_RESPONSE	0x00150000
#define GTP_NPDU_PRESENT		0X01000000
#define GTP_SEQ_NUMBER_PRESENT		0x02000000
#define GTP_EXT_HEADER_PRESENT		0x04000000
#define GTP_VERSION1_IN_FLAGS		0x20000000
#define GTP_VERSION2_IN_FLAGS		0x40000000
		
//GTP types
#define GTPV1_TYPE_CAUSE		0x01
#define GTPV2_TYPE_IMSI			0x01
#define GTPV2_TYPE_CAUSE		0x02
#define GTPV1_TYPE_IMSI			0x02
#define GTPV1_TYPE_RAI			0x03
#define GTPV1_TYPE_TLLI			0x04
#define GTPV1_TYPE_pTMSI		0x05
#define GTPV1_TYPE_SPARE1		0x06
#define GTPV1_TYPE_SPARE2		0x07
#define GTPV1_TYPE_REORDERING_REQD	0x08
#define GTPV1_TYPE_AUTH_TRIPLET		0x09
#define GTPV1_TYPE_SPARE3		0x0a
#define GTPV1_TYPE_MAP_CAUSE		0x0b
#define GTPV1_TYPE_pTMSI_SIGN		0x0c
#define GTPV1_TYPE_MS_VALIDATED		0x0d
#define GTPV1_TYPE_RECOVERY		0x0e
#define GTPV1_TYPE_SEL_MODE		0x0f
#define GTPV1_TYPE_DATA_TEID		0x10
#define GTPV1_TYPE_CTRL_TEID		0x11
#define GTPV1_TYPE_DATA_TEID_2		0x12
#define GTPV1_TYPE_TEARDOWN		0x13
#define GTPV1_TYPE_NSAPI		0x14
#define GTPV1_TYPE_NSAPI_CAUSE		0x15
#define GTPV1_TYPE_RAB_CONTEXT		0x16
#define GTPV1_TYPE_RADIO_PRIO_SMS	0x17
#define GTPV1_TYPE_RADIO_PRIO		0x18
#define GTPV1_TYPE_PKT_FLOW_ID		0x19
#define GTPV1_TYPE_CHARGING_CHK		0x1A
#define GTPV1_TYPE_TRACE_REF		0x1B
#define GTPV1_TYPE_TRACE_TYPE		0x1C
#define GTPV1_TYPE_MS_NOT_REACHABLE	0x1D
#define GTPV1_TYPE_CHARGING_ID		0x7F
#define GTPV1_TYPE_END_USER_ADD		0x80
#define GTPV1_TYPE_ACCESS_PT_NAME	0x83
#define GTPV1_TYPE_PROTOCOL_CFG_OPT	0x84
#define GTPV1_TYPE_SGSN_ADDR		0x85
#define GTPV1_TYPE_MSISDN		0x86
#define GTPV2_TYPE_MSISDN		0x4C
#define GTPV1_TYPE_CHARGING_ID		0x7F
#define GTPV1_TYPE_APN			0x83
#define GTPV2_TYPE_APN			0x47
#define GTPV1_TYPE_RADIO_PRIO_LCS	0x96
#define GTPV1_TYPE_RAT_TYPE		0x97
#define GTPV2_TYPE_RAT_TYPE		0x52
#define GTPV1_TYPE_IMEISV		0x9A

	//ip pkt type
#define	PACKET_TYPE_IPV4		0x00
#define	PACKET_TYPE_IPV6		0x01

//vlan tag	
#define PACKET_VLAN_TAG_PRESENT		0X00
#define PACKET_NO_VLAN_TAG_PRESENT	0X01

#define GTPV2_CREATE_SESSION_REQUEST	0x00200000
#define GTPV2_CREATE_BEARER_REQUEST	0x005f0000
#define GTPV2_MODIFY_BEARER_REQUEST	0x00220000
#define GTPV2_CREATE_SESSION_RESPONSE	0x00210000
#define GTPV2_CREATE_BEARER_RESPONSE	0x00600000
#define GTPV2_MODIFY_BEARER_RESPONSE	0x00230000
#define GTPV2_TEID_PRESENT		0x08000000
#define GTPV2_TYPE_FTEID		0x57
#define GTPV2_TYPE_BEARER_CONTEXT	0x5d
#define GTPV2_TYPE_REL_ACC_BEARER_REQ	0x00AA0000
#define GTPV2_TYPE_REL_ACC_BEARER_RSP	0x00AB0000
#define GTPV2_TYPE_DEL_SESSION_REQ	0x00240000
#define GTPV2_TYPE_DEL_SESSION_RSP	0x00250000
#define  ETHER_PACKET_LINUX_COOKED      0xFF

struct LteInfoAppend {
        uint32_t magic;
        uint32_t reserved0;
        uint32_t fragmentId;
        uint32_t gtpSessionId;
        uint32_t microSecondTimeStamp;
        uint32_t secondTimeStamp;
        uint32_t reserved1;
        uint32_t reserved2;
        };

union lteInfoRead {
	struct {
	        uint32_t magic;
	        uint32_t reserved0;
	        uint32_t fragmentId;
        	uint32_t gtpSessionId;
        	uint32_t microSecondTimeStamp;
        	uint32_t secondTimeStamp;
        	uint32_t reserved1;
        	uint32_t reserved2;
        	};

	__m128i xmm[2];
	};

union sessionId_2tuple_host {
	struct {
		uint32_t	sessionId;
		uint32_t	msgType;
		};
	uint16_t  xmm[5];
	};

int MAIN(int argc, char **argv);

#endif /* _MAIN_H_ */
