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
 *
 *
 *
 *   Who             What               		Date
 *  Sunil Shaligram  Ported from l2fwd example  	1st July 2014
 *  Sunil Shaligram  Added ipv6 support			23rd October 2014
 *  Sunil Shaligram  Added GTPv2 support		10th November 2014
 *  Sunil Shaligram  Added parking lot timer support	15th November 2014
 *  Sunil Shaligram  Fixed octet count bug		25th November 2014
 *  Sunil Shaligram  Added gtp Pkt statistics		16th January 2015
 *  Sunil Shaligram  Support for fragmented gtp pkts	20th January 2015
 *  Sunil Shaligram  Support for linux cooked frames	7th April 2015
 *  Sunil Shaligram  Packet xmit to dpi engine		8th June  2015
 *  Sunil Shaligram  Support for nDPI			27th June 2015
 *  Sunil Shaligram  tye req/rsp sessionId -bug	        24th July 2015
 *  Sunil Shaligram  IDR Creation and dump to csv	27th July 2015
 *  Sunil Shaligram  Fixed crash if no npdu/n_seq	30th Aug 2015
 *  Sunil Shaligram  Fixed bug handling dups gtpv2/ipv6	19th Sep 2015
 *  Sunil Shaligram  Fixed bug handling gtpv2/ipv4 	2nd Feb 2016	
 */


#include "main.h"

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;


#if 0
static inline uint8_t
get_ipv6_dst_port(void *ipv6_hdr,  uint8_t portid, lookup_struct_t * ipv6_l3fwd_lookup_struct)
{
        int ret = 0;
        union ipv6_5tuple_host key;

        ipv6_hdr = (uint8_t *)ipv6_hdr + offsetof(struct ipv6_hdr, payload_len);
        __m128i data0 = _mm_loadu_si128((__m128i*)(ipv6_hdr));
        __m128i data1 = _mm_loadu_si128((__m128i*)(((uint8_t*)ipv6_hdr)+sizeof(__m128i)));
        __m128i data2 = _mm_loadu_si128((__m128i*)(((uint8_t*)ipv6_hdr)+sizeof(__m128i)+sizeof(__m128i)));
        /* Get part of 5 tuple: src IP address lower 96 bits and protocol */
        key.xmm[0] = _mm_and_si128(data0, mask1);
        /* Get part of 5 tuple: dst IP address lower 96 bits and src IP address higher 32 bits */
        key.xmm[1] = data1;
        /* Get part of 5 tuple: dst port and src port and dst IP address higher 32 bits */
        key.xmm[2] = _mm_and_si128(data2, mask2);

        /* Find destination port */
        ret = rte_hash_lookup(ipv6_l3fwd_lookup_struct, (const void *)&key);
        return (uint8_t)((ret < 0)? portid : ipv6_l3fwd_out_if[ret]);
}
#endif
static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
        /* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
        /*
 *          * 1. The packet length reported by the Link Layer must be large
 *                   * enough to hold the minimum length legal IP datagram (20 bytes).
 *                            */
        if (link_len < sizeof(struct ipv4_hdr))
                return -1;

        /* 2. The IP checksum must be correct. */
        /* this is checked in H/W */

        /*
 *          * 3. The IP version number must be 4. If the version number is not 4
 *                   * then the packet may be another version of IP, such as IPng or
 *                            * ST-II.
 *                                     */
        if (((pkt->version_ihl) >> 4) != 4)
                return -3;
        /*
 *          * 4. The IP header length field must be large enough to hold the
 *                   * minimum length legal IP datagram (20 bytes = 5 words).
 *                            */
        if ((pkt->version_ihl & 0xf) < 5)
                return -4;

        /*
 *          * 5. The IP total length field must be large enough to hold the IP
 *                   * datagram header, whose length is specified in the IP header length
 *                            * field.
 *                                     */
        if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
                return -5;

        return 0;
}

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;
	struct rte_eth_stats ethStats;
	
	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;

		rte_eth_stats_get (portid,&ethStats);
		printf("\nethernet device Statistics for port %u ------------------------------"
                           "\nPackets received: %25"PRIu64
                           "\nBytes received: %28"PRIu64
                           "\nPackets ierrors: %26"PRIu64
                           "\nPackets rxnombuf: %27"PRIu64,
                           portid,
                      	   ethStats.ipackets, 
			   ethStats.ibytes,
                      	   ethStats.ierrors, 
                      	   ethStats.rx_nombuf); 

	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
	

        printf("\nGTP statistics ==============================="
                   "\nTotal ipv4 gtpv1 control pkts received : %18"PRIu64
                   "\nTotal ipv4 gtpv1 and gtpv2 user pkts received : %11"PRIu64
                   "\nTotal ipv4 gtpv1 and gtpv2 user pkt fragments received : %11"PRIu64
                   "\nTotal ipv6 gtpv1 and gtpv2 user pkt fragments received : %11"PRIu64
                   "\nTotal ipv4 gtpv2 control pkts received : %18"PRIu64
                   "\nTotal ipv6 gtpv1 control pkts received : %18"PRIu64
                   "\nTotal ipv6 gtpv1 and gtpv2 user pkts received : %11"PRIu64
                   "\nTotal ipv6 gtpv2 control pkts received : %18"PRIu64
                   "\nTotal ipv6 gtpv1 and gtpv2 user pkts discards: %12"PRIu64
                   "\nTotal ipv4 gtpv1 and gtpv2 user pkts fragment discards: %12"PRIu64
                   "\nTotal ipv6 gtpv1 and gtpv2 user pkts fragment discards: %12"PRIu64
                   "\nTotal ipv4 gtpv1 and gtpv2 user pkts discards: %12"PRIu64
                   "\nTotal ipv6 gtpv1 ctrl pkts discards: %22"PRIu64
                   "\nTotal ipv6 gtpv2 ctrl pkts discards: %22"PRIu64
                   "\nTotal ipv4 gtpv1 ctrl pkts discards: %22"PRIu64
                   "\nTotal ipv4 gtpv2 ctrl pkts discards: %22"PRIu64,
                   gtpStats.gtpV1IpV4CtrlPkt,
                   gtpStats.gtpV1V2IpV4UserPkt,
                   gtpStats.gtpV1V2IpV4UserPktFragment,
                   gtpStats.gtpV1V2IpV6UserPktFragment,
                   gtpStats.gtpV2IpV4CtrlPkt,
                   gtpStats.gtpV1IpV6CtrlPkt,
                   gtpStats.gtpV1V2IpV6UserPkt,
                   gtpStats.gtpV2IpV6CtrlPkt,
 		   gtpStats.gtpV1V2IpV6UserPktDiscards,
 		   gtpStats.gtpV1V2IpV4UserPktFragmentDiscards,
 		   gtpStats.gtpV1V2IpV6UserPktFragmentDiscards,
 		   gtpStats.gtpV1V2IpV4UserPktDiscards,
 		   gtpStats.gtpV1IpV6ControlPktDiscards,
 		   gtpStats.gtpV2IpV6ControlPktDiscards,
                   gtpStats.gtpV1IpV4ControlPktDiscards,
                   gtpStats.gtpV2IpV4ControlPktDiscards
                   );
        printf("\n====================================================\n");

	
}
/* Send the burst of packets on an output interface */
static int
lte_send_burst(struct lcore_queue_conf *qconf, unsigned n, uint8_t port)
{
	struct rte_mbuf **m_table;
	unsigned ret;
	unsigned queueid =0;

	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, (uint16_t) queueid, m_table, (uint16_t) n);
	port_statistics[port].tx += ret;
	printf ("tx burst ret=%d, n=%d\n",ret,n);
	if (unlikely(ret < n)) {
		port_statistics[port].dropped += (n - ret);
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue packets for TX and prepare them to be sent */
static int
lte_send_packet(struct rte_mbuf *m, uint8_t port)
{
	unsigned lcore_id, len;
	struct lcore_queue_conf *qconf;
	char name[32];
	int ret, socketid;
	struct rte_ring *pTransmitRing;
	int timepass = 0;
	int detectedProtocol;
  	const u_char *packet;
  	struct ndpi_ethhdr *ethernet;
  	struct ndpi_iphdr *iph;
	struct LteInfoAppend	*pLteAppend;
	lcore_id = rte_lcore_id();
	u_int16_t  type=0x0, ip_offset=0x0;
        printf ("sks:lte_send_packet rte_mbuf m (0x%x)\n", m);

	populateIDRTable (m,0);
	//detectedProtocol = dpiModule ( m );
        //idrCreate ( m );
	//...extract sessionid of packet.
	
        
	/*//comment out for now, no tx, since dpi is on the same box	
	port = 0x0;

	qconf = &lcore_queue_conf[lcore_id];
	len = qconf->tx_mbufs[port].len;
	qconf->tx_mbufs[port].m_table[len] = m;
	len++;

	printf ("sks: tx pkt on port-=0x%x MAX=%d len=%d...\n",port, MAX_PKT_BURST,len);
	//enough pkts to be sent 
	if (unlikely(len == MAX_PKT_BURST)) {
		lte_send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}

	lte_send_burst (qconf, len,port);

	qconf->tx_mbufs[port].len = len;
        
	socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
        rte_snprintf(name, sizeof(name), "Transmit_ring%u_io%u_sId4",
                    socketid,
                    lcore_id);

        pTransmitRing = rte_ring_lookup (name);
        if (pTransmitRing == NULL )
        	{
                printf ("Cannot find ring %s\n", name);
                return Aok;
                }
	printf ("sks: enqueuing on ring %s\n", name);
        ret = rte_ring_mp_enqueue (pTransmitRing, (void *) m);

        if (ret != 0 )
                {
                printf ("error in enqueuing to TransmitRing\n");
                return Aok;
		}
	
	while ( rte_ring_count (pTransmitRing)  != 0 ) {};
	while ( timepass++ < 10000);//...give dpi lcore time to clone the mbuf*/



	return Aok;
}


//...Calculate the timestamp

static inline void
calculateTimeStamp(struct timeval *ts) {
        uint64_t cycles;
        struct timeval cur_time;

        cycles = rte_get_timer_cycles() - start_cycles;
        cur_time.tv_sec = cycles / hz;
        cur_time.tv_usec = (cycles % hz) * 10e6 / hz;
        timeradd(&start_time, &cur_time, ts);
}

static void createIdrControlAndUserRings ( void )
        {
        char name[32];
        unsigned socket_io;
        uint32_t lcore = rte_lcore_id ();

        socket_io = rte_lcore_to_socket_id(lcore);


        printf("Creating ring to process control IDRs lcore=%u socket=%u...\n",
                lcore,
                socket_io);

        rte_snprintf(name, sizeof(name), "idrControlRing%u_io%u_sId4",
                                socket_io,
                                lcore);

        pIdrControlRing = rte_ring_create(
                               name,
                               2048,    //...2k ring size
                               socket_io,
                               RING_F_SC_DEQ);

        if (pIdrControlRing == NULL) {
                           rte_panic("Cannot create idr control ring to \n"
                                    );

                           }

        printf ("sks: successfully created idrControlRing %s\n", pIdrControlRing->name);

        printf("Creating ring to process user IDRs lcore=%u socket=%u...\n",
                lcore,
                socket_io);

        rte_snprintf(name, sizeof(name), "idrUserRing%u_io%u_sId4",
                                socket_io,
                                lcore);

        pIdrUserRing = rte_ring_create(
                               name,
                               2048,    //...2k ring size
                               socket_io,
                               RING_F_SC_DEQ);

        if (pIdrUserRing == NULL) {
                           rte_panic("Cannot create idr user ring to \n"
                                    );

                           }

        printf ("sks: successfully created idrUserRing %s\n", pIdrUserRing->name);


        }



static inline void createUserAndControlRings ( void )
	{
	char name[32];
	unsigned socket_io;
	uint32_t lcore = rte_lcore_id ();

        socket_io = rte_lcore_to_socket_id(lcore);

	//set the hastable masks for key searches
	
        ipV4HashMask0 = _mm_set_epi32(0, ALL_32_BITS, ALL_32_BITS, 0);
        ipV4HashMask1 = _mm_set_epi32(0,0,ALL_32_BITS, 0 );
        ipV4HashMask3 = _mm_set_epi32(0,0,0,0);
        ipV4HashMask2 = _mm_set_epi32(0,ALL_32_BITS,0,0);
        ipV4HashMask4 = _mm_set_epi32(ALL_32_BITS,ALL_32_BITS,0,0);
        ipV4HashMask5 = _mm_set_epi32(ALL_32_BITS,ALL_32_BITS,ALL_32_BITS,ALL_32_BITS);

        ipV6HashMask0 = _mm_set_epi32( ALL_32_BITS, ALL_32_BITS, ALL_32_BITS,0);
        ipV6HashMask1 = _mm_set_epi32( ALL_32_BITS, 0,0,ALL_32_BITS);
        ipV6HashMask2 = _mm_set_epi32( 0, 0, 0,ALL_32_BITS);
        ipV6HashMask3 = _mm_set_epi32( ALL_32_BITS,ALL_32_BITS,ALL_32_BITS,ALL_32_BITS);

        printf("Creating ring to connect I/O lcore %u (socket %u) with user lcore 2 and control lcore 3 ...\n",
                lcore,
                socket_io);

        rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",
                                socket_io,
                                lcore);

        pSessionIdV4ControlRing = rte_ring_create(
                               name,
                               2048,    //...2k ring size
                               socket_io,
                               RING_F_SC_DEQ);

        if (pSessionIdV4ControlRing == NULL) {
                           rte_panic("Cannot create ring to connect I/O core %u with user core 2\n",
                                    lcore);

                           }

        printf ("sks: successfully created sessionIdV4ControlRing %s\n", pSessionIdV4ControlRing->name);


        rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                                socket_io,
                                lcore);

        pSessionIdV6ControlRing = rte_ring_create(
                               name,
                               2048,    //...2k ring size
                               socket_io,
                               RING_F_SC_DEQ);

        if (pSessionIdV6ControlRing == NULL) {
                           rte_panic("Cannot create ring to connect I/O core %u with user core 2\n",
                                    lcore);

                           }

        printf ("sks: successfully created sessionIdV6ControlRing %s\n", pSessionIdV6ControlRing->name);



        rte_snprintf(name, sizeof(name), "Transmit_ring%u_io%u_sId4",
                                socket_io,
                                lcore);

        pTransmitRing = rte_ring_create(
                               name,
                               2048,    //...2k ring size
                               socket_io,
                               RING_F_SP_ENQ | RING_F_SC_DEQ);

        if (pTransmitRing == NULL) {
                           rte_panic("Cannot create ring to connect I/O core %u with user core 2\n",
                                    lcore);

                           }
        printf ("sks: successfully created transmitRing %s\n", pTransmitRing->name);

        rte_snprintf(name, sizeof(name), "FragId_ring%u_io%u_sId4",
                                socket_io,
                                lcore);

        pFragRing = rte_ring_create(
                               name,
                               2048,    //...2k ring size
                               socket_io,
                               RING_F_SC_DEQ);

        if (pFragRing == NULL) {
                           rte_panic("Cannot create ring to connect I/O core %u with user core 2\n",
                                    lcore);

                           }

        printf ("sks: successfully created fragRing %s\n", pFragRing->name);

	createIdrControlAndUserRings ( );
	}


static void pktRetryTimerCb (__attribute__((unused)) struct rte_timer *tim,
                            __attribute__((unused)) void *pkt);

/*segregate user and control plane traffic and send it to different core
Ideally this is done at the NIC*/
static inline int segregateControlAndUserTraffic(struct rte_mbuf *m, int repeatCount)
{
        struct		ether_hdr *eth_hdr=NULL;
        struct		ipv4_hdr *ipv4_hdr=NULL;
	struct		ipv6_hdr *ipv6_hdr=NULL;
        uint16_t	udpPortSrc;
        uint16_t	udpPortDst;
	struct		udp_hdr *pUdpHeader=NULL;
	struct		LteInfoAppend lteAppendage;
	struct		GtpV1Header *pGtpHeader=NULL;
	struct		timeval currentTime;
	//int    ringOpRetValue;
	struct		vlan_hdr * pVlanHdr;
        int		ret = 0;
        union		ipv4_3tuple_host key,newKey;
        union		ipv6_3tuple_host newKeyV6;
        union		ipv6_3tuple_host keyV6;
        union		ipv6_3tuple_host dupKeyV6;
        union		ipv6_2tuple_host fragKeyV6;
        union		ipv4_2tuple_host fragKeyV4;
        struct		sessionIdIpV4HashTableContent *pSessionIdObj;
        struct		sessionIdIpV4GtpV2HashTableContent *pSessionIdObjGtpV2;
        struct		sessionIdIpV6HashTableContent *pSessionIdObjV6 = NULL;
        struct		sessionIdIpV6GtpV2HashTableContent *pSessionIdObjGtpV2IPV6;
        struct		sessionIdIpV4UserHashTableContent *pSessionIdUserObj;
        struct		sessionIdIpV6UserHashTableContent *pSessionIdUserObjV6;
	__m128i		data0;
	__m128i		data1;
	__m128i		data2;
	__m128i		data3;
        uint32_t	controlTeid = 0;
        uint32_t	dataTeid = 0;
        int		octets = 1;
        int		lcore_id;
        int		socketid;
        int		objCount = 0;
        int		i;
        char		name[32];
        int		gtpType;
        struct		rte_ring * pControlRing;
        struct		rte_ring * pFragIdRing;
	uint32_t	sGsnIpV4UserAddr = 0; 
	uint32_t	sGsnIpV6UserAddr[IPV6_ADDR_LEN]={0,0,0,0}; 
	uint32_t	sGsnIpV4ControlAddr = 0; 
	uint32_t	sGsnIpV6ControlAddr[IPV6_ADDR_LEN]; 
	uint16_t	fwdLen;
	uint8_t *	pGtpParser=NULL;
	uint8_t		tearDownFlag = 0;
	uint8_t		ipPktType;
	uint8_t		etherPktType = 0x0;
	uint8_t		vlanTag;
	uint32_t	sessionIdOfUpdateRequest, createReqSessionId=0;
	void *		pGtpV2Header;
	int		ipType;
	int		fragPresent = 0;
	uint32_t	fragId = 0;
	struct		ipV6FragmentHeader *pFragHeader;

	bzero (&lteAppendage, sizeof(struct LteInfoAppend));

	char * pLteAppendage = rte_pktmbuf_append (m,sizeof(struct LteInfoAppend));

        eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	//first check vlan tags
	
	
        if (rte_cpu_to_be_16(eth_hdr->ether_type) == ETHER_TYPE_VLAN )
                {
		vlanTag = PACKET_VLAN_TAG_PRESENT;
                pVlanHdr = (struct vlan_hdr * )(rte_pktmbuf_mtod(m, unsigned char *) + sizeof (struct ether_hdr));
                if ( rte_cpu_to_be_16(pVlanHdr->eth_proto) == ETHER_TYPE_IPv4)
                        {
			ipPktType = PACKET_TYPE_IPV4;
                        ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) + sizeof (struct vlan_hdr));
			//...first 3 bits of the offset are flags, so mask it off
			if ((rte_cpu_to_be_16(ipv4_hdr->fragment_offset)& 0x1FFF) !=0)
				{
				printf ("sks: ipv4 vlan frag=true\n");
				fragPresent = 1;
				fragId = (uint32_t)(rte_cpu_to_be_32(ipv4_hdr->packet_id));
				} 
			}
                if ( rte_cpu_to_be_16(pVlanHdr->eth_proto) == ETHER_TYPE_IPv6)
                        {
			ipPktType = PACKET_TYPE_IPV6;
                        ipv6_hdr = (struct ipv6_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) + sizeof (struct vlan_hdr));
			if (ipv6_hdr->proto == IPPROTO_FRAGMENT )
				{
				fragPresent = 1;
				pFragHeader = (struct ipV6FragmentHeader *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) + sizeof (struct vlan_hdr) + sizeof (struct ipv6_hdr));
				printf ("sks: ipv6 vlan frag=true\n");
				fragId	= rte_cpu_to_be_32(pFragHeader->fragmentId);
				}
                        }
		}
	else
		{
		//	...No VLAN tag to worry about.
		vlanTag = PACKET_NO_VLAN_TAG_PRESENT;
                if ( rte_cpu_to_be_16(eth_hdr->ether_type) == 0x0 )
                        {
                        //...cooked up linux frame, assume ipv4 and put appropriate ipv4_hdr pointer.
                        //printf ("sks: cooked pkt\n");
                        ipPktType = PACKET_TYPE_IPV4;
                        etherPktType = ETHER_PACKET_LINUX_COOKED;
                        ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) + sizeof( uint16_t) );
                        }

                if  ( rte_cpu_to_be_16(eth_hdr->ether_type) == ETHER_TYPE_IPv4)
                        {
			ipPktType = PACKET_TYPE_IPV4;
                        ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) );
			//...first 3 bits of the offset are flags, so mask it off
			if ((rte_cpu_to_be_16(ipv4_hdr->fragment_offset)& 0x1FFF) !=0)
                                {
                                fragPresent = 1;
				fragId = (uint32_t)rte_cpu_to_be_32(ipv4_hdr->packet_id);
				printf ("sks: ipv4 frag=true\n");
                                }
			}
                if  ( rte_cpu_to_be_16(eth_hdr->ether_type) == ETHER_TYPE_IPv6)
                        {
			ipPktType = PACKET_TYPE_IPV6;
                        ipv6_hdr = (struct ipv6_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) );
                        if (ipv6_hdr->proto == IPPROTO_FRAGMENT )
                                {
                                fragPresent = 1;
                                pFragHeader = (struct ipV6FragmentHeader *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) + sizeof (struct ipv6_hdr));
				fragId	= rte_cpu_to_be_32(pFragHeader->fragmentId);
				printf ("sks: ipv6 frag=true\n");
                                }
			}
		}

	if (ipPktType == PACKET_TYPE_IPV6)
		{		
                pUdpHeader = (struct udp_hdr *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr));

		if (fragPresent == 1) 
			{
			pUdpHeader = (struct udp_hdr *)((unsigned char *)pUdpHeader + sizeof(struct ipV6FragmentHeader));
			}

                udpPortSrc = (uint16_t)(rte_cpu_to_be_16(pUdpHeader->src_port));
                udpPortDst = (uint16_t)(rte_cpu_to_be_16(pUdpHeader->dst_port));
                calculateTimeStamp (&currentTime);
		lteAppendage.magic		   = 0xBACCFEED;
                lteAppendage.secondTimeStamp       = currentTime.tv_sec;
                lteAppendage.microSecondTimeStamp  = currentTime.tv_usec;

		printf ("SKS: ipv6 fragPresent = 0x%x udpPortSrc=0x%x, udpPortDst=0x%x\n", fragPresent, udpPortSrc, udpPortDst);

                if (fragPresent == 1)
                	{
                        bzero (&fragKeyV6, sizeof (fragKeyV6));
                        fragKeyV6.ip_addr[0]=(uint32_t)(rte_cpu_to_be_32(ipv6_hdr->dst_addr[0]));
                        fragKeyV6.ip_addr[1]=(uint32_t)(rte_cpu_to_be_32(ipv6_hdr->dst_addr[4]));
                        fragKeyV6.ip_addr[2]=(uint32_t)(rte_cpu_to_be_32(ipv6_hdr->dst_addr[8]));
                        fragKeyV6.ip_addr[3]=(uint32_t)(rte_cpu_to_be_32(ipv6_hdr->dst_addr[12]));
                        fragKeyV6.fragId = fragId;

                        ret = rte_hash_lookup (pIpV6FragIdHashTable, (const void *)&fragKeyV6);
                        if ( ret >  0 )
                        	{
                                printf ("SKS: found matching frag\n");
                                //      ... found, get sessionid and transmit out and exit
                                lteAppendage.gtpSessionId = ipV6fragIdHashTable[ret].sessionId;
                                rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                //TODO - All done, transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
				//Assuming that on gtp user pkts have fragments not control pkts, hence incrementing only the user pkt stats.
                                gtpStats.gtpV1V2IpV6UserPktFragment++;
				lte_send_packet (m, 2); //hardcode port2 for now
                                //...return here itself since this is not a fully formed gtp pkt, hence
                                //...will not be in the user hash tbl.
                                return Aok;
                                }
                        else
                                {
                                //...fragment might have arrived before the first fragment
                                //...kick off timer and wait

                                if (repeatCount == 0 )
                                	{
                			if ((udpPortSrc != USERPLANE_GTP_PORT)&&(udpPortDst != USERPLANE_GTP_PORT))
						{
	                                         printf ("sks:init timer case 2...\n");
       		                                 struct rte_timer * pUserPlaneTimer;
               		                         pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                       		                 int resetReturn = 0;
                               		         rte_timer_init (pUserPlaneTimer);
                                       		 //printf ("sks: timer reset...\n");
                                        	 lcore_id = rte_lcore_id ();
                                        	 resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                        	 //printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                        	 return Nok;
						}
                                        }
                               if (repeatCount == 1)
                                        {
                                        //...orphan pkt, update stats and discard.
                                        gtpStats.gtpV1V2IpV6UserPktFragmentDiscards++;
                                        return Aok;
                                        }
                               }
                       }


                if ((udpPortSrc == USERPLANE_GTP_PORT)||(udpPortDst == USERPLANE_GTP_PORT))
                        {
			//need only data1 and data2
			//ipdst is the last 96 bits of data1 and the first 32 bits of data2.
                        //data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv6_hdr,payload_len)));
                        if (vlanTag == PACKET_NO_VLAN_TAG_PRESENT)
				{
                        	data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv6_hdr,payload_len)+sizeof(__m128i)));
                        	data2 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv6_hdr,payload_len)+ 2*sizeof(__m128i)));
                        	data3 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv6_hdr,payload_len)+ 3*sizeof(__m128i)));
				}
			else
				{
                        	data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv6_hdr,payload_len)+sizeof(__m128i)));
                        	data2 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv6_hdr,payload_len)+ 2*sizeof(__m128i)));
                        	data3 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv6_hdr,payload_len)+ 3*sizeof(__m128i)));
				}
			bzero (&keyV6, sizeof(keyV6));
                        keyV6.xmm[0] = _mm_and_si128(data0, ipV4HashMask2); //will be garbage for now
                        keyV6.xmm[1] = _mm_and_si128(data1, ipV6HashMask0);
                        keyV6.xmm[2] = _mm_and_si128(data2, ipV6HashMask1);
                        keyV6.xmm[3] = _mm_and_si128(data3, ipV6HashMask2);
                        bzero (&newKeyV6,sizeof(newKeyV6));
                        newKeyV6.ip_dst[0] = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                        newKeyV6.ip_dst[1] = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                        newKeyV6.ip_dst[2] = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                        newKeyV6.ip_dst[3] = rte_cpu_to_be_32(keyV6.ip_dst[3]);
                        newKeyV6.teid	   = rte_cpu_to_be_32(keyV6.teid);
			
			ret = 0;

                        if (pSessionIdV6UserHashTable)
                                {
				printf ("sks:looking up v6 user hash table\n");
                                ret = rte_hash_lookup(pSessionIdV6UserHashTable, (const void *)&newKeyV6);
                                }
			else
				{
				printf ("sks: USER HASHTABLE NOT INITIALIZED\n");
				return Aok;
				}
                        if (ret > 0)
                                {
				if (fragPresent == 1 )
					{
                                        lcore_id = rte_lcore_id();
                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                        rte_snprintf(name, sizeof(name), "FragId_ring%u_io%u_sId4",
                                                             socketid,
                                                             lcore_id);

                                        pFragIdRing = rte_ring_lookup (name);
                                        if (pFragIdRing == NULL )
                                        	{
                                                printf ("Cannot find ring %s\n", name);
                                                return Aok;
                                                }
                                        if (rte_ring_empty (pFragIdRing))
                                        	{
                                                printf ("setting all ring entries to NULL\n");
                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                	{
                                                        //...Can optimize more here TODO
                                                        if(pFragIdHashObjectArray[lcore_id][i])
                                                        	{
                                                                rte_free (pFragIdHashObjectArray[lcore_id][i]);
                                                                pFragIdHashObjectArray[lcore_id][i] = NULL;
                                                                }
                                                        }
                                                }

                                        while (pFragIdHashObjectArray[lcore_id][objCount] != NULL )
                                                objCount++;

                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                {
                                                printf ("FATAL: dropping pdp request msg\n");
                                                return Aok;
                                                }

                                        pFragIdHashObjectArray[lcore_id][objCount] = (struct fragIdHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct sessionIdIpV6HashObject),0);

                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV6DstAddr[0]           = newKeyV6.ip_dst[0];
                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV6DstAddr[1]           = newKeyV6.ip_dst[1];
                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV6DstAddr[2]           = newKeyV6.ip_dst[2];
                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV6DstAddr[3]           = newKeyV6.ip_dst[3];
                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV4DstAddr	             = 0x0;
                                        pFragIdHashObjectArray[lcore_id][objCount]->sessionId	             = sessionIdUserHashTableIPV6[ret].sessionId;
                                        pFragIdHashObjectArray[lcore_id][objCount]->fragId	             = fragId;

                                        ret = rte_ring_mp_enqueue (pFragIdRing, (void *) pFragIdHashObjectArray[lcore_id][objCount]);

                                        if (ret != 0 )
                                        	{
                                                printf ("error in enqueuing to FragIdRing\n");
                                                return Aok;
                                                }
                                        gtpStats.gtpV1V2IpV6UserPktFragment++;
					}
		
		                pSessionIdUserObjV6 = &sessionIdUserHashTableIPV6[ret];
                                lteAppendage.gtpSessionId = pSessionIdUserObjV6->sessionId;
                                //printf ("sks: user plane pkt, hash lkup sucessful, ready to send out pkt...\n");
                                rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                //TODO - All done, transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                gtpStats.gtpV1V2IpV6UserPkt++;
				lte_send_packet (m, 2);
				return Aok;
                                }
                        if (ret < 0)
                                {
                                printf ("sks UP lkup key not found: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x:0x%x:0x%x:0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x\n",
                               newKeyV6.pad0,newKeyV6.pad1,newKeyV6.pad2,newKeyV6.ip_src[0],newKeyV6.ip_dst[0],newKeyV6.ip_dst[1],newKeyV6.ip_dst[2],newKeyV6.ip_dst[3],newKeyV6.pad3,newKeyV6.pad4,newKeyV6.pad5,newKeyV6.pad6,newKeyV6.flagsMsgTypeAndLen,newKeyV6.teid);

                                ////TODO - session not yet initiated but we have rx user data, kickoff timer and wait.
                                printf ("sks: entry does not exist for user plane pkt, returning...repeatCount=%d\n",repeatCount);
				if (repeatCount == 0 )
					{
                                        //printf ("sks:init timer case 2...\n");
                                        struct rte_timer * pUserPlaneTimer;
                                        pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                        int resetReturn = 0;
                                        rte_timer_init (pUserPlaneTimer);
                                        //printf ("sks: timer reset...\n");
                                        lcore_id = rte_lcore_id ();
                                        resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                        //printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                        return Nok;
					}
				if (repeatCount == 1)
					{
                                        //...orphan pkt, update stats and discard.
					gtpStats.gtpV1V2IpV6UserPktDiscards++;
					return Aok;
					}
                                }
			return Aok;
                        }

                 if ((udpPortSrc == CONTROLPLANE_GTP_PORT)||(udpPortDst == CONTROLPLANE_GTP_PORT))
                         {
                         //data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv6_hdr,payload_len)));
                         if (vlanTag == PACKET_NO_VLAN_TAG_PRESENT)
				{
                         	data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv6_hdr,payload_len)+sizeof(__m128i)));
                         	data2 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv6_hdr,payload_len)+ 2*sizeof(__m128i)));
                         	data3 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv6_hdr,payload_len)+ 3*sizeof(__m128i)));
				}
			else
				{
                                data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) + sizeof (struct vlan_hdr) + offsetof(struct ipv6_hdr,payload_len)+sizeof(__m128i)));
                                data2 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) + sizeof (struct vlan_hdr) + offsetof(struct ipv6_hdr,payload_len)+ 2*sizeof(__m128i)));
                                data3 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) + sizeof (struct vlan_hdr) + offsetof(struct ipv6_hdr,payload_len)+ 3*sizeof(__m128i)));
				}
                         keyV6.xmm[0] = _mm_and_si128(data0, ipV4HashMask2); //will be garbage for now
                         keyV6.xmm[1] = _mm_and_si128(data1, ipV6HashMask0);
                         keyV6.xmm[2] = _mm_and_si128(data2, ipV6HashMask1);
                         keyV6.xmm[3] = _mm_and_si128(data3, ipV6HashMask2);
                         bzero (&newKeyV6,sizeof(newKeyV6));
                         newKeyV6.ip_dst[0] = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                         newKeyV6.ip_dst[1] = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                         newKeyV6.ip_dst[2] = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                         newKeyV6.ip_dst[3] = rte_cpu_to_be_32(keyV6.ip_dst[3]);
 
			 printf ("sks: ipv6 gtp flags=0x%x\n", rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen));
                                if (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTP_VERSION1_IN_FLAGS)
                                        {
                                        //GTPv1 processing
                                        pGtpHeader = (struct GtpV1Header *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
                                        printf ("sks:gtpv1, switch = 0x%x\n", (int)((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & ALL_32_BITS )));
                                        switch ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 ))
                                                {
                                                case GTP_PDP_DELETE_CONTEXT_REQUEST://intentional fall-thru
                                                pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpHeader  + sizeof(struct GtpV1Header) );
                                                if ( *((uint8_t *)pGtpParser) == GTPV1_TYPE_TEARDOWN)
                                                        {
                                                        (uint8_t *)pGtpParser++;
                                                        tearDownFlag = *((uint8_t *)pGtpParser);
                                                        }
                                                case GTP_PDP_DELETE_CONTEXT_RESPONSE:
                                                newKeyV6.teid   = rte_cpu_to_be_32(keyV6.teid);

                                                printf ("sks: got delete request/response msg dst=0x%x:0x%x:0x%x:0x%x, teid = 0x%x\n",newKeyV6.ip_dst[0],newKeyV6.ip_dst[1],newKeyV6.ip_dst[2],newKeyV6.ip_dst[3], newKey.teid);
                                                ret = rte_hash_lookup(pSessionIdV6ControlHashTable, (const void *)&newKeyV6);
                                                if (ret < 0 )
                                                        {
                                        		if (repeatCount == 0 )
                                                		{
                                                		printf ("sks:init timer case 3...\n");
                                                		struct rte_timer * pUserPlaneTimer;
                                                		pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                                		int resetReturn = 0;
                                                		rte_timer_init (pUserPlaneTimer);
                                                		printf ("sks: timer reset...\n");
                                                		lcore_id = rte_lcore_id ();
                                                		resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                                		printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                                		return Nok;
                                                		}
                                        		if (repeatCount == 1)
                                                		{
                                                		//...orphan pkt, update stats and discard.
                                                                gtpStats.gtpV1IpV6ControlPktDiscards++;
								//...TODO: transmit anyway.
								lte_send_packet (m, 2);
                                                                return Aok;
                                                                }
                                                        }
                                                else
                                                        {
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                                                                          socketid,
                                                                          lcore_id);

                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }
                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV6ControlHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIpV6ControlHashObjectArray[lcore_id][i]);
                                                                                pIpV6ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIpV6ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }

                                                        pSessionIdObjV6 = &sessionIdControlHashTableIPV6[ret];


                                                        pIpV6ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV6HashObject *) rte_malloc ("hash object  v6 array",sizeof(struct sessionIdIpV6HashObject),0);
                                                        //...downlink ip and control plane teid.

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[0]      	= pSessionIdObjV6->ipControl[0];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[1]      	= pSessionIdObjV6->ipControl[1];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[2]      	= pSessionIdObjV6->ipControl[2];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[3]      	= pSessionIdObjV6->ipControl[3];

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0]         	= pSessionIdObjV6->ipUser[0];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1]         	= pSessionIdObjV6->ipUser[1];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2]         	= pSessionIdObjV6->ipUser[2];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3]         	= pSessionIdObjV6->ipUser[3];

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->controlTeid		= pSessionIdObjV6->controlTeid;
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->dataTeid       	= pSessionIdObjV6->userTeid;
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  	= DELETE_GTPV1_SESSION_NO_TEARDOWN;
                                                        if ( tearDownFlag == 0xff )
                                                                {
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = DELETE_GTPV1_SESSION_TEARDOWN;
                                                                }
                                                        printf ("sks: enqueueing delete msg objCount=%d\n", objCount);

                                                        ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV6ControlHashObjectArray[lcore_id][objCount]);

							printf ("sks: ring %s, ring count=%u\n", pControlRing->name, rte_ring_count (pControlRing));
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to sessionIdRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pControlRing));
                                                        lteAppendage.gtpSessionId = sessionIdControlHashTableIPV6[ret].sessionId;
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        printf ("sks: all done for delete request/resp msg\n");
                                                        //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        gtpStats.gtpV1IpV6CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                        }
                                                break;
                                                case GTP_PDP_UPDATE_REQUEST://intentional fall-thru
                                                case GTP_PDP_UPDATE_RESPONSE://intentional fall-thru
                                                bzero (&newKey,sizeof(newKey));
                                                newKeyV6.ip_dst[0] = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                                                newKeyV6.ip_dst[1] = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                                                newKeyV6.ip_dst[2] = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                                                newKeyV6.ip_dst[3] = rte_cpu_to_be_32(keyV6.ip_dst[3]);
                                                newKeyV6.teid   = rte_cpu_to_be_32(keyV6.teid);

                                                printf ("sks: got update request/response msg dst=0x%x:0x%x:0x%x:0x%x, teid = 0x%x\n",newKeyV6.ip_dst[0],newKeyV6.ip_dst[1],
							newKeyV6.ip_dst[2], newKeyV6.ip_dst[3], newKeyV6.teid);
                                                ret = rte_hash_lookup(pSessionIdV6ControlHashTable, (const void *)&newKeyV6);
                                                if (ret < 0 )
                                                        {
                                                        printf ("orphan update context request/response\n");
                                                        //TODO: start a timer
                                                        //then tx it out if still not found
                                			if (repeatCount == 0 )
                                        			{
                                        			printf ("sks:init timer case 3...\n");
                                        			struct rte_timer * pUserPlaneTimer;
                                        			pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                        			int resetReturn = 0;
                                        			rte_timer_init (pUserPlaneTimer);
                                        			printf ("sks: timer reset...\n");
                                        			lcore_id = rte_lcore_id ();
                                        			resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                        			printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                        			return Nok;
                                                                }
                                                        if (repeatCount == 1)
                                                                {
                                                                //...orphan pkt, update stats and discard.
                                                                gtpStats.gtpV1IpV6ControlPktDiscards++;
                                                                return Aok;
								}
                                                        }
                                                else
                                                        {
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                                                                          socketid,
                                                                          lcore_id);

                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                //TODO:tx it out nevertheless
                                                                lte_send_packet (m, 2);
                                                                return Aok;
                                                                }
                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV6ControlHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIpV6ControlHashObjectArray[lcore_id][i]);
                                                                                pIpV6ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIpV6ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;
                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                //TODO: tx it out
                                                                lte_send_packet (m, 2);
                                                                return Aok;
                                                                }

                                                        pSessionIdObjV6 = &sessionIdControlHashTableIPV6[ret];


                                                        pIpV6ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV6HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV6HashObject),0);
                                                        //...downlink ip and control plane teid.

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[0]      = pSessionIdObjV6->ipControl[0];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[1]      = pSessionIdObjV6->ipControl[1];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[2]      = pSessionIdObjV6->ipControl[2];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[3]      = pSessionIdObjV6->ipControl[3];

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0]         = pSessionIdObjV6->ipUser[0];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1]         = pSessionIdObjV6->ipUser[1];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2]         = pSessionIdObjV6->ipUser[2];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3]         = pSessionIdObjV6->ipUser[3];

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->controlTeid    = pSessionIdObjV6->controlTeid;
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->dataTeid       = pSessionIdObjV6->userTeid;
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = DELETE_GTPV1_SESSION_TEARDOWN;
                                                        //remember the sessionid so that the updated hash entry has the old session id.
                                                        sessionIdOfUpdateRequest                                        = pSessionIdObjV6->sessionId;

                                                        printf ("sks: enqueueing update msg objCount=%d\n", objCount);

                                                        ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV6ControlHashObjectArray[lcore_id][objCount]);
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to sessionIdRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pControlRing));
                                                        lteAppendage.gtpSessionId = sessionIdControlHashTableIPV6[ret].sessionId;
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        lte_send_packet (m, 2);
                                                        gtpStats.gtpV1IpV6CtrlPkt++;
                                                        }

                                                case GTP_PDP_CONTEXT_REQUEST: //intentional fall-thru
                                                case GTP_PDP_CONTEXT_RESPONSE:
                                                printf ("sks: got context create request/response msg\n");
                                                //...Create a new hash entry
                                                pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpHeader  + sizeof(struct GtpV1Header));
                                                if ( rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTP_SEQ_NUMBER_PRESENT )
                                                	//...advance pGtpHeader pointer towards the control and data teids
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpParser  +  sizeof (uint16_t));

                                                //printf ("sks:ctrl plane pkt - recognized pdp request 0x%x \n", (int)(*pGtpParser) );
                                                //
                                                if ( rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTP_NPDU_PRESENT )
                                                        pGtpParser      = (unsigned char *) ((unsigned char *)pGtpParser + sizeof (uint8_t));

                                                /*printf ("*****hex dump****\n");
                                                while (octets < 32)
                                                        {
                                                        printf ("%02x ",(int)(*pGtpParser));
                                                        octets++;
                                                        pGtpParser++;
                                                        }*/
                                                octets = 1;
						sGsnIpV6ControlAddr[0]=sGsnIpV6ControlAddr[1]=sGsnIpV6ControlAddr[2]=sGsnIpV6ControlAddr[3]=0;
                                                //printf ("sks:gtp header len=0x%x\n", rte_cpu_to_be_16((uint16_t)pGtpHeader->length));
                                               while ((octets < rte_cpu_to_be_16(pGtpHeader->length))&& (sGsnIpV6ControlAddr[0] == 0) &&(sGsnIpV6ControlAddr[1]==0) && (sGsnIpV6ControlAddr[2]==0) && (sGsnIpV6ControlAddr[3]==0))
                                                        {
                                                        gtpType = (int)(*pGtpParser);
                                                        //increment parser pointer so that we can pick up the value of the type
                                                         pGtpParser += sizeof (uint8_t);
                                                         //      printf ("sks:gtpType=0x%x\n", gtpType);
                                                         switch (gtpType)
                                                                {
                                                                case GTPV1_TYPE_IMSI:
                                                                pGtpParser += 8*sizeof(uint8_t);
								octets +=8;
                                                                break;
                                                                case GTPV1_TYPE_RAI:
                                                                pGtpParser += 6*sizeof(uint8_t);
								octets +=6;
                                                                break;
                                                                case GTPV1_TYPE_RECOVERY://intentional fall thru
                                                                case GTPV1_TYPE_CAUSE:
                                                                case GTPV1_TYPE_REORDERING_REQD:
                                                                case GTPV1_TYPE_NSAPI:
                                                                case GTPV1_TYPE_SEL_MODE:
                                                                pGtpParser += sizeof(uint8_t);
								octets += 1;
                                                                break;
                                                                case GTPV1_TYPE_DATA_TEID:
                                                                dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
								octets += 4;
                                                                break;
                                                                case GTPV1_TYPE_CTRL_TEID:
                                                                controlTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
								octets += 4;
                                                                break;
                                                                case GTPV1_TYPE_CHARGING_ID:
                                                                pGtpParser += 4*sizeof(uint8_t);
								octets +=4;
                                                                break;
                                                                case GTPV1_TYPE_CHARGING_CHK: //intentional fall thru
                                                                case GTPV1_TYPE_TRACE_REF:
                                                                case GTPV1_TYPE_TRACE_TYPE:
                                                                pGtpParser += 2*sizeof(uint8_t);
								octets +=2;
                                                                break;
                                                                case GTPV1_TYPE_END_USER_ADD:
                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                pGtpParser += 2*sizeof(uint8_t);
                                                                pGtpParser += fwdLen*sizeof(uint8_t);
                                                                octets +=(2+fwdLen);
                                                                break;
                                                                case GTPV1_TYPE_ACCESS_PT_NAME: //intentional fall thru
                                                                case GTPV1_TYPE_PROTOCOL_CFG_OPT:
                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                pGtpParser += 2*sizeof(uint8_t);
                                                                pGtpParser += fwdLen*sizeof(uint8_t);
                                                                octets +=(2+fwdLen);
                                                                break;
                                                                case GTPV1_TYPE_SGSN_ADDR:
                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                if (fwdLen == 16 )
                                                                        {
                                                                        pGtpParser += 2*sizeof(uint8_t);
                                                                        sGsnIpV6ControlAddr[0] = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                        pGtpParser += 4*sizeof(uint8_t);
                                                                        sGsnIpV6ControlAddr[1] = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                        pGtpParser += 4*sizeof(uint8_t);
                                                                        sGsnIpV6ControlAddr[2] = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                        pGtpParser += 4*sizeof(uint8_t);
                                                                        sGsnIpV6ControlAddr[3] = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                        pGtpParser += 4*sizeof(uint8_t);
									octets += (2+fwdLen);
                                                                        gtpType = (int)(*pGtpParser);
                                                                        if (gtpType==GTPV1_TYPE_SGSN_ADDR)
                                                                                {
                                                                                pGtpParser += sizeof (uint8_t);
										octets++;
                                                                                fwdLen = rte_cpu_to_be_16(*((uint32_t *)pGtpParser));
                                                                                if (fwdLen == 16)
                                                                                        {
                                                                                        pGtpParser += 2*sizeof(uint8_t);
                                                                                        sGsnIpV6UserAddr[0] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                        pGtpParser += 4*sizeof(uint8_t);
                                                                                        sGsnIpV6UserAddr[1] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                        pGtpParser += 4*sizeof(uint8_t);
                                                                                        sGsnIpV6UserAddr[2] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                        pGtpParser += 4*sizeof(uint8_t);
                                                                                        sGsnIpV6UserAddr[3] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                        pGtpParser += 4*sizeof(uint8_t);
											octets += (2+fwdLen);
                                                                                        }
                                                                                }
                                                                        }
                                                                else
                                                                        {
                                                                        printf ("TODO: handle ipv4 sgsn addr\n");
                                                                        }
                                                                break;
                                                                }
                                                        }
                                                printf ("sks: data I teid =0x%x, control teid=0x%x\n", dataTeid,controlTeid);
                                                printf ("sks: sGsnIpv4ControlAddr =0x%x:0x%x:0x%x:0x%x, sGsnIpV4UserAddr=0x%x:0x%x:0x%x:0x%x\n",
							 sGsnIpV6ControlAddr[0],sGsnIpV6ControlAddr[1],sGsnIpV6ControlAddr[2],sGsnIpV6ControlAddr[3],
							 sGsnIpV6UserAddr[0],sGsnIpV6UserAddr[1],sGsnIpV6UserAddr[2],sGsnIpV6UserAddr[3]);

                                                //Check for duplicate
                                                union ipv6_3tuple_host dupKey;
                                                bzero (&dupKey, sizeof(dupKey));
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_CONTEXT_RESPONSE)
                                                        {
                                                        //...Tie the pdp response and request together with the same sessioId
                                                        dupKey.ip_dst[0] = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                                                        dupKey.ip_dst[1] = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                                                        dupKey.ip_dst[2] = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                                                        dupKey.ip_dst[3] = rte_cpu_to_be_32(keyV6.ip_dst[3]);
                                                        dupKey.teid = rte_cpu_to_be_32(key.teid);
                                                        ret = rte_hash_lookup(pSessionIdV6ControlHashTable, (const void *)&dupKey);
                                                        if (ret > 0)
                                                                {
                                                                //...pdp create request entry found, get the sessionId
                                                                createReqSessionId = sessionIdControlHashTableIPV6[ret].sessionId;
                                                                }
                                                        else
                                                                {
                                                                //...received create response earlier than create request, kick off timer and wait
                                                                if (repeatCount == 0 )
                                                                        {
                                                                        printf ("sks:init timer case 6...\n");
                                                                        struct rte_timer * pUserPlaneTimer;
                                                                        pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                                                        int resetReturn = 0;
                                                                        rte_timer_init (pUserPlaneTimer);
                                                                        printf ("sks: timer reset...\n");
                                                                        lcore_id = rte_lcore_id ();
                                                                        resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                                                        printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                                                        return Nok;
                                                                        }
                                                                if (repeatCount == 1)
                                                                        {
                                                                        //orphan pkt, update stat and return
                                                                        gtpStats.gtpV1CtrlPktDiscards++;
                                                                        return Aok;
                                                                        }
                                                                }
                                                        }

                                                dupKey.ip_dst[0] = rte_cpu_to_be_32(sGsnIpV6ControlAddr[0]);
                                                dupKey.ip_dst[1] = rte_cpu_to_be_32(sGsnIpV6ControlAddr[1]);
                                                dupKey.ip_dst[2] = rte_cpu_to_be_32(sGsnIpV6ControlAddr[2]);
                                                dupKey.ip_dst[3] = rte_cpu_to_be_32(sGsnIpV6ControlAddr[3]);
                                                dupKey.teid   = rte_cpu_to_be_32(controlTeid);
                                                ret = rte_hash_lookup(pSessionIdV6ControlHashTable, (const void *)&dupKey);

                                                if (ret > 0)
                                                        {
                                                        //it is a duplicate, append sessionId and tx out
                                                        pSessionIdObjV6 = &sessionIdControlHashTableIPV6[ret];
                                                        lteAppendage.gtpSessionId = pSessionIdObjV6->sessionId;
                                                        printf ("detected duplicate pdp request, ready to send out pkt...\n");
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO - All done, transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        lte_send_packet (m, 2);
                                                        gtpStats.gtpV1IpV6CtrlPkt++;
                                                        }
                                                else
                                                        {
                                                        //create  a new entry in hash table
                                                        //cleanup hash object array first
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                                                                        socketid,
                                                                        lcore_id);

                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV6ControlHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIpV6ControlHashObjectArray[lcore_id][i]);
                                                                                pIpV6ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }
                                                        //Add a hash entry for control DOWN TEID
                                                        while (pIpV6ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV6HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                        //...downlink ip and control plane teid.

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[0]      = sGsnIpV6ControlAddr[0];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[1]      = sGsnIpV6ControlAddr[1];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[2]      = sGsnIpV6ControlAddr[2];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[3]      = sGsnIpV6ControlAddr[3];

                                                        if ((sGsnIpV6UserAddr[0] == 0)&&(sGsnIpV6UserAddr[1] ==0) && (sGsnIpV6UserAddr[2] == 0) && (sGsnIpV6UserAddr[3]==0))
								{
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0] = sGsnIpV6ControlAddr[0];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1] = sGsnIpV6ControlAddr[1];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2] = sGsnIpV6ControlAddr[2];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3] = sGsnIpV6ControlAddr[3];
								}
                                                        else
								{
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0] = sGsnIpV6UserAddr[0];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1] = sGsnIpV6UserAddr[1];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2] = sGsnIpV6UserAddr[2];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3] = sGsnIpV6UserAddr[3];
								}

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->controlTeid    = controlTeid;
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->dataTeid       = dataTeid;

                                                        if (createReqSessionId != 0 )
                                                                {
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId      = createReqSessionId;
                                                                createReqSessionId = 0;
                                                                }
							else
								{
								printf ("sks: generating globalSessionId =0x%x\n", globalSessionId);
                                                        	pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId      = globalSessionId++;
								}
 							
							if ((((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000)== GTP_PDP_UPDATE_REQUEST))||((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000)== GTP_PDP_UPDATE_RESPONSE))
                                                        {
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId      = sessionIdOfUpdateRequest;
                                                        }

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = ADD_GTPV1_SESSION;

                                                        if ((keyV6.teid != 0) && (((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000)== GTP_PDP_CONTEXT_REQUEST)))
                                                                {
                                                                //Handle the case of creation of a secondary context by the MS
                                                                union ipv6_3tuple_host secKeyV6;
                                                                bzero (&secKeyV6, sizeof(secKeyV6));
                                                                secKeyV6.ip_src[0] = sGsnIpV6ControlAddr[0];
                                                                secKeyV6.ip_src[1] = sGsnIpV6ControlAddr[1];
                                                                secKeyV6.ip_src[2] = sGsnIpV6ControlAddr[2];
                                                                secKeyV6.ip_src[3] = sGsnIpV6ControlAddr[3];
                                                                secKeyV6.teid	   = rte_cpu_to_be_32(keyV6.teid);
                                                                ret = rte_hash_lookup(pSessionIdV6ControlHashTable, (const void *)&secKeyV6);
                                                                if (ret > 0 )
                                                                        {
                                                                        //...session exists, extract sessionId
                                                                        pSessionIdObjV6 = &sessionIdControlHashTableIPV6[ret];
                                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId = pSessionIdObjV6->sessionId;
                                                                        }
                                                                }
                                                        ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV6ControlHashObjectArray[lcore_id][objCount]);
                                                        if (ret != 0 )
                                                                printf ("error in enqueuing to sessionIdRing\n");
                                                        lteAppendage.gtpSessionId = pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId;

                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        gtpStats.gtpV1IpV6CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                        }
                                                break;  //ctxt req/resp case
                                                }
                                        }//gtpv1 case closure
			          if (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTP_VERSION2_IN_FLAGS)
                                        {
                                        //GTPv2 processing, but gtp header info is the same so reuse v1 hdr
                                        //printf ("sks:gtpv2, switch = 0x%x\n", (int)((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & ALL_32_BITS )));

                                        switch ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 ))
                                                {
						case GTPV2_TYPE_REL_ACC_BEARER_REQ   : //intentional fall-thru
						case GTPV2_TYPE_REL_ACC_BEARER_RSP   :
						case GTPV2_TYPE_DEL_SESSION_REQ      :
						case GTPV2_TYPE_DEL_SESSION_RSP      :
                                                bzero (&dupKeyV6, sizeof(dupKeyV6));
                                                dupKeyV6.ip_dst[0] = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                                                dupKeyV6.ip_dst[1] = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                                                dupKeyV6.ip_dst[2] = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                                                dupKeyV6.ip_dst[3] = rte_cpu_to_be_32(keyV6.ip_dst[3]);

						printf ("sks: delete request for gtpv2\n");
                                                if (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTPV2_TEID_PRESENT)
                                                        {
                                                        //printf ("sks: gtpv2 bearer TEID is present\n");
                                                        pGtpV2Header = (struct GtpV2Header *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header) );
                                                        dupKeyV6.teid = rte_cpu_to_be_32(((struct GtpV2Header *)pGtpV2Header)->teid);
                                                        }
                                                else
                                                        {
                                                        pGtpV2Header = (struct GtpV2Header_noTeid *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header_noTeid) );
                                                        printf ("sks: need to increment a stat, exiting processing this pkt since no teid in hdr and is not a create mgs\n");
							//TODO: tx it out
							lte_send_packet (m, 2);
                                                        return Aok;
                                                        }
                                                printf ("looking up control ip=0x%x:0x%x:0x%x:0x%x, teid = 0x%x\n", dupKeyV6.ip_dst[0], dupKeyV6.ip_dst[1], dupKeyV6.ip_dst[2], dupKeyV6.ip_dst[3],dupKeyV6.teid);
                                                ret = rte_hash_lookup(pSessionIdV6GtpV2ControlHashTable,(const void *)&dupKeyV6);

                                                if (ret <= 0 )
                                                        {
                                                printf ("error looking up control ip=0x%x:0x%x:0x%x:0x%x, teid = 0x%x\n", dupKeyV6.ip_dst[0], dupKeyV6.ip_dst[1], dupKeyV6.ip_dst[2], dupKeyV6.ip_dst[3],dupKeyV6.teid);
                                                        }
						if (ret > 0)
							{
                                                        //create  a new entry in hash table
                                                        //cleanup hash object array first
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                                                                     socketid,
                                                                     lcore_id);

                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
	                                                        {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
       		                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV6ControlHashObjectArray[lcore_id][i])
                                                                   	     {
                                                                             rte_free (pIpV6ControlHashObjectArray[lcore_id][i]);
                                                                             pIpV6ControlHashObjectArray[lcore_id][i] = NULL;
                                                                             }
                                                                        }
                                                                }
                                                        //Add a hash entry for control DOWN TEID
                                                        while (pIpV6ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;
                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");

                                                                return Aok;
                                                                }
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV6HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV6HashObject),0);
                                                        //...downlink ip and control plane teid.
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUserV4  = 0x0;
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[0] = dupKeyV6.ip_dst[0];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[1] = dupKeyV6.ip_dst[1];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[2] = dupKeyV6.ip_dst[2];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[3] = dupKeyV6.ip_dst[3];

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->controlTeid  =  dupKeyV6.teid;
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag = RELEASE_BEARER_GTPV2_SESSION ;
                                                        printf ("sks:ret =%d ENQUEUING up teid=x0x%x\n", ret, sessionIdControlHashTableIPV6GTPV2[ret].controlTeid);

                                                        ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV6ControlHashObjectArray[lcore_id][objCount]);

                                                        printf ("sks: ring %s, ring count=%u\n", pControlRing->name, rte_ring_count (pControlRing));
                                                        if (ret != 0 )
                                 	                       printf ("error in enqueuing to sessionIdRing\n");
                                                        lteAppendage.gtpSessionId = pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId ;
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO -All done transmit it out right here if possible, since i/f number is avail
                                                        //a(pSessionIdObj->intf)
                                                        gtpStats.gtpV2IpV6CtrlPkt++;
							lte_send_packet (m, 2);
                                                        return Aok;
							}
							break;
                                                case GTPV2_CREATE_BEARER_REQUEST     : //...intentional fall-thru create bearer req/resp AND modify bearer req/resp 
                                                case GTPV2_CREATE_BEARER_RESPONSE    : 
                                                case GTPV2_MODIFY_BEARER_REQUEST     : 
                                                case GTPV2_MODIFY_BEARER_RESPONSE    : 
                                                bzero (&dupKeyV6, sizeof(dupKeyV6));
                                                dupKeyV6.ip_dst[0] = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                                                dupKeyV6.ip_dst[1] = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                                                dupKeyV6.ip_dst[2] = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                                                dupKeyV6.ip_dst[3] = rte_cpu_to_be_32(keyV6.ip_dst[3]);


                                                if (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTPV2_TEID_PRESENT)
                                                        {
                                                        //printf ("sks: gtpv2 bearer TEID is present\n");
                                                        pGtpV2Header = (struct GtpV2Header *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header) );
							dupKeyV6.teid = rte_cpu_to_be_32(((struct GtpV2Header *)pGtpV2Header)->teid);
                                                        }
                                                else
                                                        {
                                                        pGtpV2Header = (struct GtpV2Header_noTeid *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header_noTeid) );
							//printf ("sks: need to increment a stat, exiting processing this pkt since no teid in hdr and is not a create mgs\n");
							return Aok;
                                                        }
						printf ("looking up control ip=0x%x:0x%x:0x%x:0x%x, teid = 0x%x\n", dupKeyV6.ip_dst[0], dupKeyV6.ip_dst[1], dupKeyV6.ip_dst[2], dupKeyV6.ip_dst[3],dupKeyV6.teid);
                                                ret = rte_hash_lookup(pSessionIdV6GtpV2ControlHashTable,(const void *)&dupKeyV6);
						if (ret <= 0 ) 
							{
						printf ("error looking up control ip=0x%x:0x%x:0x%x:0x%x, teid = 0x%x\n", dupKeyV6.ip_dst[0], dupKeyV6.ip_dst[1], dupKeyV6.ip_dst[2], dupKeyV6.ip_dst[3],dupKeyV6.teid);
							}
						if (ret > 0 )
							{
							octets = 1;
	                                                while ((octets < (int)(rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x0000FFFF)) )
                                                        	{
                                                        	gtpType = (int)(*pGtpParser);
                                                        	//printf ("sks: gtpV2type=0x%x\n", gtpType);
                                                                if (gtpType ==GTPV2_TYPE_BEARER_CONTEXT)
	                                                                {
                                                                        pGtpParser += sizeof(uint8_t);
                                                                        octets++;
                                                                        int bearerLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                        printf ("sks:bearerlen %d\n", bearerLen);
                                                                        //jump over 3 octets - 2 octets for length and 1 octet for spare and instance
                                                                        pGtpParser +=(3*sizeof(uint8_t));
                                                                        octets += 3;
                                                                        while (bearerLen > 0)
        	                                                                {
                                                                                gtpType = (int)(*pGtpParser);
                                                                                printf ("bearer context type = 0x%x\n", gtpType);
                                                                                if (gtpType == GTPV2_TYPE_FTEID)
               		                                                                {
                                                                                        //printf ("sks: fteid in bearer request found\n");
                                                                                        pGtpParser += sizeof (uint8_t);
                                                                                        octets++;
                                                                                        bearerLen--;
                                                                                        fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                        pGtpParser +=(3*sizeof(uint8_t)); //2 octets for len and 1 octets for CR flag, 
                                                                                        octets+=3;
                                                                                        bearerLen -=3;
											//...4th octet is for ipv4/v6
											//...have to do this chk irrespective of what the ethernet header for this pkt says
											//...we might have an ipv4 or an ipv6 fteid in the bc for modify/create bearer msgs
											ipType = *pGtpParser;
											if ( ipType & 0x40 )
												{
												//...ipv6 addr
                                                                                        	pGtpParser += sizeof(uint8_t);
                                                                                        	octets ++;
                                                                                        	bearerLen --;
                                                                                        	dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //only get teid/gre key
                                                                                        	pGtpParser += 4*sizeof(uint8_t);
                                                                                        	octets+=4;
                                                                                        	bearerLen -=4;
                                                                				sGsnIpV6ControlAddr[0] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                				pGtpParser += 4*sizeof(uint8_t);
                                                                				sGsnIpV6ControlAddr[1] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                				pGtpParser += 4*sizeof(uint8_t);
                                                                				sGsnIpV6ControlAddr[2] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                				pGtpParser += 4*sizeof(uint8_t);
                                                                				sGsnIpV6ControlAddr[3] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                				pGtpParser += 4*sizeof(uint8_t);
                                                                				octets += 16;
												bearerLen -= 16;
                                                        					//create  a new entry in hash table
                                                        					//cleanup hash object array first
                                                        					lcore_id = rte_lcore_id();
                                                        					socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        					rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                                                                        					socketid,
                                                                        					lcore_id);

                                                        					pControlRing = rte_ring_lookup (name);
                                                        					if (pControlRing == NULL )
                                                                					{
                                                                					printf ("Cannot find ring %s\n", name);
                                                                					return Aok;
                                                                					}
												

                                                        					if (rte_ring_empty (pControlRing))
                                                                					{
                                                                					printf ("setting all ring entries to NULL\n");
                                                                 					for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        					{
                                                                        					//...Can optimize more here TODO
                                                                        					if(pIpV6ControlHashObjectArray[lcore_id][i])
                                                                                					{
                                                                                					rte_free (pIpV6ControlHashObjectArray[lcore_id][i]);
                                                                                					pIpV6ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                					}
                                                                        					}
                                                                					}
                                                        					//Add a hash entry for control DOWN TEID
                                                        					while (pIpV6ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                					objCount++;

                                                        					if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                					{
                                                                					printf ("FATAL: dropping pdp request msg\n");
                                                                					return Aok;
                                                                					}
                                                        					pIpV6ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV6HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                        					//...downlink ip and control plane teid.
												pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUserV4  = 0x0;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[0] = dupKeyV6.ip_dst[0];
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[1] = dupKeyV6.ip_dst[1];
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[2] = dupKeyV6.ip_dst[2];
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[3] = dupKeyV6.ip_dst[3];

                                                                				pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0] = sGsnIpV6ControlAddr[0];
                                                                				pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1] = sGsnIpV6ControlAddr[1];
                                                                				pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2] = sGsnIpV6ControlAddr[2];
                                                                				pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3] = sGsnIpV6ControlAddr[3];
                                                                				pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId =  sessionIdControlHashTableIPV6GTPV2[ret].sessionId;;
												pIpV6ControlHashObjectArray[lcore_id][objCount]->dataTeid  =  dataTeid;
												pIpV6ControlHashObjectArray[lcore_id][objCount]->controlTeid  =  sessionIdControlHashTableIPV6GTPV2[ret].controlTeid;
												pIpV6ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag = ADD_BEARER_GTPV2_SESSION ;
												printf ("sks:ret =%d ENQUEUING up teid=x0x%x\n", ret, sessionIdControlHashTableIPV6GTPV2[ret].controlTeid);
												ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV6ControlHashObjectArray[lcore_id][objCount]);

												printf ("sks: ring %s, ring count=%u\n", pControlRing->name, rte_ring_count (pControlRing));
                                                        					if (ret != 0 )
                                                                					printf ("error in enqueuing to sessionIdRing\n");
                                                        					lteAppendage.gtpSessionId = pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId ;
                                                        					rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                       						//TODO -All done transmit it out right here if possible, since i/f number is avail 
                                                       						//a(pSessionIdObj->intf)
                                                       						gtpStats.gtpV2IpV6CtrlPkt++;
												lte_send_packet (m,2);
												return Aok;
											        }	
											if ( ipType & 0x80 )
												{
												//...ipv4 addr
                                                                                        	pGtpParser += sizeof(uint8_t);
                                                                                        	octets ++;
                                                                                        	bearerLen --;
                                                                                        	dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //only get teid/gre key
                                                                                        	pGtpParser += 4*sizeof(uint8_t);
                                                                                        	octets+=4;
                                                                                        	bearerLen -=4;
                                                                                        	sGsnIpV4UserAddr =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                        	pGtpParser += 4*sizeof(uint8_t);
                                                                                        	octets += 4;
												bearerLen -= 4;
  lcore_id = rte_lcore_id();
                                                                                                socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                                                                rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                                                                                                                socketid,
                                                                                                                lcore_id);

                                                                                                pControlRing = rte_ring_lookup (name);
                                                                                                if (pControlRing == NULL )
                                                                                                        {
                                                                                                        printf ("Cannot find ring %s\n", name);
                                                                                                        return Aok;
                                                                                                        }
                                                                                                if (rte_ring_empty (pControlRing))
                                                                                                        {
                                                                                                        printf ("setting all ring entries to NULL\n");
                                                                                                        for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                                                                {
                                                                                                                //...Can optimize more here TODO
                                                                                                                if(pIpV6ControlHashObjectArray[lcore_id][i])
                                                                                                                        {
                                                                                                                        rte_free (pIpV6ControlHashObjectArray[lcore_id][i]);
                                                                                                                        pIpV6ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                                                        }
                                                                                                                }
                                                                                                        }
                                                                                                //Add a hash entry for control DOWN TEID
                                                                                                while (pIpV6ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                                                        objCount++;

                                                                                                if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                                                        {
                                                                                                        printf ("FATAL: dropping pdp request msg\n");
                                                                                                        return Aok;
                                                                                                        }
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV6HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                                                                //...downlink ip and control plane teid.

                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[0] = dupKeyV6.ip_dst[0];
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[1] = dupKeyV6.ip_dst[1];
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[2] = dupKeyV6.ip_dst[2];
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[3] = dupKeyV6.ip_dst[3];

                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUserV4 = sGsnIpV4UserAddr;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0] = 0x0;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1] = 0x0;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2] = 0x0;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3] = 0x0;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId =  sessionIdControlHashTableIPV6GTPV2[ret].sessionId;;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->dataTeid  =  dataTeid;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->controlTeid  =  sessionIdControlHashTableIPV6GTPV2[ret].controlTeid;
                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag = ADD_BEARER_GTPV2_SESSION ;
                                                                                                ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV6ControlHashObjectArray[lcore_id][objCount]);
                                                                                                if (ret != 0 )
                                                                                                        printf ("error in enqueuing to sessionIdRing\n");
                                                                                                lteAppendage.gtpSessionId = pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId ;
                                                                                                rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                                                                //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                                                                gtpStats.gtpV2IpV6CtrlPkt++; 
												lte_send_packet(m,2);
												return Aok;

												}
                                                                                        }
                                                                                else
                                                                                        {
                                                                                        pGtpParser += sizeof (uint8_t);
                                                                                        octets++;
                                                                                        bearerLen--;
                                                                                        fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                        pGtpParser += (fwdLen +3)* sizeof(uint8_t);
                                                                                        octets += fwdLen + 3;
                                                                                        bearerLen -= fwdLen + 3;
                                                                                        }
                                                                                }
                                                                         //printf ("came out of bearerlen loop with dataTeid=0x%x\n", dataTeid);
                                                                         }
                                                                 else
                                                                         {
                                                                         pGtpParser += sizeof (uint8_t);
                                                                         octets++;
                                                                         fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                         pGtpParser += (fwdLen +3)* sizeof(uint8_t);
                                                                         octets += fwdLen + 3;
                                                                         }
								}

							}
						else
							{
							//...too early, start a timer and wait.
                                                        if (repeatCount == 0 )
                                                                {
								
                                                                //printf ("sks:init timer case 4...\n");
                                                                struct rte_timer * pUserPlaneTimer;
                                                                pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                                                int resetReturn = 0;
                                                                rte_timer_init (pUserPlaneTimer);
                                                                //printf ("sks: timer reset...\n");
                                                                lcore_id = rte_lcore_id ();
                                                                resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                                                printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                                                return Nok;
                                                                }
                                                        if (repeatCount == 1)
                                                                {
                                                                //...orphan pkt, update stats and discard.
                                                                gtpStats.gtpV2IpV6ControlPktDiscards++;
                                                                return Aok;
								}
							}

						break;
						case GTPV2_CREATE_SESSION_RESPONSE   :  //...intentional fall-thru
                                                case GTPV2_CREATE_SESSION_REQUEST    : 
						printf ("sks: got gtpv2 create request/resp\n");

						if (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTPV2_TEID_PRESENT)
							{
							//printf ("sks: gtpv2 ipv6 create session req/resp TEID is present\n");
							pGtpV2Header = (struct GtpV2Header *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
							pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header) );
							}
						else
							{
							pGtpV2Header = (struct GtpV2Header_noTeid *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
							pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header_noTeid) );
							}						
						octets = 1;
                                                sGsnIpV6ControlAddr[0]=sGsnIpV6ControlAddr[1]=sGsnIpV6ControlAddr[2]=sGsnIpV6ControlAddr[3]=0;
						//printf ("sks: gtpv2 pkt len=0x%x\n", (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x0000FFFF));
                                                while ((octets < (int)(rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x0000FFFF))&& (sGsnIpV6ControlAddr[0] == 0) &&(sGsnIpV6ControlAddr[1]==0) && (sGsnIpV6ControlAddr[2]==0) && (sGsnIpV6ControlAddr[3]==0))
							{
							gtpType = (int)(*pGtpParser);
							//printf ("sks: gtpV2type=0x%x\n", gtpType);
					 		if (gtpType == GTPV2_TYPE_FTEID)
								{
								pGtpParser += sizeof (uint8_t);
								octets++;
								fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
								pGtpParser +=(4*sizeof(uint8_t)); //2 octets for len and 2 octets for CR flag, instance and ipv4/v6 flag
								octets+=4;
								controlTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //teid/gre key
							
								//	...assume it is a ipv6 addr because the ethernet header says so.
								//	...potential land mine, if session is shared between two interfaces, one a v4 and the other a v6
								//	...and if the ethernet header says ipv6 but the ipv4 sgsn appears first in the gtp payload we are hosed.
                                                                pGtpParser += 4*sizeof(uint8_t);
								octets+=4;
                                                                sGsnIpV6ControlAddr[0] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                sGsnIpV6ControlAddr[1] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                sGsnIpV6ControlAddr[2] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                sGsnIpV6ControlAddr[3] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
								octets+=16;
								printf ("sks: SGSNAddr = 0x%x:0x%x:0x%x:0x%x, teid=0x%x\n",
								sGsnIpV6ControlAddr[0],sGsnIpV6ControlAddr[1],sGsnIpV6ControlAddr[2],sGsnIpV6ControlAddr[3], controlTeid);
								}
							else
								{
								pGtpParser += sizeof (uint8_t);
								octets++;
								fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
								pGtpParser += (fwdLen +3)* sizeof(uint8_t);
								octets += fwdLen + 3;
								}
							} 	
                                                //Check for duplicate
                                                union ipv6_3tuple_host dupKey;
                                                bzero (&dupKey, sizeof(dupKey));

                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_SESSION_RESPONSE)
                                                        {
                                                        //...Tie the pdp response and request together with the same sessioId
                                                        dupKey.ip_dst[0] = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                                                        dupKey.ip_dst[1] = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                                                        dupKey.ip_dst[2] = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                                                        dupKey.ip_dst[3] = rte_cpu_to_be_32(keyV6.ip_dst[3]);
                                                        dupKey.teid = rte_cpu_to_be_32(key.teid);
                                                        ret = rte_hash_lookup(pSessionIdV6GtpV2ControlHashTable, (const void *)&dupKey);
                                                        if (ret > 0)
                                                                {
                                                                //...pdp create request entry found, get the sessionId
                                                                createReqSessionId = sessionIdControlHashTableIPV6GTPV2[ret].sessionId;
                                                                }
                                                        else
                                                                {
                                                                //...received create response earlier than create request, kick off timer and wait
                                                                if (repeatCount == 0 )
                                                                        {
                                                                        printf ("sks:init timer case 6...\n");
                                                                        struct rte_timer * pUserPlaneTimer;
                                                                        pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                                                        int resetReturn = 0;
                                                                        rte_timer_init (pUserPlaneTimer);
                                                                        printf ("sks: timer reset...\n");
                                                                        lcore_id = rte_lcore_id ();
                                                                        resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                                                        printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                                                        return Nok;
                                                                        }
                                                                if (repeatCount == 1)
                                                                        {
                                                                        //orphan pkt, update stat and return
                                                                        gtpStats.gtpV2CtrlPktDiscards++;
                                                                        return Aok;
                                                                        }
                                                                }
                                                        }
                                                dupKey.ip_dst[0] = sGsnIpV6ControlAddr[0];
                                                dupKey.ip_dst[1] = sGsnIpV6ControlAddr[1];
                                                dupKey.ip_dst[2] = sGsnIpV6ControlAddr[2];
                                                dupKey.ip_dst[3] = sGsnIpV6ControlAddr[3];
                                                dupKey.teid   = controlTeid;
                                                ret = rte_hash_lookup(pSessionIdV6GtpV2ControlHashTable, (const void *)&dupKey);

                                                if (ret > 0)
                                                        {
                                                        //it is a duplicate, append sessionId and tx out
                                                        pSessionIdObjGtpV2IPV6 = &sessionIdControlHashTableIPV6GTPV2[ret];
                                                        lteAppendage.gtpSessionId = pSessionIdObjGtpV2IPV6->sessionId;
                                                        //printf ("detected duplicate pdp request, ready to send out pkt...\n");
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO - All done, transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        gtpStats.gtpV2IpV6CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                        }
                                                else
                                                        {
                                                        //create  a new entry in hash table
                                                        //cleanup hash object array first
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                                                                        socketid,
                                                                        lcore_id);
							printf("sks: writing to ring %s\n", name);
                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }
                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                 for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV6ControlHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIpV6ControlHashObjectArray[lcore_id][i]);
                                                                                pIpV6ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }
                                                        //Add a hash entry for control DOWN TEID
                                                        while (pIpV6ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV6HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV6HashObject),0);
                                                        //...downlink ip and control plane teid.

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[0]      = sGsnIpV6ControlAddr[0];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[1]      = sGsnIpV6ControlAddr[1];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[2]      = sGsnIpV6ControlAddr[2];
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[3]      = sGsnIpV6ControlAddr[3];

                                                        if ((sGsnIpV6UserAddr[0] == 0)&&(sGsnIpV6UserAddr[1] ==0) && (sGsnIpV6UserAddr[2] == 0) && (sGsnIpV6UserAddr[3]==0))
                                                                {
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0] = sGsnIpV6ControlAddr[0];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1] = sGsnIpV6ControlAddr[1];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2] = sGsnIpV6ControlAddr[2];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3] = sGsnIpV6ControlAddr[3];
                                                                }
                                                        else
                                                                {
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0] = sGsnIpV6UserAddr[0];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1] = sGsnIpV6UserAddr[1];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2] = sGsnIpV6UserAddr[2];
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3] = sGsnIpV6UserAddr[3];
                                                                }

                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->controlTeid    = controlTeid;
							dataTeid 							= 0;
							if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000) == GTPV2_CREATE_SESSION_RESPONSE )
								{
								//...in gtpv2 only the create session response msg has the userplane teid in the bearer create msg
								//...parse this from where we left off earlier.
								while (((octets < (int)(rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen)))) && (dataTeid == 0))
									{ 
			                                                gtpType = (int)(*pGtpParser);
                                                        		//printf ("sks: create session response gtpV2type=0x%x\n", gtpType);
									if (gtpType ==GTPV2_TYPE_BEARER_CONTEXT)
										{
										pGtpParser += sizeof(uint8_t);
										octets++;
                                                                		int bearerLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
										//printf ("sks:bearerlen %d\n", bearerLen);
										//jump over 3 octets - 2 octets for length and 1 octet for spare and instance
                                                                		pGtpParser +=(3*sizeof(uint8_t)); 
										octets += 3;
										while (bearerLen > 0)
											{
											gtpType = (int)(*pGtpParser);
											//printf ("bearer context type = 0x%x\n", gtpType);
               			                                        		if (gtpType == GTPV2_TYPE_FTEID)
       		                                                        			{
                                                                                        	printf ("sks: ipv6 fteid in bearer request found\n");
                                                                                        	pGtpParser += sizeof (uint8_t);
                                                                                        	octets++;
                                                                                        	bearerLen--;
                                                                                        	fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                        	pGtpParser +=(3*sizeof(uint8_t)); //2 octets for len and 1 octets for CR flag,
                                                                                        	octets+=3;
                                                                                        	bearerLen -=3;
                                                                                        	//...4th octet is for ipv4/v6
                                                                                        	//...have to do this chk irrespective of what the ethernet header for this pkt says
                                                                                        	//...we might have an ipv4 or an ipv6 fteid in the bc for modify/create bearer msgs
												ipType = *pGtpParser; 
                                                                                        	printf ("sks: ip type = 0x%x\n", ipType);
                                                                                        	if ( ipType & 0x40 )
                                                                                                	{
                                                                                                	//...ipv6 addr
                                                                                                	pGtpParser += sizeof(uint8_t);
                                                                                                	octets ++;
                                                                                                	bearerLen --;
                                                                                                	dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //only get teid/gre key
                                                                                                	pGtpParser += 4*sizeof(uint8_t);
                                                                                                	octets+=4;
                                                                                                	bearerLen -=4;
                                                                                                	sGsnIpV6ControlAddr[0] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
	                                                                                                pGtpParser += 4*sizeof(uint8_t);
	                                                                                                sGsnIpV6ControlAddr[1] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
	                                                                                                pGtpParser += 4*sizeof(uint8_t);
	                                                                                                sGsnIpV6ControlAddr[2] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
	                                                                                                pGtpParser += 4*sizeof(uint8_t);
	                                                                                                sGsnIpV6ControlAddr[3] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
	                                                                                                pGtpParser += 4*sizeof(uint8_t);
	                                                                                                octets += 16;
	                                                                                                bearerLen -= 16;
	                                                                                                //create  a new entry in hash table
	                                                                                                //cleanup hash object array first
	                                                                                                //...downlink ip and control plane teid.
	
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUserV4 = 0x0;
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0] = sGsnIpV6ControlAddr[0];
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1] = sGsnIpV6ControlAddr[1];
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2] = sGsnIpV6ControlAddr[2];
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3] = sGsnIpV6ControlAddr[3];
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->dataTeid  =  dataTeid;
	                                                                                                }
	                                                                                        if ( ipType & 0x80 )
	                                                                                                {
	                                                                                                //...ipv4 addr
	                                                                                                pGtpParser += sizeof(uint8_t);
	                                                                                                octets ++;
	                                                                                                bearerLen --;
	                                                                                                dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //only get teid/gre key
	                                                                                                pGtpParser += 4*sizeof(uint8_t);
	                                                                                                octets+=4;
	                                                                                                bearerLen -=4;
	                                                                                                sGsnIpV4UserAddr =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
	                                                                                                pGtpParser += 4*sizeof(uint8_t);
	                                                                                                octets += 4;
	                                                                                                bearerLen -= 4;
	                                                                                                //...downlink ip and control plane teid.
	
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUserV4 = sGsnIpV4UserAddr;
													printf ("sks: setting ipUserV4 to crap value of 0x%x\n", sGsnIpV4UserAddr);
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[0] = 0x0;
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[1] = 0x0;
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[2] = 0x0;
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUser[3] = 0x0;
	                                                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->dataTeid  =  dataTeid;
													}
												}
	                                                        			else
	                                                                			{
       		                                                         			pGtpParser += sizeof (uint8_t);
	                                                                			octets++;
												bearerLen--;
	                                                                			fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
	                                                                			pGtpParser += (fwdLen +3)* sizeof(uint8_t);
	                                                                			octets += fwdLen + 3;
												bearerLen -= fwdLen + 3;
	                                                                			}
											}
										//printf ("came out of bearerlen loop with dataTeid=0x%x\n", dataTeid);
										}
                                                                         else
                                                                                {
                                                                                pGtpParser += sizeof (uint8_t);
                                                                                octets++;
                                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                pGtpParser += (fwdLen +3)* sizeof(uint8_t);
                                                                                octets += fwdLen + 3;
                                                                                }

									}
								}
							//printf ("sks: gtpV2, user teid=0x%x\n", dataTeid);
                                                       	pIpV6ControlHashObjectArray[lcore_id][objCount]->dataTeid       = dataTeid;
							
                                                        if (createReqSessionId != 0 )
                                                                {
                                                                pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId      = createReqSessionId;
                                                                createReqSessionId = 0;
                                                                }
							else
								{
 								printf ("sks: generating globalSessionId =0x%x\n", globalSessionId);
                                                        	pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId      = globalSessionId++;
								}
                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = ADD_GTPV2_SESSION;

                                                        if ((keyV6.teid != 0) && (((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000)== GTPV2_CREATE_SESSION_REQUEST)))
                                                                {
                                                                //Handle the case of creation of a secondary context by the MS
                                                                union ipv6_3tuple_host secKeyV6;
                                                                bzero (&secKeyV6, sizeof(secKeyV6));
                                                                secKeyV6.ip_src[0] = sGsnIpV6ControlAddr[0];
                                                                secKeyV6.ip_src[1] = sGsnIpV6ControlAddr[1];
                                                                secKeyV6.ip_src[2] = sGsnIpV6ControlAddr[2];
                                                                secKeyV6.ip_src[3] = sGsnIpV6ControlAddr[3];
                                                                secKeyV6.teid      = rte_cpu_to_be_32(keyV6.teid);
                                                                ret = rte_hash_lookup(pSessionIdV6GtpV2ControlHashTable, (const void *)&secKeyV6);
                                                                if (ret > 0 )
                                                                        {
                                                                        //...session exists, extract sessionId
                                                                        pSessionIdObjGtpV2IPV6 = &sessionIdControlHashTableIPV6GTPV2[ret];
                                                                        pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId = pSessionIdObjV6->sessionId;
                                                                        }
                                                                }

							printf ("control ip=0x%x:0x%x:0x%x:0x%x\n",pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[0],pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[1],pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[2],pIpV6ControlHashObjectArray[lcore_id][objCount]->ipControl[3]);

							printf ("ipuserV4 flag = 0x%x\n",pIpV6ControlHashObjectArray[lcore_id][objCount]->ipUserV4); 		
			                                ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV6ControlHashObjectArray[lcore_id][objCount]);

							printf ("sks: ring %s, ring count=%u\n", pControlRing->name, rte_ring_count (pControlRing));
                                                        if (ret != 0 )
                                                                printf ("error in enqueuing to sessionIdRing\n");
                                                        lteAppendage.gtpSessionId = pIpV6ControlHashObjectArray[lcore_id][objCount]->sessionId;

                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        gtpStats.gtpV2IpV6CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                        }	
						break;
						}

                                        }

                                } //control plane if statement
		}
        
	if (ipPktType == PACKET_TYPE_IPV4) { if ( ipv4_hdr->next_proto_id    == IPPROTO_UDP ) {
                        /* Check to make sure the packet is valid (RFC1812) */
                        if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt.pkt_len) < 0)
                               {
                               rte_pktmbuf_free(m);
                               printf ("invalid ipv4 header\n");
                               return Nok;//pkt already freed here
                               }
                        }
		else
			{
			return Aok;
			}

                pUdpHeader = (struct udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
		udpPortSrc = (uint16_t)(rte_cpu_to_be_16(pUdpHeader->src_port));
		udpPortDst = (uint16_t)(rte_cpu_to_be_16(pUdpHeader->dst_port));
       		calculateTimeStamp (&currentTime);
		lteAppendage.magic                 = 0xBACCFEED;
       		lteAppendage.secondTimeStamp       = currentTime.tv_sec;
       		lteAppendage.microSecondTimeStamp  = currentTime.tv_usec;
                if (fragPresent == 1)
                	{
                        bzero (&fragKeyV4, sizeof (fragKeyV4));
                        fragKeyV4.ip_addr = ipv4_hdr->dst_addr;
                        fragKeyV4.fragId  = fragId;

                        ret = rte_hash_lookup (pIpV4FragIdHashTable, (const void *)&fragKeyV4);
                        if ( ret >  0 )
                        	{
                                //      ... found, get sessionid and transmit out and exit
                                lteAppendage.gtpSessionId = ipV4fragIdHashTable[ret].sessionId;
                                rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                //TODO - All done, transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                gtpStats.gtpV1V2IpV4UserPktFragment++;
				lte_send_packet (m, 2);
                                //...return here itself since this is not a fully formed gtp pkt, hence
                                //...will not be in the user hash tbl.
                                return Aok;
                                }
                        else
                                {
                                //...fragment might have arrived before the first fragment
                                //...kick off timer and wait

                                if (repeatCount == 0 )
                                	{
                                        //printf ("sks:init timer case 2...\n");
                                        struct rte_timer * pUserPlaneTimer;
                                        pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                        int resetReturn = 0;
                                        rte_timer_init (pUserPlaneTimer);
                                        //printf ("sks: timer reset...\n");
                                        lcore_id = rte_lcore_id ();
                                        resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                        //printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                        return Nok;
                                        }
                                if (repeatCount == 1)
                                        {
                                        //...orphan pkt, update stats and discard.
                                        gtpStats.gtpV1V2IpV4UserPktFragmentDiscards++;
                                        return Aok;
                                        }
                                }
                        }

      		if ((udpPortSrc == USERPLANE_GTP_PORT)||(udpPortDst == USERPLANE_GTP_PORT))
              		{
                        if (vlanTag == PACKET_NO_VLAN_TAG_PRESENT)
				{
                                if (etherPktType !=  ETHER_PACKET_LINUX_COOKED)
                                        {
                                        data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)));
                                        data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i)));
                                        }
                                else
                                        {
                                        data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live))+sizeof (uint16_t));
                                        data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i))+sizeof(uint16_t));
                                        }
				}
			else
				{
                                data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv4_hdr,time_to_live)));
                                data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i)));
				}
            		key.xmm[0] = _mm_and_si128(data0, ipV4HashMask2);
          		key.xmm[1] = _mm_and_si128(data1, ipV4HashMask2);
                        bzero (&newKey,sizeof(newKey));
                        newKey.ip_dst = rte_cpu_to_be_32(key.ip_dst);
                        newKey.teid   = rte_cpu_to_be_32(key.teid);

			//printf ("sks: looking up userplane hash table\n");
			if (pSessionIdV4UserHashTable)
				{
                                //printf ("sks UP lkup key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                               //newKey.pad0,newKey.pad1,newKey.pad2,newKey.ip_src,newKey.ip_dst,newKey.pad3,newKey.pad4,newKey.pad5,newKey.pad6,newKey.flagsMsgTypeAndLen,newKey.teid,newKey.pad7);
               			ret = rte_hash_lookup(pSessionIdV4UserHashTable, (const void *)&newKey);
				}
                        if (ret > 0)
                                {
                                if (fragPresent == 1 )
                                        {
                                        lcore_id = rte_lcore_id();
                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                        rte_snprintf(name, sizeof(name), "FragId_ring%u_io%u_sId4",
                                                             socketid,
                                                             lcore_id);

                                        pFragIdRing = rte_ring_lookup (name);
                                        if (pFragIdRing == NULL )
                                                {
                                                printf ("Cannot find ring %s\n", name);
                                                return Aok;
                                                }
                                        if (rte_ring_empty (pFragIdRing))
                                                {
                                                printf ("setting all ring entries to NULL\n");
                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                        {
                                                        //...Can optimize more here TODO
                                                        if(pFragIdHashObjectArray[lcore_id][i])
                                                                {
                                                                rte_free (pFragIdHashObjectArray[lcore_id][i]);
                                                                pFragIdHashObjectArray[lcore_id][i] = NULL;
                                                                }
                                                        }
                                                }

                                        while (pFragIdHashObjectArray[lcore_id][objCount] != NULL )
                                                objCount++;

                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                {
                                                printf ("FATAL: dropping pdp request msg\n");
                                                return Aok;
                                                }

                                        pFragIdHashObjectArray[lcore_id][objCount] = (struct fragIdHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct sessionIdIpV6HashObject),0);

                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV6DstAddr[0]           = 0x0;
                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV6DstAddr[1]           = 0x0;
                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV6DstAddr[2]           = 0x0;
                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV6DstAddr[3]           = 0x0;
                                        pFragIdHashObjectArray[lcore_id][objCount]->ipV4DstAddr              = newKey.ip_dst;
                                        pFragIdHashObjectArray[lcore_id][objCount]->sessionId                = sessionIdUserHashTableIPV4[ret].sessionId;
                                        pFragIdHashObjectArray[lcore_id][objCount]->fragId                   = fragId;
					
                                        ret = rte_ring_mp_enqueue (pFragIdRing, (void *) pFragIdHashObjectArray[lcore_id][objCount]);


                                        if (ret != 0 )
                                                {
                                                printf ("error in enqueuing to sessionIdRing\n");
                                                return Aok;
                                                }
                                        gtpStats.gtpV1V2IpV4UserPktFragment++;
                                        }


                                pSessionIdUserObj = &sessionIdUserHashTableIPV4[ret];
                                lteAppendage.gtpSessionId = pSessionIdUserObj->sessionId;
                                //p
                                //intf ("sks: user plane pkt, hash lkup sucessful, ready to send out pkt...\n");
                                rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                //TODO - All done, transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                gtpStats.gtpV1V2IpV4UserPkt++;
				lte_send_packet (m, 2);
				return Aok;
                                }
			if (ret < 0)
				{
				////TODO - session not yet initiated but we have rx user data, kickoff timer and wait.
                                printf ("sks: entry does not exist for user plane pkt ipaddr=0x%x, teid=0x%x, repeatCount=%d returning...\n",newKey.ip_dst,newKey.teid, repeatCount);
                                if (repeatCount == 0 )
                                        {
                                        //...start timer, userplane pkt has arrived early
                                        printf ("sks:init timer case 5...\n");
                                        struct rte_timer * pUserPlaneTimer;
					pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
					int resetReturn = 0;
                                        rte_timer_init (pUserPlaneTimer);
					printf ("sks: timer reset...\n");
					lcore_id = rte_lcore_id ();
                                        resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
					printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
					return Nok;
                                        } 
                                 if (repeatCount == 1)
                                        {
                                        //...orphan pkt, update stats and discard.
                                        gtpStats.gtpV1V2IpV4UserPktDiscards++;
					printf ("sks, timer ticked, still entry is not there, returning...\n");
                                        return Aok;
                                        }
                                }
                      	}
                 if ((udpPortSrc == CONTROLPLANE_GTP_PORT)||(udpPortDst == CONTROLPLANE_GTP_PORT))
                      	 {
                         if (vlanTag == PACKET_NO_VLAN_TAG_PRESENT)
				{
                                if (etherPktType !=  ETHER_PACKET_LINUX_COOKED)
                                        {
					//rte_pktmbuf_dump(m,100);
                                        data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)));
                                        data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i)));
                                        }
                                else
                                        {
                                        data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live) + sizeof(uint16_t)));
                                        data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i)+ sizeof(uint16_t)));
                                        }
				}
			else
				{
                                data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv4_hdr,time_to_live)));
                                data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i)));

				}
 
			 key.xmm[0] = _mm_and_si128(data0, ipV4HashMask2);
                         key.xmm[1] = _mm_and_si128(data1, ipV4HashMask0);

	    	         printf ("sks: flags=0x%x ipdst=0x%x\n", key.flagsMsgTypeAndLen, rte_cpu_to_be_32(key.ip_dst));
                                if (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTP_VERSION1_IN_FLAGS)
                                        {
                                        //GTPv1 processing
                                        pGtpHeader = (struct GtpV1Header *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
					printf ("sks:gtpv1, switch = 0x%x\n", (int)((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & ALL_32_BITS )));
					switch ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 ))
						{
						case GTP_PDP_DELETE_CONTEXT_REQUEST://intentional fall-thru
                                               	pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpHeader  + sizeof(struct GtpV1Header) );
					        if ( *((uint8_t *)pGtpParser) == GTPV1_TYPE_TEARDOWN)
							{
							(uint8_t *)pGtpParser++;
							tearDownFlag = *((uint8_t *)pGtpParser);
							}	
						case GTP_PDP_DELETE_CONTEXT_RESPONSE:
                                       		key.xmm[1] = _mm_and_si128(data1, ipV4HashMask2);
				                bzero (&newKey,sizeof(newKey));
                               			newKey.ip_dst = rte_cpu_to_be_32(key.ip_dst);
                                        	newKey.teid   = rte_cpu_to_be_32(key.teid);

                                               	printf ("sks: ipv4 got delete request/response msg dst=0x%x, teid = 0x%x srcip=0x%x\n",newKey.ip_dst, newKey.teid, key.ip_src);
 						ret = rte_hash_lookup(pSessionIdV4ControlHashTable, (const void *)&newKey);
						if (ret < 0 )
							{
							printf ("ipv4 orphan delete context request/response\n");
                                                        if (repeatCount == 0 )
                                                                {
                                                                printf ("sks:init timer case 3...\n");
                                                                struct rte_timer * pUserPlaneTimer;
                                                                pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                                                int resetReturn = 0;
                                                                rte_timer_init (pUserPlaneTimer);
                                                                printf ("sks: timer reset...\n");
                                                                lcore_id = rte_lcore_id ();
                                                                resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                                                printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                                                return Nok;
                                                                }
                                                        if (repeatCount == 1)
                                                                {
                                                                //...orphan pkt, update stats and discard.
                                                                gtpStats.gtpV1IpV4ControlPktDiscards++;
								//...TODO: tx it out nevertheless
								lte_send_packet (m, 2);
                                                                return Aok;
                                                                }
							}
						else
							{
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",
                                                                          socketid,
                                                                          lcore_id);

                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
                                                        	{
                                                                printf ("Cannot find ring %s\n", name);
								//TODO:tx it out nevertheless
								lte_send_packet (m, 2);
                                                                return Aok;
                                                                }
                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                	{
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV4ControlHashObjectArray[lcore_id][i])
                                                                        	{
                                                                                rte_free (pIpV4ControlHashObjectArray[lcore_id][i]);
                                                                                pIpV4ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIpV4ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
								//TODO: tx it out
								lte_send_packet (m, 2);
                                                                return Aok;
                                                                }

                                                       	pSessionIdObj = &sessionIdControlHashTableIPV4[ret];


                                                        pIpV4ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV4HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                       	//...downlink ip and control plane teid.

                                                       	pIpV4ControlHashObjectArray[lcore_id][objCount]->ipControl      = pSessionIdObj->ipControl;

                                                       	pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser         = pSessionIdObj->ipUser;

                                                       	pIpV4ControlHashObjectArray[lcore_id][objCount]->controlTeid    = pSessionIdObj->controlTeid;
                                                       	pIpV4ControlHashObjectArray[lcore_id][objCount]->dataTeid       = pSessionIdObj->userTeid;
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = DELETE_GTPV1_SESSION_NO_TEARDOWN;

							lteAppendage.gtpSessionId = sessionIdControlHashTableIPV4[ret].sessionId;
 							printf ("sks:segregate:requests received sessId= 0x%x\n", lteAppendage.gtpSessionId);


							if ( tearDownFlag == 0xff )
								{
                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = DELETE_GTPV1_SESSION_TEARDOWN;
								}
							printf ("sks: enqueueing delete msg objCount=%d\n", objCount);

				
                                       			ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV4ControlHashObjectArray[lcore_id][objCount]);
                                                       	if (ret != 0 )
                                                       		{
                                                       		printf ("error in enqueuing to sessionIdRing\n");
                                                               	return Aok;
                                                               	}


                                                	rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
							printf ("sks: all done for delete request/resp msg\n");
                                                	//TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                	gtpStats.gtpV1IpV4CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
							}
						break;
						case GTP_PDP_UPDATE_REQUEST://intentional fall-thru
						printf ("sks:updt req\n");
						case GTP_PDP_UPDATE_RESPONSE://intentional fall-thru
                                                key.xmm[1] = _mm_and_si128(data1, ipV4HashMask2);
                                                bzero (&newKey,sizeof(newKey));
                                                newKey.ip_dst = rte_cpu_to_be_32(key.ip_dst);
                                                newKey.teid   = rte_cpu_to_be_32(key.teid);

                                                printf ("sks: ipv4 got update request/response msg dst=0x%x, teid = 0x%x ipsrc=0x%x\n",newKey.ip_dst, newKey.teid, rte_cpu_to_be_32(key.ip_src));
                                                ret = rte_hash_lookup(pSessionIdV4ControlHashTable, (const void *)&newKey);
                                                if (ret < 0 )
                                                        {
                                                        printf ("ipv4 orphan update context request/response\n");
                                                        // start a timer
							//then tx it out if still not found
			                                if (repeatCount == 0 )
                        			                {
                                        			printf ("sks:init timer case 6...\n");
                                        			struct rte_timer * pUserPlaneTimer;
                                        			pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                        			int resetReturn = 0;
                                        			rte_timer_init (pUserPlaneTimer);
                                        			printf ("sks: timer reset...\n");
                                        			lcore_id = rte_lcore_id ();
                                        			resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                        			printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                        			return Nok;
                                                                }
                                                        if (repeatCount == 1)
                                                                {
                                                                //...orphan pkt, update stats and discard.
                                                                return Aok;
                                                                }
                                                        }
                                                else
                                                        {
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",
                                                                          socketid,
                                                                          lcore_id);

                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                //TODO:tx it out nevertheless
                                                                lte_send_packet (m, 2);
                                                                return Aok;
                                                                }
                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV4ControlHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIpV4ControlHashObjectArray[lcore_id][i]);
                                                                                pIpV4ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIpV4ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                //TODO: tx it out
                                                                lte_send_packet (m, 2);
                                                                return Aok;
                                                                }

                                                        pSessionIdObj = &sessionIdControlHashTableIPV4[ret];


                                                        pIpV4ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV4HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                        //...downlink ip and control plane teid.

                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->ipControl      = pSessionIdObj->ipControl;

                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser         = pSessionIdObj->ipUser;

                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->controlTeid    = pSessionIdObj->controlTeid;
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->dataTeid       = pSessionIdObj->userTeid;
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = DELETE_GTPV1_SESSION_TEARDOWN;
							//remember the sessionid so that the updated hash entry has the old session id.
							sessionIdOfUpdateRequest					= sessionIdControlHashTableIPV4[ret].sessionId;
                                                        lteAppendage.gtpSessionId 					= sessionIdControlHashTableIPV4[ret].sessionId;
 							printf ("sks:segregate:requests received sessId= 0x%x%x\n", *(((int*)(&(lteAppendage.gtpSessionId)))+1), lteAppendage.gtpSessionId);


							printf ("sks: enqueueing update msg objCount=%d\n", objCount);

                                                        ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV4ControlHashObjectArray[lcore_id][objCount]);
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to sessionIdRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pControlRing));
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        gtpStats.gtpV1IpV4CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                        }
 
						case GTP_PDP_CONTEXT_REQUEST: //intentional fall-thru
						case GTP_PDP_CONTEXT_RESPONSE:
						key.xmm[1] = _mm_and_si128(data1, ipV4HashMask0);
						printf ("sks: got context create request/response msg\n");
	                                        //...Create a new hash entry
                                             	pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpHeader  + sizeof(struct GtpV1Header));
               		                        if ( rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTP_SEQ_NUMBER_PRESENT )
                                                //...advance pGtpHeader pointer towards the control and data teids
                                                       	pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpParser  +  sizeof (uint16_t));

                                       	 	//printf ("sks:ctrl plane pkt - recognized pdp request 0x%x \n", (int)(*pGtpParser) );
                                               	if ( rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTP_NPDU_PRESENT )
                                                       	pGtpParser      = (unsigned char *) ((unsigned char *)pGtpParser + sizeof (uint8_t));

                                               	/*printf ("*****hex dump****\n");
                                              	while (octets < 32)
                                                  	{
                                                       	printf ("%02x ",(int)(*pGtpParser));
                                                       	octets++;
                                                       	pGtpParser++;
                                                      	}*/
                                               	octets = 1;
                                        	//printf ("sks:gtp header len=0x%x\n", rte_cpu_to_be_16((uint16_t)pGtpHeader->length));
                                               while ((octets < rte_cpu_to_be_16(pGtpHeader->length))&& (sGsnIpV4ControlAddr == 0))
                                                      	{
                                                       	gtpType = (int)(*pGtpParser);
                                                  	//increment parser pointer so that we can pick up the value of the type
                                                        pGtpParser += sizeof (uint8_t);
						 	octets ++;	
                                                         //      printf ("sks:gtpType=0x%x\n", gtpType);
                                                         switch (gtpType)        
								{
                                                                case GTPV1_TYPE_IMSI:
                                                                pGtpParser += 8*sizeof(uint8_t);
								octets += 8;
                                                                break;
                                                                case GTPV1_TYPE_RAI:
                                                                pGtpParser += 6*sizeof(uint8_t);
								octets += 6;
                                                                break;
                                                                case GTPV1_TYPE_RECOVERY://intentional fall thru
                                                                case GTPV1_TYPE_CAUSE:
                                                                case GTPV1_TYPE_REORDERING_REQD:
                                                                case GTPV1_TYPE_NSAPI:
                                                                case GTPV1_TYPE_SEL_MODE:
                                                                pGtpParser += sizeof(uint8_t);
								octets ++;
                                                                break;
                                                                case GTPV1_TYPE_DATA_TEID:
                                                                dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
								octets += 4;
                                                                break;
                                                                case GTPV1_TYPE_CTRL_TEID:
                                                                controlTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
								octets += 4;
                                                                break;
                                                                case GTPV1_TYPE_CHARGING_ID:
                                                                pGtpParser += 4*sizeof(uint8_t);
								octets += 4;
								break;
                                                                case GTPV1_TYPE_CHARGING_CHK: //intentional fall thru
                                                                case GTPV1_TYPE_TRACE_REF:
                                                                case GTPV1_TYPE_TRACE_TYPE:
                                                                pGtpParser += 2*sizeof(uint8_t);
								octets += 2;
                                                                break;
                                                                case GTPV1_TYPE_END_USER_ADD:
                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                pGtpParser += 2*sizeof(uint8_t);
                                                                pGtpParser += fwdLen*sizeof(uint8_t);
								octets += (2+ fwdLen);
                                                                break;
                                                                case GTPV1_TYPE_ACCESS_PT_NAME: //intentional fall thru
                                                                case GTPV1_TYPE_PROTOCOL_CFG_OPT:
                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                pGtpParser += 2*sizeof(uint8_t);
                                                                pGtpParser += fwdLen*sizeof(uint8_t);
								octets += (2+ fwdLen);
                                                                break;
                                                                case GTPV1_TYPE_SGSN_ADDR:
                                                        	fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                               	if (fwdLen == 4 )
                                                                     	{
                                                                      	pGtpParser += 2*sizeof(uint8_t);
                                                                       	sGsnIpV4ControlAddr = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                   	pGtpParser += fwdLen*sizeof(uint8_t);
                                                                   	gtpType = (int)(*pGtpParser);
									octets += (2+ fwdLen);
                                                                      	if (gtpType==GTPV1_TYPE_SGSN_ADDR)
                                                                        	{
                                                                             	pGtpParser += sizeof (uint8_t);
                                                                               	fwdLen = rte_cpu_to_be_16(*((uint32_t *)pGtpParser));
                                                                               	if (fwdLen == 4)
                                                                                  	{
                                                                                      	pGtpParser += 2*sizeof(uint8_t);
                                                                                     	sGsnIpV4UserAddr =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                     	pGtpParser += fwdLen*sizeof(uint8_t);
											octets += (1+ fwdLen);
                                                                                      	}
                                                                               	}
                                                                  	}
                                                               	else
                                                                       	{
                                                                     	printf ("TODO: handle ipv6 sgsn addr\n");
                                                                   	}
                                                              	break;
                                                       		}
                                              		}
                                            	printf ("sks: data I teid =0x%x, control teid=0x%x\n", dataTeid,controlTeid);
                                             	printf ("sks: sGsnIpv4ControlAddr =0x%x, sGsnIpV4UserAddr=0x%x\n", sGsnIpV4ControlAddr, sGsnIpV4UserAddr);

                                            	union ipv4_3tuple_host dupKey;
                                              	bzero (&dupKey, sizeof(dupKey));
						if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_CONTEXT_RESPONSE)
							{
							//...Tie the pdp response and request together with the same sessioId
							dupKey.ip_dst = rte_cpu_to_be_32(key.ip_dst);
							dupKey.teid = rte_cpu_to_be_32(key.teid);
                                                	ret = rte_hash_lookup(pSessionIdV4ControlHashTable, (const void *)&dupKey);
							if (ret > 0)
								{
								printf ("sks: successfully tied together the sessionIds\n");
								//...pdp create request entry found, get the sessionId 
								createReqSessionId = sessionIdControlHashTableIPV4[ret].sessionId; 
								}
							else
								{
								//...received create response earlier than create request, kick off timer and wait
                                                        	if (repeatCount == 0 )
                                                                	{
                                                                	printf ("sks:init timer case 6...\n");
                                                                	struct rte_timer * pUserPlaneTimer;
                                                                	pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                                                	int resetReturn = 0;
                                                                	rte_timer_init (pUserPlaneTimer);
                                                                	printf ("sks: timer reset...\n");
                                                                	lcore_id = rte_lcore_id ();
                                                                	resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                                                	printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                                                	return Nok;
                                                                	}
                                                        	if (repeatCount == 1)
                                                                	{
									//orphan pkt, update stat and return
									printf ("sks: not able to tie together the sessionIds, discarding...\n");
									gtpStats.gtpV1CtrlPktDiscards++;
									return Aok;
									}
								}
							}

                                              	dupKey.ip_dst = sGsnIpV4ControlAddr;
                                              	dupKey.teid   = controlTeid;
                                           	ret = rte_hash_lookup(pSessionIdV4ControlHashTable, (const void *)&dupKey);

                                        	if (ret > 0)
                                                     	{
                                                   	//it is a duplicate, append sessionId and tx out
                                                   	lteAppendage.gtpSessionId = sessionIdControlHashTableIPV4[ret].sessionId;
                                                	printf ("detected duplicate pdp request, ready to send out pkt...\n");
                                                      	rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                      	//TODO - All done, transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                      	gtpStats.gtpV1IpV4CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                     	}
                                               	else
                                                	{
                                                       	//create  a new entry in hash table
                                                       	//cleanup hash object array first
                                                     	lcore_id = rte_lcore_id();
                                                      	socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                      	rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",
                                                                   	socketid,
                                                                	lcore_id);

                                                       	pControlRing = rte_ring_lookup (name);
                                                       	if (pControlRing == NULL )
                                                             	{
                                                        	printf ("Cannot find ring %s\n", name);
                                                               	return Aok;
                                                              	}

                                                       	if (rte_ring_empty (pControlRing))
                                                           	{
                                                            	printf ("setting all ring entries to NULL\n");
                                                             	for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                     	{
                                                                      	//...Can optimize more here TODO
                                                                      	if(pIpV4ControlHashObjectArray[lcore_id][i])
                                                 	                 	{
                                                                            	rte_free (pIpV4ControlHashObjectArray[lcore_id][i]);
                                                                              	pIpV4ControlHashObjectArray[lcore_id][i] = NULL;
                                                                        	}
                                                                       	}
                                                               	}

                                                   	//Add a hash entry for control DOWN TEID
                                                  	while (pIpV4ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                        	objCount++;

                                                      	if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                             	{
                                                               	printf ("FATAL: dropping pdp request msg\n");
                                                             	return Aok;
                                                             	}

                                                      	pIpV4ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV4HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                   	//...downlink ip and control plane teid.

                                                	pIpV4ControlHashObjectArray[lcore_id][objCount]->ipControl      = sGsnIpV4ControlAddr;

                                                     	if (sGsnIpV4UserAddr == 0)
                                                             	pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser = sGsnIpV4ControlAddr;
                                                  	else
                                                   		pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser = sGsnIpV4UserAddr;

                                                      	pIpV4ControlHashObjectArray[lcore_id][objCount]->controlTeid    = controlTeid;
                                                     	pIpV4ControlHashObjectArray[lcore_id][objCount]->dataTeid       = dataTeid;

							if (createReqSessionId != 0 )
								{
							        pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId      = createReqSessionId;
								lteAppendage.gtpSessionId = createReqSessionId;
								createReqSessionId = 0;
								}
							else
								{	
 								printf ("sks: generating globalSessionId =0x%x\n", globalSessionId);
                                                       		pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId      = globalSessionId++;
								lteAppendage.gtpSessionId = pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId;
								}

							if ((((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000)== GTP_PDP_UPDATE_REQUEST))||((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000)== GTP_PDP_UPDATE_RESPONSE))
							{
							pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId      = sessionIdOfUpdateRequest;
							lteAppendage.gtpSessionId					= sessionIdOfUpdateRequest;
							}
                                                       	pIpV4ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = ADD_GTPV1_SESSION;
									
							//re-enable the flagsMsgTypeAndLen
		                                        key.xmm[1] = _mm_and_si128(data1, ipV4HashMask0);

                                                   	if ((key.teid != 0) && (((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000)== GTP_PDP_CONTEXT_REQUEST)))
                                                           	{
                                                               	//Handle the case of creation of a secondary context by the MS
                                                            	union ipv4_3tuple_host secKey;
                                                              	bzero (&secKey, sizeof(secKey));
                                                             	secKey.ip_dst = sGsnIpV4ControlAddr;
                                                              	secKey.teid   = rte_cpu_to_be_32(key.teid);
                                                               	ret = rte_hash_lookup(pSessionIdV4ControlHashTable, (const void *)&secKey);
                                                               	if (ret > 0 )
                                                                   	{
                                                                  	//...session exists, extract sessionId
                                                                      	pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId = sessionIdControlHashTableIPV4[ret].sessionId;
                                                                    	}
                                                              	}

                                                     	ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV4ControlHashObjectArray[lcore_id][objCount]);
                                                      	if (ret != 0 )
                                                          	printf ("error in enqueuing to sessionIdRing\n");
                                                       	rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                       	//TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                       	gtpStats.gtpV1IpV4CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                      	}
						break;  //ctxt req/resp case
						}
					}//gtpv1 case closure
                                  if (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTP_VERSION2_IN_FLAGS)
                                        {
                                        //GTPv2 processing, but gtp header info is the same so reuse v1 hdr
                                        printf ("sks:gtpv2, ip v4 switch = 0x%x\n", (int)((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & ALL_32_BITS )));

                                        switch ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 ))
                                                {
                                                case GTPV2_TYPE_REL_ACC_BEARER_REQ   : //intentional fall-thru
                                                case GTPV2_TYPE_REL_ACC_BEARER_RSP   :
                                                case GTPV2_TYPE_DEL_SESSION_REQ      :
                                                case GTPV2_TYPE_DEL_SESSION_RSP      :
                                                bzero (&newKey, sizeof(newKey));
                                                newKey.ip_dst = rte_cpu_to_be_32(key.ip_dst);

                                                if (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTPV2_TEID_PRESENT)
                                                        {
                                                        //printf ("sks: gtpv2 bearer TEID is present\n");
                                                        pGtpV2Header = (struct GtpV2Header *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header) );
                                                        newKey.teid = rte_cpu_to_be_32(((struct GtpV2Header *)pGtpV2Header)->teid);
                                                        }
                                                else
                                                        {
                                                        pGtpV2Header = (struct GtpV2Header_noTeid *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header_noTeid) );
                                                        printf ("sks: need to increment a stat, exiting processing this pkt since no teid in hdr and is not a create mgs\n");
                                                        //TODO: tx it out
                                                        lte_send_packet (m, 2);
                                                        return Aok;
                                                        }
                                                ret = rte_hash_lookup(pSessionIdV4GtpV2ControlHashTable,(const void *)&newKey);

                                                if (ret <= 0 )
                                                        {
                                                printf ("error looking up control \n");
                                                        }
                                                if (ret > 0)
                                                        {
                                                        //create  a new entry in hash table
                                                        //cleanup hash object array first
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",
                                                                     socketid,
                                                                     lcore_id);

                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV4ControlHashObjectArray[lcore_id][i])
                                                                             {
                                                                             rte_free (pIpV4ControlHashObjectArray[lcore_id][i]);
                                                                             pIpV4ControlHashObjectArray[lcore_id][i] = NULL;
                                                                             }
                                                                        }
                                                                }
                                                        //Add a hash entry for control DOWN TEID
                                                        while (pIpV4ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;
                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV4HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                        //...downlink ip and control plane teid.
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser  = 0x0;
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->ipControl = newKey.ip_dst;

                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->controlTeid  =  newKey.teid;
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag = RELEASE_BEARER_GTPV2_SESSION ;
                                                        printf ("sks:ret =%d ENQUEUING up teid=x0x%x\n", ret, sessionIdControlHashTableIPV4GTPV2[ret].controlTeid);
							
                                                        ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV4ControlHashObjectArray[lcore_id][objCount]);
							//calculateTimeStamp (&currentTime);
                                                        //printf ("sks:enque done ring %s, ring count=%u time=0x%x.0x%x\n", pControlRing->name, rte_ring_count (pControlRing),currentTime.tv_sec, currentTime.tv_usec);
                                                        if (ret != 0 )
                                                               printf ("error in enqueuing to sessionIdRing\n");
                                                        lteAppendage.gtpSessionId = pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId ;
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO -All done transmit it out right here if possible, since i/f number is avail
                                                        //a(pSessionIdObj->intf)
                                                        gtpStats.gtpV2IpV4CtrlPkt++;
							lte_send_packet (m, 2);
                                                        return Aok;
                                                        }
                                                        break;

                                                case GTPV2_CREATE_BEARER_REQUEST     : //...intentional fall-thru create bearer req/resp AND modify bearer req/resp
                                                case GTPV2_CREATE_BEARER_RESPONSE    :
                                                case GTPV2_MODIFY_BEARER_REQUEST     :
                                                case GTPV2_MODIFY_BEARER_RESPONSE    :
                                                bzero (&newKey, sizeof(newKey));
                                                newKey.ip_dst = rte_cpu_to_be_32(key.ip_dst);

                                                if (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTPV2_TEID_PRESENT)
                                                        {
                                                        printf ("sks: gtpv2 TEID is present\n");
                                                        pGtpV2Header = (struct GtpV2Header *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header) );
                                                        newKey.teid = rte_cpu_to_be_32(((struct GtpV2Header *)pGtpV2Header)->teid);
							//printf ("sks: came here\n");
                                                        }
                                                else
                                                        {
                                                        pGtpV2Header = (struct GtpV2Header_noTeid *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header_noTeid) );
                                                        printf ("sks: need to increment a stat, exiting processing this pkt since no teid in hdr and is not a create mgs\n");
                                                        return Aok;
                                                        }
						
						printf ("sks: lookup up ipv4 gtpv2 control hash ip=0x%x, teid=0x%x\n", newKey.ip_dst, newKey.teid);
                                                ret = rte_hash_lookup(pSessionIdV4GtpV2ControlHashTable,(const void *)&newKey);
						printf ("sks: gtpv2 v4 hash returned 0x%x\n", ret);
                                                if (ret > 0 )
                                                        {
                                                        octets = 1;
                                                        while ((octets < (int)(rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x0000FFFF)) )
                                                                {
                                                                gtpType = (int)(*pGtpParser);
                                                                //printf ("sks: gtpV2type=0x%x\n", gtpType);
                                                                if (gtpType ==GTPV2_TYPE_BEARER_CONTEXT)
                                                                        {
                                                                        pGtpParser += sizeof(uint8_t);
                                                                        octets++;
                                                                        int bearerLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                        //printf ("sks:bearerlen %d\n", bearerLen);
                                                                        //jump over 3 octets - 2 octets for length and 1 octet for spare and instance
                                                                        pGtpParser +=(3*sizeof(uint8_t));
                                                                        octets += 3;
                                                                        while (bearerLen > 0)
                                                                                {
                                                                                gtpType = (int)(*pGtpParser);
                                                                                //printf ("bearer context type = 0x%x\n", gtpType);
                                                                                if (gtpType == GTPV2_TYPE_FTEID)
                                                                                        {
                                                                                        printf ("sks: fteid in bearer request found\n");
                                                                                        pGtpParser += sizeof (uint8_t);
                                                                                        octets++;
                                                                                        bearerLen--;
                                                                                        fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                        pGtpParser +=(3*sizeof(uint8_t)); //2 octets for len and 1 octets for CR flag,
                                                                                        octets+=3;
                                                                                        bearerLen -=3;
                                                                                        //...4th octet is for ipv4/v6
                                                                                        //...have to do this chk irrespective of what the ethernet header for this pkt says
                                                                                        //...we might have an ipv4 or an ipv6 fteid in the bc for modify/create bearer msgs
                                                                                        if ( *pGtpParser && 0x40 )
                                                                                                {
                                                                                                //...ipv6 addr
                                                                                                pGtpParser += sizeof(uint8_t);
                                                                                                octets ++;
                                                                                                bearerLen --;
                                                                                                dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //only get teid/gre key
                                                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                                                octets+=4;
                                                                                                bearerLen -=4;
                                                                                                sGsnIpV6ControlAddr[0] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                                                sGsnIpV6ControlAddr[1] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                                                sGsnIpV6ControlAddr[2] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                                                sGsnIpV6ControlAddr[3] =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                                                octets += 16;
                                                                                                bearerLen -= 16;
                                                                                                //create  a new entry in hash table
                                                                                                //cleanup hash object array first
                                                                                                lcore_id = rte_lcore_id();
                                                                                                socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                                                                rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",


                                                                                                                socketid,
                                                                                                                lcore_id);

                                                                                                pControlRing = rte_ring_lookup (name);
                                                                                                if (pControlRing == NULL )
                                                                                                        {
                                                                                                        printf ("Cannot find ring %s\n", name);
                                                                                                        return Aok;
                                                                                                        }

                                                                                                if (rte_ring_empty (pControlRing))
                                                                                                        {
                                                                                                        printf ("setting all ring entries to NULL\n");
                                                                                                        for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                                                                {
                                                                                                                //...Can optimize more here TODO
                                                                                                                if(pIpV4ControlHashObjectArray[lcore_id][i])
                                                                                                                        {
                                                                                                                        rte_free (pIpV4ControlHashObjectArray[lcore_id][i]);
                                                                                                                        pIpV4ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                                                        }
                                                                                                                }
                                                                                                        }
                                                                                                //Add a hash entry for control DOWN TEID
                                                                                                while (pIpV4ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                                                        objCount++;

                                                                                                if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                                                        {
                                                                                                        printf ("FATAL: dropping pdp request msg\n");
                                                                                                        return Aok;
                                                                                                        }
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV4HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                                                                //...downlink ip and control plane teid.
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser  = 0x0;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipControl = newKey.ip_dst;

                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUserV6[0] = sGsnIpV6ControlAddr[0];
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUserV6[1] = sGsnIpV6ControlAddr[1];
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUserV6[2] = sGsnIpV6ControlAddr[2];
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUserV6[3] = sGsnIpV6ControlAddr[3];
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId =  sessionIdControlHashTableIPV6GTPV2[ret].sessionId;;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->dataTeid  =  dataTeid;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->controlTeid  =  sessionIdControlHashTableIPV6GTPV2[ret].controlTeid;

                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag = ADD_BEARER_GTPV2_SESSION ;

                                                                                                ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV4ControlHashObjectArray[lcore_id][objCount]);


												//calculateTimeStamp (&currentTime);
                                                        					//printf ("sks:enque done ring %s, ring count=%u time=0x%x.0x%x\n", pControlRing->name, rte_ring_count (pControlRing),currentTime.tv_sec, currentTime.tv_usec);

                                                                                                if (ret != 0 )
                                                                                                        printf ("error in enqueuing to sessionIdRing\n");
                                                                                                lteAppendage.gtpSessionId = pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId ;
                                                                                                rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                                                                //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                                                                lte_send_packet (m,2);
                                                                                                gtpStats.gtpV2IpV4CtrlPkt++; 
												return Aok;
                                                                                                }
                                                                                        if ( *pGtpParser && 0x80 )
                                                                                                {
                                                                                                //...ipv4 addr
                                                                                                pGtpParser += sizeof(uint8_t);
                                                                                                octets ++;
                                                                                                bearerLen --;
                                                                                                dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //only get teid/gre key
                                                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                                                octets+=4;
                                                                                                bearerLen -=4;
                                                                                                sGsnIpV4UserAddr =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                                                octets += 4;
                                                                                                bearerLen -= 4;
  lcore_id = rte_lcore_id();
                                                                                                socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                                                                rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",
                                                                                                                socketid,
                                                                                                                lcore_id);

                                                                                                pControlRing = rte_ring_lookup (name);
                                                                                                if (pControlRing == NULL )
                                                                                                        {
                                                                                                        printf ("Cannot find ring %s\n", name);
                                                                                                        return Aok;
                                                                                                        }

                                                                                                if (rte_ring_empty (pControlRing))
                                                                                                        {
                                                                                                        printf ("setting all ring entries to NULL\n");
                                                                                                        for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                                                                {
                                                                                                                //...Can optimize more here TODO
                                                                                                                if(pIpV4ControlHashObjectArray[lcore_id][i])
                                                                                                                        {
                                                                                                                        rte_free (pIpV4ControlHashObjectArray[lcore_id][i]);
                                                                                                                        pIpV4ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                                                        }
                                                                                                                }
                                                                                                        }

                                                                                                //Add a hash entry for control DOWN TEID
                                                                                                while (pIpV4ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                                                        objCount++;

                                                                                                if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                                                        {
                                                                                                        printf ("FATAL: dropping pdp request msg\n");
                                                                                                        return Aok;
                                                                                                        }
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV4HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                                                                //...downlink ip and control plane teid.

                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipControl = newKey.ip_dst;

                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser = sGsnIpV4UserAddr;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUserV6[0] = 0x0;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUserV6[1] = 0x0;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUserV6[2] = 0x0;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUserV6[3] = 0x0;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId =  sessionIdControlHashTableIPV4GTPV2[ret].sessionId;;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->dataTeid  =  dataTeid;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->controlTeid  =  sessionIdControlHashTableIPV4GTPV2[ret].controlTeid;
                                                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag = ADD_BEARER_GTPV2_SESSION ;

                                                                                                ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV4ControlHashObjectArray[lcore_id][objCount]);


												//calculateTimeStamp (&currentTime);
                                                        					//printf ("sks:enque done ring %s, ring count=%u time=0x%x.0x%x\n", pControlRing->name, rte_ring_count (pControlRing),currentTime.tv_sec, currentTime.tv_usec);

                                                                                                if (ret != 0 )
                                                                                                        printf ("error in enqueuing to sessionIdRing\n");
                                                                                                lteAppendage.gtpSessionId = pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId ;
                                                                                                rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                                                                //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                                                                lte_send_packet(m,2);
                                                                                                gtpStats.gtpV2IpV4CtrlPkt++;
                                                                                                return Aok;

                                                                                                }
                                                                                        }
                                                                                else
                                                                                        {
                                                                                        pGtpParser += sizeof (uint8_t);
                                                                                        octets++;
                                                                                        bearerLen--;
                                                                                        fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                        pGtpParser += (fwdLen +3)* sizeof(uint8_t);
                                                                                        octets += fwdLen + 3;
                                                                                        bearerLen -= fwdLen + 3;
                                                                                        }

                                                                                }
                                                                         //printf ("came out of bearerlen loop with dataTeid=0x%x\n", dataTeid);
                                                                         }
                                                                 else
                                                                         {
                                                                         pGtpParser += sizeof (uint8_t);
                                                                         octets++;
                                                                         fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                         pGtpParser += (fwdLen +3)* sizeof(uint8_t);
                                                                         octets += fwdLen + 3;
                                                                         }
                                                                }

                                                        }
                                                else
                                                        {
                                                        //...too early, start a timer and wait.
                                                        if (repeatCount == 0 )
                                                                {
								calculateTimeStamp (&currentTime);
                                                                printf ("sks:time=0x%x.0x%x init timer case 1...\n", currentTime.tv_sec, currentTime.tv_usec);
                                                                struct rte_timer * pUserPlaneTimer;
                                                                pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                                                int resetReturn = 0;
                                                                rte_timer_init (pUserPlaneTimer);
                                                                printf ("sks: timer reset...\n");
                                                                lcore_id = rte_lcore_id ();
                                                                resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                                                printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                                                return Nok;
                                                                }
                                                        if (repeatCount == 1)
                                                                {
								calculateTimeStamp (&currentTime);
                                                                //...orphan pkt, update stats and discard.
                                                                printf ("sks: hash entry not there, discarding bearer msg time=0x%x.0x%x\n", currentTime.tv_sec, currentTime.tv_usec);
								gtpStats.gtpV2IpV4ControlPktDiscards++;
                                                                return Aok;
                                                                }
                                                        }

                                                break;
                                                case GTPV2_CREATE_SESSION_RESPONSE   :  //...intentional fall-thru
                                                case GTPV2_CREATE_SESSION_REQUEST    :
                                                printf ("sks: got ipv4 gtpv2 create request\n");
                                                if (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTPV2_TEID_PRESENT)
                                                        {
                                                        printf ("sks: gtpv2 create req/resp TEID is present\n");
                                                        pGtpV2Header = (struct GtpV2Header *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header) );
                                                        }
                                                else
                                                        {
                                                        pGtpV2Header = (struct GtpV2Header_noTeid *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
                                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header_noTeid) );

                                                        }
                                                octets = 1;
						sGsnIpV4ControlAddr=0x0;
                                                printf ("sks: ipv4 gtpv2 pkt len=0x%x\n", (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x0000FFFF));
                                                while ((octets < (int)(rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x0000FFFF))&& (sGsnIpV4ControlAddr == 0))
                                                        {
                                                        gtpType = (int)(*pGtpParser);
                                                        //printf ("sks: gtpV2type=0x%x\n", gtpType);
                                                        if (gtpType == GTPV2_TYPE_FTEID)
                                                                {
                                                                pGtpParser += sizeof (uint8_t);
                                                                octets++;
                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                pGtpParser +=(4*sizeof(uint8_t)); //2 octets for len and 2 octets for CR flag, instance and ipv4/v6 flag
                                                                octets+=4;
                                                                controlTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //teid/gre key

                                                                //      ...assume it is a ipv6 addr because the ethernet header says so.
                                                                //      ...potential land mine, if session is shared between two interfaces, one a v4 and the other a v6
                                                                //      ...and if the ethernet header says ipv6 but the ipv4 sgsn appears first in the gtp payload we are hosed.
                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                octets+=4;
                                                                sGsnIpV4ControlAddr =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                octets+=4;
                                                                printf ("sks: SGSNAddr = 0x%x, teid=0x%x\n",
                                                                sGsnIpV4ControlAddr, controlTeid);
                                                                }
                                                        else
                                                                {
                                                                pGtpParser += sizeof (uint8_t);
                                                                octets++;
                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                pGtpParser += (fwdLen +3)* sizeof(uint8_t);
                                                                octets += fwdLen + 3;
                                                                }
                                                        }
                                                //Check for duplicate
                                                union ipv4_3tuple_host dupKey;
                                                bzero (&dupKey, sizeof(dupKey));
                                                dupKey.ip_dst = sGsnIpV4ControlAddr;
                                                dupKey.teid   = controlTeid;
                                                ret = rte_hash_lookup(pSessionIdV4GtpV2ControlHashTable, (const void *)&dupKey);

                                                if (ret > 0)
                                                        {
                                                        //it is a duplicate, append sessionId and tx out
                                                        pSessionIdObjGtpV2 = & sessionIdControlHashTableIPV4GTPV2[ret];
                                                        lteAppendage.gtpSessionId = pSessionIdObjGtpV2->sessionId;
                                                        printf ("detected duplicate pdp request, ready to send out pkt...\n");
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO - All done, transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        gtpStats.gtpV2IpV4CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                        }
                                                else
                                                        {
                                                        //create  a new entry in hash table
                                                        //cleanup hash object array first
                                                        lcore_id = rte_lcore_id();
                                                        socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );
                                                        rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",
                                                                        socketid,
                                                                        lcore_id);

                                                        pControlRing = rte_ring_lookup (name);
                                                        if (pControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                 for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIpV4ControlHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIpV4ControlHashObjectArray[lcore_id][i]);
                                                                                pIpV4ControlHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }
                                                        //Add a hash entry for control DOWN TEID
                                                        while (pIpV4ControlHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }

                                                        pIpV4ControlHashObjectArray[lcore_id][objCount] = (struct sessionIdIpV4HashObject *) rte_malloc ("hash object array",sizeof(struct sessionIdIpV4HashObject),0);
                                                        //...downlink ip and control plane teid.

                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->ipControl      = sGsnIpV4ControlAddr;

                                                        if ((sGsnIpV4UserAddr == 0))
                                                                {
                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser = sGsnIpV4ControlAddr;
                                                                }
                                                        else
                                                                {
                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->ipUser = sGsnIpV4UserAddr;
                                                                }

                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->controlTeid    = controlTeid;
                                                        dataTeid                                                        = 0;
                                                        if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000) == GTPV2_CREATE_SESSION_RESPONSE )
                                                                {
                                                       		dupKey.ip_dst = rte_cpu_to_be_32(key.ip_dst);
                                                        	dupKey.teid = rte_cpu_to_be_32(key.teid);
								printf ("sks: ip=0x%x, teid=0x%x\n", dupKey.ip_dst,dupKey.teid);
                                                        	ret = rte_hash_lookup(pSessionIdV4GtpV2ControlHashTable, (const void *)&dupKey);
                                                        	if (ret > 0)
                                                                	{
									createReqSessionId = sessionIdControlHashTableIPV4GTPV2[ret].sessionId;
									}
                                                        	else
                                                                	{
                                                                	if (repeatCount == 0 )
                                                                        	{
                                                                        	printf ("sks:init timer case 6...\n");
                                                                        	struct rte_timer * pUserPlaneTimer;
                                                                        	pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                                                        	int resetReturn = 0;
                                                                        	rte_timer_init (pUserPlaneTimer);
                                                                        	printf ("sks: timer reset...\n");
                                                                        	lcore_id = rte_lcore_id ();
                                                                        	resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pktRetryTimerCb,(void *)m);
                                                                        	printf ("sks: returning nok resetReturn=%d...\n", resetReturn);
                                                                        	return Nok;
                                                                        	}
									
                                                                	if (repeatCount == 1)
                                                                        	{
                                                                        	gtpStats.gtpV2CtrlPktDiscards++;
                                                                        	return Aok;
										}
									}	
                                                                //...in gtpv2 only the create session response msg has the userplane teid in the bearer create msg
                                                                //...parse this from where we left off earlier.
                                                                while (((octets < (int)(rte_cpu_to_be_32(key.flagsMsgTypeAndLen)))) && (dataTeid == 0))
                                                                        {
                                                                        gtpType = (int)(*pGtpParser);
                                                                        //printf ("sks: create session response gtpV2type=0x%x\n", gtpType);
                                                                        if (gtpType ==GTPV2_TYPE_BEARER_CONTEXT)
                                                                                {
                                                                                pGtpParser += sizeof(uint8_t);
                                                                                octets++;
                                                                                int bearerLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                //printf ("sks:bearerlen %d\n", bearerLen);
                                                                                //jump over 3 octets - 2 octets for length and 1 octet for spare and instance
                                                                                pGtpParser +=(3*sizeof(uint8_t));
                                                                                octets += 3;
                                                                                while (bearerLen > 0)
                                                                                        {
                                                                                        gtpType = (int)(*pGtpParser);
                                                                                        //printf ("bearer context type = 0x%x\n", gtpType);
                                                                                        if (gtpType == GTPV2_TYPE_FTEID)
                                                                                                {
                                                                                                printf ("sks: fteid in bearer request found\n");

                                                                                                pGtpParser += sizeof (uint8_t);
                                                                                                octets++;
                                                                                                bearerLen--;
                                                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                                pGtpParser +=(4*sizeof(uint8_t)); //2 octets for len and 2 octets for CR flag, instance and ipv4/v6 flag
                                                                                                octets+=4;
                                                                                                bearerLen -=4;
                                                                                                dataTeid = rte_cpu_to_be_32(*((uint32_t *)pGtpParser)); //only get teid/gre key
                                                                                                pGtpParser += 4*sizeof(uint8_t);
                                                                                                octets+=4;
                                                                                                bearerLen -=4;
                                                                                                }
                                                                                        else
                                                                                                {
                                                                                                pGtpParser += sizeof (uint8_t);
                                                                                                octets++;
                                                                                                bearerLen--;
                                                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                                pGtpParser += (fwdLen +3)* sizeof(uint8_t);
                                                                                                octets += fwdLen + 3;
                                                                                                bearerLen -= fwdLen + 3;
                                                                                                }
                                                                                        }
                                                                                //printf ("came out of bearerlen loop with dataTeid=0x%x\n", dataTeid);
                                                                                }
                                                                         else
                                                                                {
                                                                                pGtpParser += sizeof (uint8_t);
                                                                                octets++;
                                                                                fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                                                                                pGtpParser += (fwdLen +3)* sizeof(uint8_t);
                                                                                octets += fwdLen + 3;
                                                                                }

                                                                        }
                                                                }
                                                        //printf ("sks: gtpV2, user teid=0x%x\n", dataTeid);
                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->dataTeid       = dataTeid;
                                                        if (createReqSessionId != 0 )
                                                                {
                                                                pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId      = createReqSessionId;
                                                                createReqSessionId = 0;
                                                                }
							else
								{
 								printf ("sks: generating globalSessionId =0x%x\n", globalSessionId);
                                                        	pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId      = globalSessionId++;
								}

                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->addDeleteFlag  = ADD_GTPV2_SESSION;

                                                        if ((key.teid != 0) && (((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000)== GTPV2_CREATE_SESSION_REQUEST)))
                                                                {
                                                                //Handle the case of creation of a secondary context by the MS
                                                                union ipv4_3tuple_host secKey;
                                                                bzero (&secKey, sizeof(secKey));
                                                                secKey.ip_src = sGsnIpV4ControlAddr;
                                                                secKey.teid      = rte_cpu_to_be_32(key.teid);
                                                                ret = rte_hash_lookup(pSessionIdV4GtpV2ControlHashTable, (const void *)&secKey);
                                                                if (ret > 0 )
                                                                        {
                                                                        //...session exists, extract sessionId
                                                                        pSessionIdObjGtpV2 = &sessionIdControlHashTableIPV4GTPV2[ret];
                                                                        pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId = pSessionIdObjGtpV2->sessionId;
                                                                        }
                                                                }

                                                        ret = rte_ring_mp_enqueue (pControlRing, (void *)pIpV4ControlHashObjectArray[lcore_id][objCount]);


							//calculateTimeStamp (&currentTime);
                                       			//printf ("sks:enque done ring %s, ring count=%u time=0x%x.0x%x\n", pControlRing->name, rte_ring_count (pControlRing),currentTime.tv_sec, currentTime.tv_usec);

                                                        if (ret != 0 )
                                                                printf ("error in enqueuing to sessionIdRing\n");
                                                        lteAppendage.gtpSessionId = pIpV4ControlHashObjectArray[lcore_id][objCount]->sessionId;
                                                        rte_memcpy(pLteAppendage, &lteAppendage,sizeof(struct LteInfoAppend) );
                                                        //TODO -All done transmit it out right here if possible, since i/f number is avail (pSessionIdObj->intf)
                                                        gtpStats.gtpV2IpV4CtrlPkt++;
							lte_send_packet (m, 2);
							return Aok;
                                                        }
                                                break;
                                                }

                                        }

                                } //control plane if statement
                        }//ipv4 if statement

	return Aok;
}

/* main processing loop */
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned lcore_id;
	uint64_t prev_tsc, prev_tsc_timer,diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	//...Initialize the time, so that the timestamp calculation will work
	gettimeofday(&start_time, NULL);
        start_cycles = rte_get_timer_cycles();
        hz = rte_get_timer_hz();
	prev_tsc = 0;
	prev_tsc_timer = 0;
	timer_tsc = 0;
	globalSessionId = 0x01;

        /* init RTE timer library */
        rte_timer_subsystem_init();

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	//...Initialize nDPI module
 	setupDetection (lcore_id);

	//...setup locks
	

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}
	createUserAndControlRings ( );

	//...clear out gtp statistics
	//
        gtpStats.gtpV1IpV4CtrlPkt		= 0x0;
        gtpStats.gtpV1V2IpV4UserPkt		= 0x0;
        gtpStats.gtpV2IpV4CtrlPkt		= 0x0;
        gtpStats.gtpV1IpV6CtrlPkt		= 0x0;
        gtpStats.gtpV1V2IpV6UserPkt		= 0x0;
        gtpStats.gtpV1V2IpV6UserPktFragment	= 0x0;
        gtpStats.gtpV1V2IpV4UserPktFragmentDiscards	= 0x0;
        gtpStats.gtpV1V2IpV6UserPktFragmentDiscards	= 0x0;
        gtpStats.gtpV2IpV6CtrlPkt		= 0x0;
        gtpStats.gtpV1V2IpV6UserPktDiscards	= 0x0;
        gtpStats.gtpV1V2IpV4UserPktDiscards	= 0x0;
        gtpStats.gtpV1IpV6ControlPktDiscards	= 0x0;
        gtpStats.gtpV2IpV6ControlPktDiscards	= 0x0;
        gtpStats.gtpV1IpV4ControlPktDiscards	= 0x0;
        gtpStats.gtpV2IpV4ControlPktDiscards	= 0x0;


	while (1) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc_timer;
                if (diff_tsc > TIMER_RESOLUTION_CYCLES) 
			{
                        rte_timer_manage();
			prev_tsc_timer = cur_tsc;
			}

		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
/*sks_remove
			for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				l2fwd_send_burst(&lcore_queue_conf[lcore_id],
						 qconf->tx_mbufs[portid].len,
						 (uint8_t) portid);
				qconf->tx_mbufs[portid].len = 0;
			}
*/
			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= (uint64_t) timer_period)) {
					/* do this only on master core */
					if (lcore_id == rte_get_master_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
						 pkts_burst, MAX_PKT_BURST);
			port_statistics[portid].rx += nb_rx;
			
			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				//...	l2fwd_simple_forward(m, portid);
				if (segregateControlAndUserTraffic (m,0) == Aok )
					{
					rte_pktmbuf_free (m);//free for now, but later tx and free.
					}

			}
		}
	}
}

/*retry timer callback.  need this since timercb in dpdk currently supports only one arg
 * and the segregate function takes 2 args since we need to know how we are calling
 * segregate (thru the nic rx or thru the cb, else we will be stuck in a forever loop
 * of retrying*/

static void pktRetryTimerCb (__attribute__((unused)) struct rte_timer *tim,
                            __attribute__((unused)) void *pkt)
        {
	//printf ("SKS:  timer cb  called\n");
        segregateControlAndUserTraffic (pkt, 1);
	rte_pktmbuf_free ((struct rte_mbuf *)pkt);
	rte_free (tim);
        }

static inline uint32_t
sessionId_hash_crc(const void *data, __rte_unused uint32_t data_len,
        uint32_t init_val)
{
        const union sessionId_2tuple_host *k1;

        k1 = data;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        init_val = rte_hash_crc_4byte(k1->sessionId, init_val);
        init_val = rte_hash_crc_4byte(k1->msgType, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        //init_val = rte_jhash_1word(k1->ip_src, init_val);
        init_val = rte_jhash_1word(k1->sessionId, init_val);
        init_val = rte_jhash_1word(k1->msgType, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        return (init_val);
}

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
        uint32_t init_val)
{
        const union ipv4_3tuple_host *k1;

        k1 = data;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        //init_val = rte_hash_crc_4byte(k1->ip_src, init_val);
        init_val = rte_hash_crc_4byte(k1->ip_dst, init_val);
        init_val = rte_hash_crc_4byte(k1->teid, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        //init_val = rte_jhash_1word(k1->ip_src, init_val);
        init_val = rte_jhash_1word(k1->ip_dst, init_val);
        init_val = rte_jhash_1word(k1->teid, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        return (init_val);
}

static inline uint32_t
ipv4_hash_fragId(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
	
	const union ipv4_2tuple_host *k1;
	k1 = data;
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        init_val = rte_hash_crc_4byte(k1->fragId, init_val);
        init_val = rte_hash_crc_4byte(k1->ip_addr, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        init_val = rte_jhash_1word(k1->fragId, init_val);
        init_val = rte_jhash_1word(k1->ip_addr, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        return (init_val);


}

static inline uint32_t
ipv6_hash_crc(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
        const union ipv6_3tuple_host *k;
        uint32_t t;
        const uint32_t *p;
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
//        const uint32_t  *ip_src0, *ip_src1, *ip_src2, *ip_src3;
        const uint32_t  *ip_dst0, *ip_dst1, *ip_dst2, *ip_dst3;
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

        k = data;
        t = 17;//sks - hardcode it for now - it is always going to be udp
        p = (const uint32_t *)&k->teid;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        //ip_src0 = (const uint32_t *) k->ip_src;
        //ip_src1 = (const uint32_t *)(k->ip_src+4);
        //ip_src2 = (const uint32_t *)(k->ip_src+8);
        //ip_src3 = (const uint32_t *)(k->ip_src+12);
        ip_dst0 = (const uint32_t *) k->ip_dst;
        ip_dst1 = (const uint32_t *)(k->ip_dst+1);
        ip_dst2 = (const uint32_t *)(k->ip_dst+2);
        ip_dst3 = (const uint32_t *)(k->ip_dst+3);
        init_val = rte_hash_crc_4byte(t, init_val);
        //init_val = rte_hash_crc_4byte(*ip_src0, init_val);
        //init_val = rte_hash_crc_4byte(*ip_src1, init_val);
        //init_val = rte_hash_crc_4byte(*ip_src2, init_val);
        //init_val = rte_hash_crc_4byte(*ip_src3, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst0, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst1, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst2, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst3, init_val);
        init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        init_val = rte_jhash_1word(t, init_val);
        init_val = rte_jhash(k->ip_src, sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
        init_val = rte_jhash(k->ip_dst, sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
        init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        return (init_val);
}
static inline uint32_t
ipv6_hash_fragId(const void *data, __rte_unused uint32_t data_len, uint32_t init_val)
{
        const union ipv6_2tuple_host *k;
        uint32_t t;
        const uint32_t *p;
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
//        const uint32_t  *ip_src0, *ip_src1, *ip_src2, *ip_src3;
        const uint32_t  *ip_dst0, *ip_dst1, *ip_dst2, *ip_dst3;
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

        k = data;
        t = 17;//sks - hardcode it for now - it is always going to be udp
        p = (const uint32_t *)&k->fragId;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
        ip_dst0 = (const uint32_t *) k->ip_addr;
        ip_dst1 = (const uint32_t *)(k->ip_addr+1);
        ip_dst2 = (const uint32_t *)(k->ip_addr+2);
        ip_dst3 = (const uint32_t *)(k->ip_addr+3);
        init_val = rte_hash_crc_4byte(t, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst0, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst1, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst2, init_val);
        init_val = rte_hash_crc_4byte(*ip_dst3, init_val);
        init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        init_val = rte_jhash_1word(t, init_val);
        init_val = rte_jhash(k->ip_addr, sizeof(uint32_t) * IPV6_ADDR_LEN, init_val);
        init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
        return (init_val);
}

void writeCSVFile ( int );

void writeCSVFile ( int loc )
        {
        FILE  *fd;
        fd = fopen ( "/home/sks/idr.csv", "a+");
        if (fd == NULL)
                {
                printf ("Cannot open file /home/sks/idr.csv\n");
                return;
                }
        printf ("writeCSVFile !!!!\n");

        fprintf ( fd, "%u,%u,%u,%u,%u,%u,%u,%u:%u:%u:%u,%u:%u:%u:%u,%u,%u,%#" PRIx64 ",%u,%s,%u,%s,%u,%u,%u,%s,%u,%u\n",
        ctrlIdrHashTable[loc].startmSecs,
        ctrlIdrHashTable[loc].startuSecs,
        ctrlIdrHashTable[loc].endmSecs,
        ctrlIdrHashTable[loc].enduSecs,
        ctrlIdrHashTable[loc].ifType,
        ctrlIdrHashTable[loc].srcIp,
        ctrlIdrHashTable[loc].dstIp,
        ctrlIdrHashTable[loc].srcIpV6[0],
        ctrlIdrHashTable[loc].srcIpV6[1],
        ctrlIdrHashTable[loc].srcIpV6[2],
        ctrlIdrHashTable[loc].srcIpV6[3],
        ctrlIdrHashTable[loc].dstIpV6[0],
        ctrlIdrHashTable[loc].dstIpV6[1],
        ctrlIdrHashTable[loc].dstIpV6[2],
        ctrlIdrHashTable[loc].dstIpV6[3],
        ctrlIdrHashTable[loc].srcPort,
        ctrlIdrHashTable[loc].dstPort,
        ctrlIdrHashTable[loc].imsi,
        ctrlIdrHashTable[loc].imeisv,
        ctrlIdrHashTable[loc].msisdn,
        ctrlIdrHashTable[loc].pTMSI,
        ctrlIdrHashTable[loc].apn,
        ctrlIdrHashTable[loc].uli,
        ctrlIdrHashTable[loc].rat,
        ctrlIdrHashTable[loc].gtpVersion,
        ctrlIdrHashTable[loc].direction,
        ctrlIdrHashTable[loc].causeCode,
        ctrlIdrHashTable[loc].timeoutIndicator
        );

        fclose (fd);
        }


static void
sessionIdHashTableMaint ( void )
	{
	char name[32];
        struct rte_ring * pControlRing = NULL;
        struct rte_ring * pControlRingV6 = NULL;
        struct rte_ring * pFragRing = NULL;
        struct rte_ring * pIdrRing = NULL;
        struct sessionIdIpV4HashObject *pHashObject = NULL;
        struct sessionIdIpV6HashObject *pHashObjectV6 = NULL;
        struct fragIdHashObject *pFragIdHashObject = NULL;
        struct idrHashObject *pIdrHashObject = NULL;
        void * pTest[20];
        int ret;
        int lcore_id=0x01;
        union ipv4_3tuple_host  key;
        union ipv6_3tuple_host  keyV6;
	struct gtpV2IpBearerList	*pBearer = NULL;
        union ipv4_2tuple_host fragKeyV4;
        union ipv6_2tuple_host fragKeyV6;
        union sessionId_2tuple_host sessionIdKey;
	struct timeval currentTime;

	//...init the globalsessionid and i/f
	lastInterfaceUsed = 2;

        struct rte_hash_parameters ipv4FragIdHashTblParams = {
        .name = NULL,
        .entries = SESSION_HASH_ENTRIES,
        .bucket_entries = 4,
        .key_len = sizeof(union ipv4_2tuple_host),
        .hash_func = ipv4_hash_fragId,
        .hash_func_init_val = 0,
        };

        struct rte_hash_parameters ipv6FragIdHashTblParams = {
        .name = NULL,
        .entries = SESSION_HASH_ENTRIES,
        .bucket_entries = 4,
        .key_len = sizeof(union ipv6_2tuple_host),
        .hash_func = ipv6_hash_fragId,
        .hash_func_init_val = 0,
        };


    	struct rte_hash_parameters ipV4SessionIdHashParams = {
        .name = NULL,
        .entries = SESSION_HASH_ENTRIES,
        .bucket_entries = 4,
        .key_len = sizeof(union ipv4_3tuple_host),
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
    	};

        struct rte_hash_parameters controlIdrHashTblParams = {
        .name = NULL,
        .entries = SESSION_HASH_ENTRIES,
        .bucket_entries = 4,
        .key_len = sizeof(union sessionId_2tuple_host),
        .hash_func = sessionId_hash_crc,
        .hash_func_init_val = 0,
        };
	
	int socketid;

    	struct rte_hash_parameters ipV6SessionIdHashParams = {
        .name = NULL,
        .entries = SESSION_HASH_ENTRIES,
        .bucket_entries = 4,
        .key_len = sizeof(union ipv6_3tuple_host),
        .hash_func = ipv6_hash_crc,
        .hash_func_init_val = 0,
    	};

    	char s[64];
	socketid = rte_lcore_to_socket_id(rte_lcore_id() );

	/*create a fragId table*/
        rte_snprintf(s, sizeof(s), "ipv4FragIdHashTable_%d", socketid);
        ipv4FragIdHashTblParams.name = s;
        ipv4FragIdHashTblParams.socket_id = socketid;
        pIpV4FragIdHashTable = rte_hash_create(&ipv4FragIdHashTblParams);
        if (pIpV4FragIdHashTable == NULL)
                {
                printf (" hash table is NULL !!!, exiting\n");
                rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", socketid);
                }

        rte_snprintf(s, sizeof(s), "ipv6FragIdHashTable_%d", socketid);
        ipv6FragIdHashTblParams.name = s;
        ipv6FragIdHashTblParams.socket_id = socketid;
        pIpV6FragIdHashTable = rte_hash_create(&ipv6FragIdHashTblParams);
        if (pIpV6FragIdHashTable == NULL)
                {
                printf (" hash table is NULL !!!, exiting\n");
                rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", socketid);
                }

	
	/* create ipv4 control hash table */
	rte_snprintf(s, sizeof(s), "ipv4_sessionIdControl_hash_%d", socketid);
	ipV4SessionIdHashParams.name = s;
	ipV4SessionIdHashParams.socket_id = socketid;
	pSessionIdV4ControlHashTable = rte_hash_create(&ipV4SessionIdHashParams);
	if (pSessionIdV4ControlHashTable == NULL)
		{
		printf (" hash table is NULL !!!, exiting\n");
		rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
				"socket %d\n", socketid);
		}

        rte_snprintf(s, sizeof(s), "ipv4_gtpV2_sessionIdControl_hash_%d", socketid);
        ipV4SessionIdHashParams.name = s;
        ipV4SessionIdHashParams.socket_id = socketid;
        pSessionIdV4GtpV2ControlHashTable = rte_hash_create(&ipV4SessionIdHashParams);
        if (pSessionIdV4ControlHashTable == NULL)
                {
                printf (" hash table is NULL !!!, exiting\n");
                rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", socketid);
                }


        /* create ipv6 control hash table */
        rte_snprintf(s, sizeof(s), "ipv6_sessionIdControl_hash_%d", socketid);
        ipV6SessionIdHashParams.name = s;
        ipV6SessionIdHashParams.socket_id = socketid;
        pSessionIdV6ControlHashTable = rte_hash_create(&ipV6SessionIdHashParams);
        if (pSessionIdV6ControlHashTable == NULL)
                {
                printf (" hash table is NULL !!!, exiting\n");
                rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", socketid);
                }

        rte_snprintf(s, sizeof(s), "ipv6_gtpV2_sessionIdControl_hash_%d", socketid);
        ipV6SessionIdHashParams.name = s;
        ipV6SessionIdHashParams.socket_id = socketid;
        pSessionIdV6GtpV2ControlHashTable = rte_hash_create(&ipV6SessionIdHashParams);
        if (pSessionIdV6ControlHashTable == NULL)
                {
                printf (" hash table is NULL !!!, exiting\n");
                rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", socketid);
                }

	/* create ipv4 user hash table */
        rte_snprintf(s, sizeof(s), "ipv4_sessionIdUser_hash_%d", socketid);
        ipV4SessionIdHashParams.name = s;
        ipV4SessionIdHashParams.socket_id = socketid;
        pSessionIdV4UserHashTable = rte_hash_create(&ipV4SessionIdHashParams);
        if (pSessionIdV4UserHashTable == NULL)
                {
                printf (" hash table is NULL !!!, exiting\n");
                rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", socketid);
                }

        /* create ipv6 user hash table */
        rte_snprintf(s, sizeof(s), "ipv6_sessionIdUser_hash_%d", socketid);
        ipV6SessionIdHashParams.name = s;
        ipV6SessionIdHashParams.socket_id = socketid;
        pSessionIdV6UserHashTable = rte_hash_create(&ipV6SessionIdHashParams);
        if (pSessionIdV6UserHashTable == NULL)
                {
                printf (" hash table is NULL !!!, exiting\n");
                rte_exit(EXIT_FAILURE, "Unable to create %s the l3fwd hash on "
                                "socket %d\n", s, socketid);
                }
	/*create a control IDR table*/
        rte_snprintf(s, sizeof(s), "ControlIdrHashTable_%d", socketid);
        controlIdrHashTblParams.name = s;
        controlIdrHashTblParams.socket_id = socketid;
        pCtrlIdrHashTable = rte_hash_create(&controlIdrHashTblParams);
        if (pCtrlIdrHashTable == NULL)
                {
                printf (" control idr hash table is NULL !!!, exiting\n");
                rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
                                "socket %d\n", socketid);
                }


         bzero ( &key,sizeof(key));
         bzero ( &keyV6,sizeof(keyV6));

         socketid = rte_lcore_to_socket_id(lcore_id );
         rte_snprintf(name, sizeof(name), "sessionIdAddV4Control_ring%u_io%u_sId4",
                    socketid,
                    lcore_id);

         pControlRing = rte_ring_lookup (name);

         rte_snprintf(name, sizeof(name), "sessionIdAddV6Control_ring%u_io%u_sId4",
                    socketid,
                    lcore_id);

         pControlRingV6 = rte_ring_lookup (name);

	if (pControlRingV6 == NULL) { printf ("sks: v6 control RING is NULL!!!!\n");};

         rte_snprintf(name, sizeof(name), "FragId_ring%u_io%u_sId4",
                    socketid,
                    lcore_id);

         pFragRing = rte_ring_lookup (name);
	
	if (pFragRing == NULL) { printf ("sks: frag RING is NULL!!!!\n");};

        rte_snprintf(name, sizeof(name), "idrControlRing%u_io%u_sId4",
                                socketid,
                                lcore_id);

        pIdrRing = rte_ring_lookup (name);

	if (pIdrRing == NULL) { printf ("sks: idr RING is NULL!!!!\n");};
	int printIndex=0;

	while (1) 
		{
		if (pIdrRing != NULL )
			{
			ret = rte_ring_dequeue (pIdrRing, (void **)pTest);
			//calculateTimeStamp (&currentTime);
			if (ret == 0 )
				{
				pIdrHashObject = (struct idrHashObject *)pTest[0];
				//printf ("sks: ...........................pIdrRing dequeue successful ring count %d time 0x%x.0x%x\n", rte_ring_count (pIdrRing));
				if (pIdrHashObject )
					{
					bzero (&sessionIdKey, sizeof (sessionIdKey));	
					sessionIdKey.sessionId = pIdrHashObject->sessionId;
					sessionIdKey.msgType   = pIdrHashObject->msgType;
					//printf ("Maint:sks: key.sid=0x%x, key.mType=0x%x\n",sessionIdKey.sessionId,sessionIdKey.msgType);
					}
				ret = rte_hash_add_key (pCtrlIdrHashTable, &sessionIdKey);
				if (ret>0)
					{
					//printf ("Maint:sks: adding idr hash key for sId=0x%x, msgType=0x%x\n", sessionIdKey.sessionId,sessionIdKey.msgType);
					//...zero out the control idr before populating it
					if ((pIdrHashObject->origMsgType == GTP_PDP_CONTEXT_REQUEST)||(pIdrHashObject->origMsgType == GTP_PDP_UPDATE_REQUEST)||
					    (pIdrHashObject->origMsgType == GTP_PDP_DELETE_CONTEXT_REQUEST)||(pIdrHashObject->origMsgType == GTPV2_CREATE_SESSION_REQUEST) ||
					    (pIdrHashObject->origMsgType == GTPV2_TYPE_REL_ACC_BEARER_REQ)||(pIdrHashObject->origMsgType == GTPV2_TYPE_DEL_SESSION_REQ) ||
					    (pIdrHashObject->origMsgType == GTPV2_CREATE_BEARER_REQUEST)||(pIdrHashObject->origMsgType == GTPV2_MODIFY_BEARER_REQUEST)) 
						{
						//printf ("sks: Maint - storing hash object in hashtable for req msg\n");
						bzero (&ctrlIdrHashTable[ret],sizeof (struct controlIdr));
						ctrlIdrHashTable[ret].startmSecs = pIdrHashObject->secs;
						ctrlIdrHashTable[ret].startuSecs = pIdrHashObject->usecs;
						ctrlIdrHashTable[ret].srcIp 	 = pIdrHashObject->ipV4SrcAddr;
						ctrlIdrHashTable[ret].dstIp 	 = pIdrHashObject->ipV4DstAddr;
						ctrlIdrHashTable[ret].srcIpV6[0] = pIdrHashObject->ipV6SrcAddr[0];
						ctrlIdrHashTable[ret].srcIpV6[1] = pIdrHashObject->ipV6SrcAddr[1];
						ctrlIdrHashTable[ret].srcIpV6[2] = pIdrHashObject->ipV6SrcAddr[2];
						ctrlIdrHashTable[ret].srcIpV6[3] = pIdrHashObject->ipV6SrcAddr[3];
                                        	ctrlIdrHashTable[ret].dstIpV6[0] = pIdrHashObject->ipV6DstAddr[0];
                                        	ctrlIdrHashTable[ret].dstIpV6[1] = pIdrHashObject->ipV6DstAddr[1];
                                        	ctrlIdrHashTable[ret].dstIpV6[2] = pIdrHashObject->ipV6DstAddr[2];
                                        	ctrlIdrHashTable[ret].dstIpV6[3] = pIdrHashObject->ipV6DstAddr[3];
						}
					else
						{
						//printf ("sks: Maint - storing hash object in hashtable for resp msg\n");
                                                ctrlIdrHashTable[ret].endmSecs = pIdrHashObject->secs;
                                                ctrlIdrHashTable[ret].enduSecs = pIdrHashObject->usecs;
						}

					if (pIdrHashObject->imsi != 0 )
                                        	ctrlIdrHashTable[ret].imsi	 = pIdrHashObject->imsi;
					if (pIdrHashObject->imeisv != 0 )
                                        	ctrlIdrHashTable[ret].imeisv	 = pIdrHashObject->imeisv;
					if (pIdrHashObject->msip != 0 )
                                        	ctrlIdrHashTable[ret].msip	 = pIdrHashObject->msip;
                                        if (pIdrHashObject->pTMSI != 0 )
                                                ctrlIdrHashTable[ret].pTMSI      = pIdrHashObject->pTMSI;
					
					if (pIdrHashObject->apn[0]!='\0')
						rte_snprintf (ctrlIdrHashTable[ret].apn,sizeof(pIdrHashObject->apn), "%s", pIdrHashObject->apn);
					if (pIdrHashObject->msisdn[0]!='\0')
						rte_snprintf (ctrlIdrHashTable[ret].msisdn,sizeof(pIdrHashObject->msisdn), "%s", pIdrHashObject->msisdn);

                                        if (pIdrHashObject->uli != 0 )
                                                ctrlIdrHashTable[ret].uli        = pIdrHashObject->uli;
                                        if (pIdrHashObject->rat != 0 )
                                                ctrlIdrHashTable[ret].rat        = pIdrHashObject->rat;
                                        if (pIdrHashObject->gtpVersion != 0 )
                                                ctrlIdrHashTable[ret].gtpVersion = pIdrHashObject->gtpVersion;


                                        }
				else
					{
					printf ( "Unable to create control Idr HashTable entry\n");
					}

				}
			else
				{
	/*			printIndex++;
				if ((printIndex %100000000) == 0)
					{
					printf ("sks: ctrlIdrHashTable[406168] contents...0x%x,0x%x\n", ctrlIdrHashTable[406168].startmSecs,ctrlIdrHashTable[406168].startuSecs );
					}*/

				}
			}

		if (pFragRing != NULL)
			{
		        //...ring exists, continue
                        //rte_ring_dump(pControlRing);
                        ret = rte_ring_dequeue ( pFragRing, (void **)pTest);
                        pFragIdHashObject = NULL;
                        if (ret == 0 )
                                {
                                printf ("sks:dequeue successful ring count %d\n", rte_ring_count (pFragRing));
                                pFragIdHashObject = (struct fragIdHashObject *)pTest[0];
                                }
                        if (pFragIdHashObject )
				{
			        if (pFragIdHashObject->ipV4DstAddr == 0x0)
					{
					//...it is an ipv6 fragment
					bzero ( &fragKeyV6, sizeof (fragKeyV6));
					fragKeyV6.fragId = pFragIdHashObject->fragId;
					fragKeyV6.ip_addr[0] = pFragIdHashObject->ipV6DstAddr[0];
					fragKeyV6.ip_addr[1] = pFragIdHashObject->ipV6DstAddr[1];
					fragKeyV6.ip_addr[2] = pFragIdHashObject->ipV6DstAddr[2];
					fragKeyV6.ip_addr[3] = pFragIdHashObject->ipV6DstAddr[3];

                                        ret = rte_hash_add_key (pIpV6FragIdHashTable, &keyV6);
					if (ret > 0)
						{
						ipV6fragIdHashTable[ret].fragId = fragKeyV6.fragId;
						ipV6fragIdHashTable[ret].sessionId = pFragIdHashObject->sessionId;
						}
					else
						{
						printf ("cannot add entry to ipv6 fragment table\n");
						}
					}
				else
					{
					//it is an ipv4 fragment
                                        bzero ( &fragKeyV4, sizeof (fragKeyV4));
                                        fragKeyV4.fragId = pFragIdHashObject->fragId;
                                        fragKeyV4.ip_addr = pFragIdHashObject->ipV4DstAddr;

                                        ret = rte_hash_add_key (pIpV4FragIdHashTable, &fragKeyV4);
                                        if (ret > 0)
                                                {
                                                ipV4fragIdHashTable[ret].fragId = fragKeyV4.fragId;
                                                ipV4fragIdHashTable[ret].sessionId = pFragIdHashObject->sessionId;
                                                }
                                        else
                                                {
                                                printf ("cannot add entry to ipv4 fragment table\n");
                                                }
					}	
				}
			}

		if (pControlRing != NULL )
			{
			//...ring exists, continue
			//rte_ring_dump(pControlRing);
			//calculateTimeStamp(&currentTime);
			ret = rte_ring_dequeue ( pControlRing, (void **)pTest);
			pHashObject = NULL;
			if (ret == 0 )
				{
				printf ("sks: ...........................pControlRing dequeue successful ring count %d time 0x%x.0x%x\n", rte_ring_count (pControlRing));
				pHashObject = (struct sessionIdIpV4HashObject *)pTest[0];
				printf ("sks:addDeleteFlag = 0x%x\n", (int)(pHashObject->addDeleteFlag));
				}
			if (pHashObject )
				{
                                if ((int)(pHashObject->addDeleteFlag) == ADD_BEARER_GTPV2_SESSION)
                                        {
                                        key.ip_dst = pHashObject->ipControl;
                                        key.teid   = pHashObject->controlTeid;
                                        ret = rte_hash_lookup (pSessionIdV4GtpV2ControlHashTable, &key);

                                        if (ret < 0 )
                                                {
                                                printf ("sks: no session established for bearer update\n");
                                                }
                                        if (ret > 0 )
                                                {
                                                if (pHashObject->ipUser == 0x0)
                                                        {
                                                        //...ipv6 bearer
                                                        if (pHashObject->dataTeid)
                                                                {
                                                                if (sessionIdControlHashTableIPV4GTPV2[ret].pBearerList != NULL )
                                                                        {
                                                                        struct gtpV2IpBearerList *pBearer;
                                                                        pBearer = sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->pNextBearer;

                                                                        while (pBearer != NULL )
                                                                                {
                                                                                //...keep going till end of the list
                                                                                pBearer = pBearer->pNextBearer;
                                                                                }

                                                                        pBearer = (struct gtpV2IpBearerList *) rte_malloc ("bearerLst",sizeof (struct gtpV2IpBearerList ),0);
                                                                        if (pBearer != NULL)
                                                                                {
                                                                                pBearer->pNextBearer = NULL;
                                                                                pBearer->ipV4User = 0x0;
                                                                                pBearer->ipV6User[0]=pHashObject->ipUserV6[0];
                                                                                pBearer->ipV6User[1]=pHashObject->ipUserV6[1];
                                                                                pBearer->ipV6User[2]=pHashObject->ipUserV6[2];
                                                                                pBearer->ipV6User[3]=pHashObject->ipUserV6[3];
                                                                                pBearer->userTeid   =pHashObject->dataTeid;
                                                                                }
                                                                        else
                                                                                {
                                                                                printf ("sks: cannot allocate bearer \n");
                                                                                }
                                                                        }
                                                                //...add it to the userplane hashtable first and then to the bearer list in the control plane hashtable.
                                                                keyV6.teid = pHashObject->dataTeid;
                                                                keyV6.ip_dst[0] = pHashObject->ipUserV6[0];

                                                                keyV6.ip_dst[1] = pHashObject->ipUserV6[1];
                                                                keyV6.ip_dst[2] = pHashObject->ipUserV6[2];
                                                                keyV6.ip_dst[3] = pHashObject->ipUserV6[3];
                                                                /*printf ("sks adding UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                                key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);*/
                                                                ret = rte_hash_add_key (pSessionIdV6UserHashTable, &keyV6);
                                                                if (ret > 0 )
                                                                        {
                                                                        sessionIdUserHashTableIPV6[ret].ipUserV6[0] = pHashObject->ipUserV6[0];
                                                                        sessionIdUserHashTableIPV6[ret].ipUserV6[1] = pHashObject->ipUserV6[1];
                                                                        sessionIdUserHashTableIPV6[ret].ipUserV6[2] = pHashObject->ipUserV6[2];
                                                                        sessionIdUserHashTableIPV6[ret].ipUserV6[3] = pHashObject->ipUserV6[3];
                                                                        sessionIdUserHashTableIPV6[ret].userTeid   = pHashObject->dataTeid;
                                                                        sessionIdUserHashTableIPV6[ret].sessionId = pHashObject->sessionId;
                                                                        sessionIdUserHashTableIPV6[ret].outputInterface = lastInterfaceUsed;
                                                                        }
                                                                else
                                                                        {
                                                                        printf ("cannot add key to user hash table\n");
                                                                        }
                                                                }

                                                        }
                                                else
                                                        {
                                                        //...ipv4 bearer

                                                        if (pHashObject->dataTeid)
                                                                {
                                                                if (sessionIdControlHashTableIPV4GTPV2[ret].pBearerList != NULL )
                                                                        {
                                                                        struct gtpV2IpBearerList *pBearer;
                                                                        pBearer = sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->pNextBearer;

                                                                        while (pBearer != NULL )
                                                                                {
                                                                                //...keep going till end of the list
                                                                                pBearer = pBearer->pNextBearer;
                                                                                }

                                                                        pBearer = (struct gtpV2IpBearerList *) rte_malloc ("bearerLst",sizeof (struct gtpV2IpBearerList ),0);
                                                                        if (pBearer != NULL)
                                                                                {
                                                                                pBearer->pNextBearer = NULL;
                                                                                pBearer->ipV4User = pHashObject->ipUser;
                                                                                pBearer->ipV6User[0]=0x0;
                                                                                pBearer->ipV6User[1]=0x0;
                                                                                pBearer->ipV6User[2]=0x0;
                                                                                pBearer->ipV6User[3]=0x0;
                                                                                pBearer->userTeid   =pHashObject->dataTeid;

                                                                                }
                                                                        else
                                                                                {
                                                                                printf ("sks: cannot allocate bearer \n");
                                                                                }
                                                                        }
                                                                //...add it to the userplane hashtable first and then to the bearer list in the control plane hashtable.
                                                                key.teid = pHashObject->dataTeid;
                                                                key.ip_dst = pHashObject->ipUser;
                                                                /*printf ("sks adding UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                                key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);*/
                                                                ret = rte_hash_add_key (pSessionIdV4UserHashTable, &key);
                                                                if (ret > 0 )
                                                                        {
                                                                        sessionIdUserHashTableIPV4[ret].ipUser = pHashObject->ipUser;
                                                                        sessionIdUserHashTableIPV4[ret].userTeid   = pHashObject->dataTeid;
                                                                        sessionIdUserHashTableIPV4[ret].sessionId = pHashObject->sessionId;
                                                                        sessionIdUserHashTableIPV4[ret].outputInterface = lastInterfaceUsed;
                                                                        }
                                                                else
                                                                        {
                                                                        printf ("cannot add key to user hash table\n");
                                                                        }
                                                                }
                                                        }
                                                }
                                        }

                                if (((int)(pHashObject->addDeleteFlag) == ADD_GTPV1_SESSION)||((int)(pHashObject->addDeleteFlag) == ADD_GTPV2_SESSION))
                                        {
                                        //...first create the entry in the control hash table
                                        key.ip_dst = pHashObject->ipControl;
                                        key.teid   = pHashObject->controlTeid;
                                        /*printf ("sks adding CP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);*/


					if ((int)(pHashObject->addDeleteFlag) == ADD_GTPV1_SESSION)
						{
						//...first create the entry in the control hash table
						key.ip_dst = pHashObject->ipControl;
						key.teid   = pHashObject->controlTeid;
						printf ("sks adding CP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
							key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);
						ret = rte_hash_add_key (pSessionIdV4ControlHashTable, &key);
						if (ret < 0 )
							{
							printf ("error while addding CP key\n");
							}
						if(ret >= 0 )
							{
							sessionIdControlHashTableIPV4[ret].ipControl     = pHashObject->ipControl;
							sessionIdControlHashTableIPV4[ret].ipUser        = pHashObject->ipUser;
							sessionIdControlHashTableIPV4[ret].controlTeid   = pHashObject->controlTeid;	
							sessionIdControlHashTableIPV4[ret].userTeid      = pHashObject->dataTeid;	
							sessionIdControlHashTableIPV4[ret].sessionId 	 = pHashObject->sessionId;
							//tx only on ports 2 and  3 for now, hard code it
							//TODO: right now it is round robin load balancing, need to add 
							//intelligence to this approach.
							if (lastInterfaceUsed == 3) 
								lastInterfaceUsed =2;
							else
								lastInterfaceUsed =3;

							sessionIdControlHashTableIPV4[ret].outputInterface = lastInterfaceUsed;
							//...chk if the datateid is non null, then map to the same sessionId and i/f
							if (pHashObject->dataTeid)
								{
								key.teid = pHashObject->dataTeid;
								key.ip_dst = pHashObject->ipUser;
								printf ("sks adding UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
								key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);
								ret = rte_hash_add_key (pSessionIdV4UserHashTable, &key);
								if (ret > 0 )
									{
						        		sessionIdUserHashTableIPV4[ret].ipUser          = pHashObject->ipUser;
       				                        		sessionIdUserHashTableIPV4[ret].userTeid        = pHashObject->dataTeid;
               		      			        		sessionIdUserHashTableIPV4[ret].sessionId       = pHashObject->sessionId;
               		      			        		sessionIdUserHashTableIPV4[ret].outputInterface = lastInterfaceUsed;
									}
								else
									{
									printf ("cannot add key to user hash table\n");
									}
								}
							}
						}
                                        if ((int)(pHashObject->addDeleteFlag) == ADD_GTPV2_SESSION)
                                                {
						printf ("sks:TblMaint: adding gtpv2 ipv4 session to v4 control hash table ip=0x%x, teid=0x%x\n", key.ip_dst,key.teid);
                                                ret = rte_hash_add_key (pSessionIdV4GtpV2ControlHashTable, &key);
                                                if(ret >= 0 )
                                                        {
                                                        //...create a bearer list first and then add to the userplane hashtable
                                                        sessionIdControlHashTableIPV4GTPV2[ret].ipControl     = pHashObject->ipControl;

                                                        sessionIdControlHashTableIPV4GTPV2[ret].pBearerList      = (struct gtpV2IpBearerList *) rte_malloc ("bearerLst",sizeof (struct gtpV2IpBearerList ),0);
                                                        if (sessionIdControlHashTableIPV4GTPV2[ret].pBearerList)
                                                                {
                                                                //blindly copy the ips, since the appropriate ip addr is zeroed out on the sending lcore
                                                                sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->ipV6User[0]        = pHashObject->ipUserV6[0];
                                                                sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->ipV6User[1]        = pHashObject->ipUserV6[1];
                                                                sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->ipV6User[2]        = pHashObject->ipUserV6[2];
                                                                sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->ipV6User[3]        = pHashObject->ipUserV6[3];
                                                                sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->ipV4User           = pHashObject->ipUser;
                                                                sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->userTeid           = pHashObject->dataTeid;
                                                                sessionIdControlHashTableIPV4GTPV2[ret].pBearerList->pNextBearer        = NULL;
                                                                }

                                                        sessionIdControlHashTableIPV4GTPV2[ret].controlTeid   = pHashObject->controlTeid;
                                                        sessionIdControlHashTableIPV4GTPV2[ret].sessionId     = pHashObject->sessionId;
                                                        //tx only on ports 2 and  3 for now, hard code it
                                                        //TODO: right now it is round robin load balancing, need to add
                                                        //intelligence to this approach.
                                                        if (lastInterfaceUsed == 3)
                                                                lastInterfaceUsed =2;
                                                        else
                                                                lastInterfaceUsed =3;
                                                        sessionIdControlHashTableIPV6GTPV2[ret].outputInterface = lastInterfaceUsed;
                                                        //...chk if the datateid is non null, then map to the same sessionId and i/f
                                                        if (pHashObject->dataTeid)
                                                                {
                                                                if (pHashObject->ipUser == 0x0)
                                                                        {
                                                                	keyV6.teid 	= pHashObject->dataTeid;
                                                                        keyV6.ip_dst[0] = pHashObject->ipUserV6[0];
                                                                        keyV6.ip_dst[1] = pHashObject->ipUserV6[1];
                                                                        keyV6.ip_dst[2] = pHashObject->ipUserV6[2];
                                                                        keyV6.ip_dst[3] = pHashObject->ipUserV6[3];
                                                                        /*printf ("sks adding UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                                        key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);*/
                                                                        ret = rte_hash_add_key (pSessionIdV6UserHashTable, &keyV6);
                                                                        if (ret > 0 )
                                                                                {
                                                                                sessionIdUserHashTableIPV6[ret].ipUserV6[0] = pHashObject->ipUserV6[0];
                                                                                sessionIdUserHashTableIPV6[ret].ipUserV6[1] = pHashObject->ipUserV6[1];
                                                                                sessionIdUserHashTableIPV6[ret].ipUserV6[2] = pHashObject->ipUserV6[2];
                                                                                sessionIdUserHashTableIPV6[ret].ipUserV6[3] = pHashObject->ipUserV6[3];
                                                                                sessionIdUserHashTableIPV6[ret].userTeid   = pHashObject->dataTeid;
                                                                                sessionIdUserHashTableIPV6[ret].sessionId = pHashObject->sessionId;
                                                                                sessionIdUserHashTableIPV6[ret].outputInterface = lastInterfaceUsed;
                                                                                }
                                                                        else
                                                                                {
                                                                                printf ("cannot add key to user hash table\n");
                                                                                }
                                                                        }
                                                                else
                                                                        {
                                                                        //...need to add to the ipv4 userplane hash table

                                                                        key.teid = pHashObject->dataTeid;
                                                                        key.ip_dst = pHashObject->ipUser;
                                                                        //printf ("sks adding UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                                        //key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);
                                                                        ret = rte_hash_add_key (pSessionIdV4UserHashTable, &key);
                                                                        if (ret > 0 )
                                                                                {
                                                                                sessionIdUserHashTableIPV4[ret].ipUser = pHashObject->ipUser;
                                                                                sessionIdUserHashTableIPV4[ret].userTeid   = pHashObject->dataTeid;
                                                                                sessionIdUserHashTableIPV4[ret].sessionId = pHashObject->sessionId;
                                                                                sessionIdUserHashTableIPV4[ret].outputInterface = lastInterfaceUsed;
                                                                                }
                                                                        else
                                                                                {
                                                                                printf ("cannot add key to user hash table\n");
                                                                                }
                                                                        }
                                                                }
                                                        }
                                                if (ret < 0 )
                                                        {
                                                        printf ("error while addding CP key\n");
                                                        }
                                                }

					}

                                if ((int)(pHashObject->addDeleteFlag) == RELEASE_BEARER_GTPV2_SESSION )
                                        {
                                        printf ("sks: ipv4 gtpv2 release bearer msg addDeleteFlag = 0x%x\n", pHashObject->addDeleteFlag);
                                        key.ip_dst 	= pHashObject->ipControl;
                                        key.teid      	= pHashObject->controlTeid;

                                        ret = rte_hash_del_key (pSessionIdV4GtpV2ControlHashTable,&key);

                                        if (ret >= 0 )
                                                {
                                                pBearer = sessionIdControlHashTableIPV4GTPV2[ret].pBearerList;

                                                while (pBearer)
                                                        {
                                                        //...run thru the bearer list and delete all bearer channels
                                                        if (pBearer->ipV4User == 0x0)
                                                                {
                                                                //...ipv6 bearer
                                                                keyV6.teid      = pBearer->userTeid;
                                                                keyV6.ip_dst[0] = pBearer->ipV6User[0];
                                                                keyV6.ip_dst[1] = pBearer->ipV6User[1];
                                                                keyV6.ip_dst[2] = pBearer->ipV6User[2];
                                                                keyV6.ip_dst[3] = pBearer->ipV6User[3];
                                                                rte_hash_del_key ( pSessionIdV6UserHashTable, &keyV6);
                                                                }
                                                        else
                                                                {
                                                                //...ipv4 bearer, reuse the key
                                                                key.teid        = pBearer->userTeid;
                                                                key.ip_dst      = pBearer->ipV4User;
                                                                rte_hash_del_key (pSessionIdV4UserHashTable, &key);
                                                                }
                                                        pBearer = pBearer->pNextBearer;
                                                        }
                                                sessionIdControlHashTableIPV4GTPV2[ret].ipControl         = 0x0;
                                                sessionIdControlHashTableIPV4GTPV2[ret].pBearerList          = NULL;
                                                sessionIdControlHashTableIPV4GTPV2[ret].controlTeid          = 0x0;
                                                sessionIdControlHashTableIPV4GTPV2[ret].sessionId            = 0x0;
                                                sessionIdControlHashTableIPV4GTPV2[ret].outputInterface      = 0x0;
                                                }

                                        }


				if (((int)(pHashObject->addDeleteFlag) == DELETE_GTPV1_SESSION_NO_TEARDOWN)||((int)(pHashObject->addDeleteFlag) == DELETE_GTPV1_SESSION_TEARDOWN ))
					{
					printf ("sks: ip v4  gtpv1 dequeued delete msg\n");
                                        key.ip_dst = pHashObject->ipControl;
                                        key.teid   = pHashObject->controlTeid;
                                        printf ("sks deleting CP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);
                                        ret = rte_hash_del_key (pSessionIdV4ControlHashTable, &key);

                                        if(ret >= 0 )
                                                {
                                                sessionIdControlHashTableIPV4[ret].ipControl     = 0xDEADBEEF;
                                                sessionIdControlHashTableIPV4[ret].ipUser        = 0xDEADBEEF;
                                                sessionIdControlHashTableIPV4[ret].controlTeid   = 0xDEADBEEF;
                                                sessionIdControlHashTableIPV4[ret].userTeid      = 0xDEADBEEF;
                                                sessionIdControlHashTableIPV4[ret].sessionId     = 0xDEADBEEF;
                                                sessionIdControlHashTableIPV4[ret].outputInterface = 0x0;

                                                //...chk if the datateid is non null, then map to the same sessionId and i/f
                                                if ((pHashObject->dataTeid) && (pHashObject->addDeleteFlag == DELETE_GTPV1_SESSION_TEARDOWN))
                                                        {
                                                        key.teid = pHashObject->dataTeid;
                                                        key.ip_dst = pHashObject->ipUser;
                                                        printf ("sks deleting UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                        key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);
                                                        ret = rte_hash_del_key (pSessionIdV4UserHashTable, &key);
                                                        if (ret > 0 )
                                                                {
                                                                sessionIdUserHashTableIPV4[ret].ipUser		= 0xDEADBEEF;
                                                                sessionIdUserHashTableIPV4[ret].userTeid	= 0xDEADBEEF;
                                                                sessionIdUserHashTableIPV4[ret].sessionId	= 0xDEADBEEF;
                                                                sessionIdUserHashTableIPV4[ret].outputInterface = 0x0;
                                                                }
                                                        else
                                                                {
                                                                printf ("cannot add key to user hash table\n");
                                                                }
                                                        }
                                                }
					}
				}
			}

                if (pControlRingV6 != NULL )
                        {
                                //...ring exists, continue
                                //rte_ring_dump(pControlRing);
                                if (rte_ring_count (pControlRingV6) > 0)
					{
					printf ("SKS: ring has data\n");
					}
                                ret = rte_ring_dequeue ( pControlRingV6, (void **)pTest);
                                if (ret == 0 )
                                        {
                                        printf ("sks:dequeue successful ring count %d\n", rte_ring_count (pControlRing));
                                        pHashObjectV6 = (struct sessionIdIpV6HashObject *)pTest[0];
                                        printf ("sks:addDeleteFlag = 0x%x\n", (int)(pHashObjectV6->addDeleteFlag));
                                        }
                                if (ret != 0 )
                                        {
                                        //...no data on ring, continue...
                                        continue;
                                        }
                                if (pHashObjectV6 == NULL)
                                        {
                                        printf ("sks hash object is null\n");
                                        continue;
                                        }

			 	printf ("addflag=0x%x,ipuserV4=0x%x\n", pHashObjectV6->addDeleteFlag,pHashObjectV6->ipUserV4);	
                                if ((int)(pHashObjectV6->addDeleteFlag) == ADD_BEARER_GTPV2_SESSION)
					{
                                        keyV6.ip_dst[0] = pHashObjectV6->ipControl[0];
                                        keyV6.ip_dst[1] = pHashObjectV6->ipControl[1];
                                        keyV6.ip_dst[2] = pHashObjectV6->ipControl[2];
                                        keyV6.ip_dst[3] = pHashObjectV6->ipControl[3];
                                        keyV6.teid   = pHashObjectV6->controlTeid;
                                        ret = rte_hash_lookup (pSessionIdV6GtpV2ControlHashTable, &keyV6);

					if (ret < 0 )
						{
						printf ("sks: no session established for bearer update ipdst=0x%x:0x%x:0x%x:0x%x, ctrlTeid=0x%x\n",
						keyV6.ip_dst[0], keyV6.ip_dst[1], keyV6.ip_dst[2], keyV6.ip_dst[3], keyV6.teid);
						}
					if (ret > 0 )
						{
					        if (pHashObjectV6->ipUserV4 == 0x0)
							{
							//...ipv6 bearer
							printf ("sks:sessionMaint: gtpv2 add ipv6 bearer request\n");
                                                        if (pHashObjectV6->dataTeid)
                                                                {
								if (sessionIdControlHashTableIPV6GTPV2[ret].pBearerList != NULL )
									{
									struct gtpV2IpBearerList *pBearer;
									pBearer = sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->pNextBearer; 
									
									while (pBearer != NULL ) 
										{
										//...keep going till end of the list
										pBearer = pBearer->pNextBearer;
										}
									
									pBearer = (struct gtpV2IpBearerList *) rte_malloc ("bearerLst",sizeof (struct gtpV2IpBearerList ),0);
									if (pBearer != NULL)
										{
										pBearer->pNextBearer = NULL;
										pBearer->ipV4User = 0x0;
										pBearer->ipV6User[0]=pHashObjectV6->ipUser[0];
										pBearer->ipV6User[1]=pHashObjectV6->ipUser[1];
										pBearer->ipV6User[2]=pHashObjectV6->ipUser[2];
										pBearer->ipV6User[3]=pHashObjectV6->ipUser[3];
										pBearer->userTeid   =pHashObjectV6->dataTeid;
										}
									else
										{
										printf ("sks: cannot allocate bearer \n");
										continue;
										}
									}
								//...add it to the userplane hashtable first and then to the bearer list in the control plane hashtable.
                                                                keyV6.teid = pHashObjectV6->dataTeid;
                                                                keyV6.ip_dst[0] = pHashObjectV6->ipUser[0];
                                                                keyV6.ip_dst[1] = pHashObjectV6->ipUser[1];
                                                                keyV6.ip_dst[2] = pHashObjectV6->ipUser[2];
                                                                keyV6.ip_dst[3] = pHashObjectV6->ipUser[3];
                                                                printf ("sks adding UP bearer key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x:0x%x:0x%x:0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x\n",
                                                                        keyV6.pad0,keyV6.pad1,keyV6.pad2,keyV6.ip_src[0],keyV6.ip_dst[0],keyV6.ip_dst[1],keyV6.ip_dst[2],keyV6.ip_dst[3],keyV6.pad3,keyV6.pad4,keyV6.pad5,keyV6.pad6,keyV6.flagsMsgTypeAndLen,keyV6.teid);
 
								ret = rte_hash_add_key (pSessionIdV6UserHashTable, &keyV6);
                                                                if (ret > 0 )
                                                                        {
                                                                        sessionIdUserHashTableIPV6[ret].ipUserV6[0] = pHashObjectV6->ipUser[0];
                                                                        sessionIdUserHashTableIPV6[ret].ipUserV6[1] = pHashObjectV6->ipUser[1];
                                                                        sessionIdUserHashTableIPV6[ret].ipUserV6[2] = pHashObjectV6->ipUser[2];
                                                                        sessionIdUserHashTableIPV6[ret].ipUserV6[3] = pHashObjectV6->ipUser[3];
                                                                        sessionIdUserHashTableIPV6[ret].userTeid   = pHashObjectV6->dataTeid;
                                                                        sessionIdUserHashTableIPV6[ret].sessionId = pHashObjectV6->sessionId;
		                                                        sessionIdUserHashTableIPV6[ret].outputInterface = lastInterfaceUsed;
                                                                        }
                                                                else
                                                                        {
                                                                        printf ("cannot add key to user hash table\n");
                                                                        continue;
                                                                        }
                                                                }

							}
						else
							{
							//...ipv4 bearer
							printf ("sks:sessionMaint: gtpv2 add ipv4 bearer request\n");

                                                        if (pHashObjectV6->dataTeid)
                                                                {
                                                                if (sessionIdControlHashTableIPV6GTPV2[ret].pBearerList != NULL )
                                                                        {
                                                                        struct gtpV2IpBearerList *pBearer;
                                                                        pBearer = sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->pNextBearer;

                                                                        while (pBearer != NULL )
                                                                                {
                                                                                //...keep going till end of the list
                                                                                pBearer = pBearer->pNextBearer;
                                                                                }

                                                                        pBearer = (struct gtpV2IpBearerList *) rte_malloc ("bearerLst",sizeof (struct gtpV2IpBearerList ),0);
                                                                        if (pBearer != NULL)
                                                                                {
                                                                                pBearer->pNextBearer = NULL;
                                                                                pBearer->ipV4User = pHashObjectV6->ipUserV4;
                                                                                pBearer->ipV6User[0]=0x0;
                                                                                pBearer->ipV6User[1]=0x0;
                                                                                pBearer->ipV6User[2]=0x0;
                                                                                pBearer->ipV6User[3]=0x0;
                                                                                pBearer->userTeid   =pHashObjectV6->dataTeid;
                                                                                }
                                                                        else
                                                                                {
                                                                                printf ("sks: cannot allocate bearer \n");
                                                                                continue;
                                                                                }
                                                                        }
                                                                //...add it to the userplane hashtable first and then to the bearer list in the control plane hashtable.
                                                                key.teid = pHashObjectV6->dataTeid;
                                                                key.ip_dst = pHashObjectV6->ipUserV4;
                                                                printf ("sks adding UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                                key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);
                                                                ret = rte_hash_add_key (pSessionIdV4UserHashTable, &key);
                                                                if (ret > 0 )
                                                                        {
                                                                        sessionIdUserHashTableIPV4[ret].ipUser = pHashObjectV6->ipUser[0];
                                                                        sessionIdUserHashTableIPV4[ret].userTeid   = pHashObjectV6->dataTeid;
                                                                        sessionIdUserHashTableIPV4[ret].sessionId = pHashObjectV6->sessionId;
                                                                        sessionIdUserHashTableIPV4[ret].outputInterface = lastInterfaceUsed;
                                                                        }
                                                                else
                                                                        {
                                                                        printf ("cannot add key to user hash table\n");
                                                                        continue;
				                                        }
								} 
							}
						}
					}
                                if (((int)(pHashObjectV6->addDeleteFlag) == ADD_GTPV1_SESSION)||((int)(pHashObjectV6->addDeleteFlag) == ADD_GTPV2_SESSION))
                                        {
                                        //...first create the entry in the control hash table
                                        keyV6.ip_dst[0] = pHashObjectV6->ipControl[0];
                                        keyV6.ip_dst[1] = pHashObjectV6->ipControl[1];
                                        keyV6.ip_dst[2] = pHashObjectV6->ipControl[2];
                                        keyV6.ip_dst[3] = pHashObjectV6->ipControl[3];
                                        keyV6.teid   = pHashObjectV6->controlTeid;
                                        printf ("sks adding CP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x:0x%x:0x%x:0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x\n",
                                                keyV6.pad0,keyV6.pad1,keyV6.pad2,keyV6.ip_src[0],keyV6.ip_dst[0],keyV6.ip_dst[1],keyV6.ip_dst[2],keyV6.ip_dst[3],keyV6.pad3,keyV6.pad4,keyV6.pad5,keyV6.pad6,keyV6.flagsMsgTypeAndLen,keyV6.teid);
                                        if ((int)(pHashObjectV6->addDeleteFlag) == ADD_GTPV1_SESSION)
						{
						ret = rte_hash_add_key (pSessionIdV6ControlHashTable, &keyV6);
	                                        if(ret >= 0 )
       	                                        	{
                                                	sessionIdControlHashTableIPV6[ret].ipControl[0]     = pHashObjectV6->ipControl[0];
                                                	sessionIdControlHashTableIPV6[ret].ipControl[1]     = pHashObjectV6->ipControl[1];
                                                	sessionIdControlHashTableIPV6[ret].ipControl[2]     = pHashObjectV6->ipControl[2];
                                                	sessionIdControlHashTableIPV6[ret].ipControl[3]     = pHashObjectV6->ipControl[3];
                                                	sessionIdControlHashTableIPV6[ret].ipUser[0]        = pHashObjectV6->ipUser[0];
                                                	sessionIdControlHashTableIPV6[ret].ipUser[1]        = pHashObjectV6->ipUser[1];
                                                	sessionIdControlHashTableIPV6[ret].ipUser[2]        = pHashObjectV6->ipUser[2];
                                                	sessionIdControlHashTableIPV6[ret].ipUser[3]        = pHashObjectV6->ipUser[3];

                                                	sessionIdControlHashTableIPV6[ret].controlTeid   = pHashObjectV6->controlTeid;
                                                	sessionIdControlHashTableIPV6[ret].userTeid      = pHashObjectV6->dataTeid;
                                                	sessionIdControlHashTableIPV6[ret].sessionId     = pHashObjectV6->sessionId;
                                                	//tx only on ports 2 and  3 for now, hard code it
                                                	//TODO: right now it is round robin load balancing, need to add
                                                	//intelligence to this approach.
                                                	if (lastInterfaceUsed == 3)
                                                        	lastInterfaceUsed =2;
                                                	else
                                                        	lastInterfaceUsed =3;
                                                	sessionIdControlHashTableIPV6[ret].outputInterface = lastInterfaceUsed;
                                                	//...chk if the datateid is non null, then map to the same sessionId and i/f
                                                	if (pHashObjectV6->dataTeid)
                                                        	{
                                                        	keyV6.teid = pHashObjectV6->dataTeid;
                                                        	keyV6.ip_dst[0] = pHashObjectV6->ipUser[0];
                                                        	keyV6.ip_dst[1] = pHashObjectV6->ipUser[1];
                                                        	keyV6.ip_dst[2] = pHashObjectV6->ipUser[2];
                                                        	keyV6.ip_dst[3] = pHashObjectV6->ipUser[3];
                                                                printf ("sks adding UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x:0x%x:0x%x:0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x\n",
      		                                                keyV6.pad0,keyV6.pad1,keyV6.pad2,keyV6.ip_src[0],keyV6.ip_dst[0],keyV6.ip_dst[1],keyV6.ip_dst[2],keyV6.ip_dst[3],keyV6.pad3,keyV6.pad4,keyV6.pad5,keyV6.pad6,keyV6.flagsMsgTypeAndLen,keyV6.teid);
	
								ret = rte_hash_add_key (pSessionIdV6UserHashTable, &keyV6);
                                                        	if (ret > 0 )
                                                                	{
                                                                	sessionIdUserHashTableIPV6[ret].ipUserV6[0] = pHashObjectV6->ipUser[0];
                                                                	sessionIdUserHashTableIPV6[ret].ipUserV6[1] = pHashObjectV6->ipUser[1];
                                                                	sessionIdUserHashTableIPV6[ret].ipUserV6[2] = pHashObjectV6->ipUser[2];
                                                                	sessionIdUserHashTableIPV6[ret].ipUserV6[3] = pHashObjectV6->ipUser[3];
                                                                	sessionIdUserHashTableIPV6[ret].userTeid   = pHashObjectV6->dataTeid;
                                                                	sessionIdUserHashTableIPV6[ret].sessionId = pHashObjectV6->sessionId;
                                                                	sessionIdUserHashTableIPV6[ret].outputInterface = lastInterfaceUsed;
                                                                	}
                                                        	else
                                                                	{
                                                                	printf ("cannot add key to user hash table\n");
                                                                	continue;
                                                                	}
                                                        	}
                                                	}
						}

					if ((int)(pHashObjectV6->addDeleteFlag) == ADD_GTPV2_SESSION)
						{
						printf ("sks: ading gpv2 ipv6 control hash\n");
						ret = rte_hash_add_key (pSessionIdV6GtpV2ControlHashTable, &keyV6);
                                                if(ret >= 0 )
                                                        {
							//...create a bearer list first and then add to the userplane hashtable
                                                        sessionIdControlHashTableIPV6GTPV2[ret].ipControl[0]     = pHashObjectV6->ipControl[0];
                                                        sessionIdControlHashTableIPV6GTPV2[ret].ipControl[1]     = pHashObjectV6->ipControl[1];
                                                        sessionIdControlHashTableIPV6GTPV2[ret].ipControl[2]     = pHashObjectV6->ipControl[2];
                                                        sessionIdControlHashTableIPV6GTPV2[ret].ipControl[3]     = pHashObjectV6->ipControl[3];

							sessionIdControlHashTableIPV6GTPV2[ret].pBearerList	 = (struct gtpV2IpBearerList *) rte_malloc ("bearerLst",sizeof (struct gtpV2IpBearerList ),0);
							if (sessionIdControlHashTableIPV6GTPV2[ret].pBearerList)
								{
								//blindly copy the ips, since the appropriate ip addr is zeroed out on the sending lcore
								sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->ipV6User[0]	= pHashObjectV6->ipUser[0];	
								sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->ipV6User[1]	= pHashObjectV6->ipUser[1];	
								sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->ipV6User[2]	= pHashObjectV6->ipUser[2];	
								sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->ipV6User[3]	= pHashObjectV6->ipUser[3];	
								sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->ipV4User		= pHashObjectV6->ipUserV4;
								sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->userTeid		= pHashObjectV6->dataTeid;
								sessionIdControlHashTableIPV6GTPV2[ret].pBearerList->pNextBearer	= NULL;
								}

                                                        sessionIdControlHashTableIPV6GTPV2[ret].controlTeid   = pHashObjectV6->controlTeid;
                                                        sessionIdControlHashTableIPV6GTPV2[ret].sessionId     = pHashObjectV6->sessionId;
                                                        //tx only on ports 2 and  3 for now, hard code it
                                                        //TODO: right now it is round robin load balancing, need to add
                                                        //intelligence to this approach.
                                                        if (lastInterfaceUsed == 3)
                                                                lastInterfaceUsed =2;
                                                        else
                                                                lastInterfaceUsed =3;
                                                        sessionIdControlHashTableIPV6GTPV2[ret].outputInterface = lastInterfaceUsed;
                                                        //...chk if the datateid is non null, then map to the same sessionId and i/f
                                                        if (pHashObjectV6->dataTeid)
                                                                {
                                                                keyV6.teid = pHashObjectV6->dataTeid;
								printf ("sks: ipUserV4=0x%x\n", pHashObjectV6->ipUserV4);
								if (pHashObjectV6->ipUserV4 == 0x0)
									{
                                                                	keyV6.ip_dst[0] = pHashObjectV6->ipUser[0];
                                                                	keyV6.ip_dst[1] = pHashObjectV6->ipUser[1];
                                                                	keyV6.ip_dst[2] = pHashObjectV6->ipUser[2];
                                                                	keyV6.ip_dst[3] = pHashObjectV6->ipUser[3];
				                                        printf ("sks adding v6 UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x:0x%x:0x%x:0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x\n",
                               			                        keyV6.pad0,keyV6.pad1,keyV6.pad2,keyV6.ip_src[0],keyV6.ip_dst[0],keyV6.ip_dst[1],keyV6.ip_dst[2],keyV6.ip_dst[3],keyV6.pad3,keyV6.pad4,keyV6.pad5,keyV6.pad6,keyV6.flagsMsgTypeAndLen,keyV6.teid);

									printf ("sks: ading gpv2 ipv6 user hash\n");
                                                                	ret = rte_hash_add_key (pSessionIdV6UserHashTable, &keyV6);
                                                                	if (ret > 0 )
                                                                        	{
                                                                        	sessionIdUserHashTableIPV6[ret].ipUserV6[0] = pHashObjectV6->ipUser[0];
                                                                        	sessionIdUserHashTableIPV6[ret].ipUserV6[1] = pHashObjectV6->ipUser[1];
                                                                        	sessionIdUserHashTableIPV6[ret].ipUserV6[2] = pHashObjectV6->ipUser[2];
                                                                        	sessionIdUserHashTableIPV6[ret].ipUserV6[3] = pHashObjectV6->ipUser[3];
                                                                        	sessionIdUserHashTableIPV6[ret].userTeid   = pHashObjectV6->dataTeid;
                                                                        	sessionIdUserHashTableIPV6[ret].sessionId = pHashObjectV6->sessionId;
                                                                        	sessionIdUserHashTableIPV6[ret].outputInterface = lastInterfaceUsed;
                                                                        	}
                                                                	else
                                                                        	{
                                                                        	printf ("cannot add key to user hash table\n");
                                                                        	continue;
                                                                        	}
                                                                	}
								else
									{
									//...need to add to the ipv4 userplane hash table
							
		                                                        key.teid = pHashObjectV6->dataTeid;
               			                                        key.ip_dst = pHashObjectV6->ipUserV4;
                             	                                        printf ("sks adding v4 UP key: ip_dst=0x%x,teid=0x%x\n",
       				                                        key.ip_dst,key.teid);
	
									ret = rte_hash_add_key (pSessionIdV4UserHashTable, &key);
                                                        		if (ret > 0 )
                                                                		{
                                                                		sessionIdUserHashTableIPV4[ret].ipUser = pHashObjectV6->ipUserV4;
                                                                		sessionIdUserHashTableIPV4[ret].userTeid   = pHashObjectV6->dataTeid;
                                                                		sessionIdUserHashTableIPV4[ret].sessionId = pHashObjectV6->sessionId;
                                                                		sessionIdUserHashTableIPV4[ret].outputInterface = lastInterfaceUsed;
                                                                		}
                                                        		else
                                                                		{
                                                                		printf ("cannot add key to user hash table\n");
                                                                		continue;
                                                                		}
									}
                                                        	}
							}
                                        	if (ret < 0 )
                                                	{
                                                	printf ("error while addding CP key\n");
                                                	}
						}
                                        }

                                if ((int)(pHashObjectV6->addDeleteFlag) == RELEASE_BEARER_GTPV2_SESSION )
					{
                                        printf ("sks: ipv6 gtpv2 release bearer msg addDeleteFlag = 0x%x\n", pHashObjectV6->addDeleteFlag);
                                        keyV6.ip_dst[0] = pHashObjectV6->ipControl[0];
                                        keyV6.ip_dst[1] = pHashObjectV6->ipControl[1];
                                        keyV6.ip_dst[2] = pHashObjectV6->ipControl[2];
                                        keyV6.ip_dst[3] = pHashObjectV6->ipControl[3];
                                        keyV6.teid      = pHashObjectV6->controlTeid;

					ret = rte_hash_del_key (pSessionIdV6GtpV2ControlHashTable,&keyV6);

					if (ret >= 0 )
						{
						pBearer = sessionIdControlHashTableIPV6GTPV2[ret].pBearerList;

						while (pBearer)
							{
							printf ("sks: deleting bearer channel\n");
							//...run thru the bearer list and delete all bearer channels	
							if (pBearer->ipV4User == 0x0)
								{
								//...ipv6 bearer
								keyV6.teid	= pBearer->userTeid;
								keyV6.ip_dst[0] = pBearer->ipV6User[0];
								keyV6.ip_dst[1] = pBearer->ipV6User[1];
								keyV6.ip_dst[2] = pBearer->ipV6User[2];
								keyV6.ip_dst[3] = pBearer->ipV6User[3];
								rte_hash_del_key ( pSessionIdV6UserHashTable, &keyV6);
								}
							else
								{
								//...ipv4 bearer
								key.teid	= pBearer->userTeid;
								key.ip_dst	= pBearer->ipV4User;
								rte_hash_del_key (pSessionIdV4UserHashTable, &key);
								}
							pBearer = pBearer->pNextBearer;
							}
                                                sessionIdControlHashTableIPV6GTPV2[ret].ipControl[0]         = 0x0;
                                                sessionIdControlHashTableIPV6GTPV2[ret].ipControl[1]         = 0x0;
                                                sessionIdControlHashTableIPV6GTPV2[ret].ipControl[2]         = 0x0;
                                                sessionIdControlHashTableIPV6GTPV2[ret].ipControl[3]         = 0x0;
                                                sessionIdControlHashTableIPV6GTPV2[ret].pBearerList          = NULL; 
                                                sessionIdControlHashTableIPV6GTPV2[ret].controlTeid          = 0x0;
                                                sessionIdControlHashTableIPV6GTPV2[ret].sessionId            = 0x0;
                                                sessionIdControlHashTableIPV6GTPV2[ret].outputInterface      = 0x0;
						}
					
					}
                                if (((int)(pHashObjectV6->addDeleteFlag) == DELETE_GTPV1_SESSION_NO_TEARDOWN)||((int)(pHashObjectV6->addDeleteFlag) == DELETE_GTPV1_SESSION_TEARDOWN ))
                                        {
                                        printf ("sks: ipv6 gtpv1 dequeued delete msg addDeleteFlag = 0x%x\n", pHashObjectV6->addDeleteFlag);
                                        keyV6.ip_dst[0] = pHashObjectV6->ipControl[0];
                                        keyV6.ip_dst[1] = pHashObjectV6->ipControl[1];
                                        keyV6.ip_dst[2] = pHashObjectV6->ipControl[2];
                                        keyV6.ip_dst[3] = pHashObjectV6->ipControl[3];
                                        keyV6.teid   	= pHashObjectV6->controlTeid;
                                        /*printf ("sks deleting CP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);*/
                                        ret = rte_hash_del_key (pSessionIdV6ControlHashTable, &keyV6);

                                        if(ret >= 0 )
                                                {
                                                sessionIdControlHashTableIPV6[ret].ipControl[0]     	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].ipControl[1]     	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].ipControl[2]     	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].ipControl[3]     	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].ipUser[0]        	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].ipUser[1]        	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].ipUser[2]        	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].ipUser[3]        	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].controlTeid   	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].userTeid      	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].sessionId     	= 0x0;
                                                sessionIdControlHashTableIPV6[ret].outputInterface 	= 0x0;

                                                //...chk if the datateid is non null, then map to the same sessionId and i/f
                                                if ((pHashObjectV6->dataTeid) && (pHashObjectV6->addDeleteFlag == DELETE_GTPV1_SESSION_TEARDOWN))
                                                        {
                                                        keyV6.teid 	= pHashObjectV6->dataTeid;
                                                        keyV6.ip_dst[0] = pHashObjectV6->ipUser[0];
                                                        keyV6.ip_dst[1] = pHashObjectV6->ipUser[1];
                                                        keyV6.ip_dst[2] = pHashObjectV6->ipUser[2];
                                                        keyV6.ip_dst[3] = pHashObjectV6->ipUser[3];
                                                       /* printf ("sks deleting UP key: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x,pad7=0x%x\n",
                                                        key.pad0,key.pad1,key.pad2,key.ip_src,key.ip_dst,key.pad3,key.pad4,key.pad5,key.pad6,key.flagsMsgTypeAndLen,key.teid,key.pad7);*/
                                                        ret = rte_hash_del_key (pSessionIdV6UserHashTable, &keyV6);
                                                        if (ret > 0 )
                                                                {
                                                                sessionIdUserHashTableIPV6[ret].ipUserV6[0]          	= 0x0;
                                                                sessionIdUserHashTableIPV6[ret].ipUserV6[1]         	= 0x0;
                                                                sessionIdUserHashTableIPV6[ret].ipUserV6[2]          	= 0x0;
                                                                sessionIdUserHashTableIPV6[ret].ipUserV6[3]          	= 0x0;
                                                                sessionIdUserHashTableIPV6[ret].userTeid        	= 0x0;
                                                                sessionIdUserHashTableIPV6[ret].sessionId       	= 0x0;
                                                                sessionIdUserHashTableIPV6[ret].outputInterface 	= 0x0;
                                                                }
                                                        else
                                                                {
                                                                printf ("cannot add key to user hash table\n");
                                                                continue;
                                                                }
                                                        }
                                                }
                                        }
				}
			else
				{
				printf ("sks:pControlV6 is NULL!!!\n");
				}
		}
	}
static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf ("sks, lcoreid=%u\n", lcore_id);

	
	if ( lcore_id == 0x01 )
		l2fwd_main_loop();

	
	if ( lcore_id == 0x02)
		sessionIdHashTableMaint ( );

	return 0;
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n",
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:q:T:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_period = l2fwd_parse_timer_period(optarg) * 1000 * TIMER_MILLISECOND;
			if (timer_period < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			l2fwd_usage(prgname);
			return -1;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int
MAIN(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info;
	int ret;
	uint8_t nb_ports;
	uint8_t nb_ports_available;
	uint8_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

	/* create the mbuf pool */
	l2fwd_pktmbuf_pool =
		rte_mempool_create("mbuf_pool", NB_MBUF,
				   MBUF_SIZE, 32,
				   sizeof(struct rte_pktmbuf_pool_private),
				   rte_pktmbuf_pool_init, NULL,
				   rte_pktmbuf_init, NULL,
				   rte_socket_id(), 0);
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* init driver(s) */
	if (rte_pmd_init_all() < 0)
		rte_exit(EXIT_FAILURE, "Cannot init pmd\n");

	if (rte_eal_pci_probe() < 0)
		rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			l2fwd_dst_ports[portid] = last_port;
			l2fwd_dst_ports[last_port] = portid;
		}
		else
			last_port = portid;

		nb_ports_in_mask++;

		rte_eth_dev_info_get(portid, &dev_info);
	}
	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_dst_ports[last_port] = last_port;
	}

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id])
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) portid);
	}

	nb_ports_available = nb_ports;

	/* Initialise each port */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", (unsigned) portid);
			nb_ports_available--;
			continue;
		}
		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);
		fflush(stdout);
		ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, (unsigned) portid);

		rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);

		/* init one RX queue */
		fflush(stdout);
		/*ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid), &rx_conf,
					     l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, (unsigned) portid);*/

		//...setup 5 rx queues

		int queueNum = 0;
		while (queueNum <1)
			{
			printf ("sks: setting up queueNum %d on port %d\n", queueNum, portid);
			ret = rte_eth_rx_queue_setup(portid, queueNum, nb_rxd,
                       		                      rte_eth_dev_socket_id(portid), &rx_conf,
                               		              l2fwd_pktmbuf_pool);
                	if (ret < 0)
                        	rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                                  	ret, (unsigned) portid);
			queueNum++;
			}



		/* init one TX queue on each port */
		fflush(stdout);
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid), &tx_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, (unsigned) portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		printf("done: \n");

		rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				(unsigned) portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(nb_ports, l2fwd_enabled_port_mask);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}





