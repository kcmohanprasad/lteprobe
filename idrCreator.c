 /*
 *  *
 *   *   Who             What                               Date
 *    *  Sunil Shaligram Original		          1st July 2015
 *    */
#if 0
#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h>
#define getopt getopt____
#else
#include <unistd.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>


#include "../config.h"
#include "main.h"
#ifdef HAVE_JSON_C
#include <json.h>
#endif
#define NDPI_ENABLE_DEBUG_MESSAGES

//#include "ndpi_api.h"

#include <sys/socket.h>

#endif

#include "main.h"

void FillUpGtpV2ControlIdr (struct GtpV2Header * pGtpHeader ,uint8_t *pGtpParser, struct idrHashObject *pObj, int hashLoc)
	{
        ctrlIdrHashTable[hashLoc].gtpVersion = 2;

        int             octets = 0;
        uint32_t        controlTeid = 0;
        uint32_t        dataTeid = 0;
        uint8_t         gtpType;
        uint16_t        fwdLen;
	uint16_t	bytesWritten=0;
                        
        while ((octets < rte_cpu_to_be_16(pGtpHeader->length)))
                {
                gtpType = (uint8_t)(*pGtpParser);
		//printf ("sks: gtp pkt dump 0x%2x 0x%2x 0x%2x 0x%2x \n", *pGtpParser, *(pGtpParser +1),*(pGtpParser +2), *(pGtpParser+3));
                //increment parser pointer so that we can pick up the value of the type
                pGtpParser += sizeof (uint8_t);
                octets++;
                printf ("FillupGtpV2ControlIdr:sks:gtpType=0x%x\n", gtpType);
	        switch (gtpType)
                	{
                        case GTPV2_TYPE_RAT_TYPE:
				fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
				pGtpParser += 3*sizeof(uint8_t);//len+spare
				pObj->rat = *((uint8_t *)pGtpParser);
				//printf ("sks: gtpv2 rat = 0x%x\n", pObj->rat);
                        	break;
                        case GTPV2_TYPE_MSISDN:
				fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
				pGtpParser += 3*sizeof(uint8_t);//len+spare
				bytesWritten = rte_snprintf (pObj->msisdn,fwdLen+2,"%s",(uint8_t *)pGtpParser);	
				//printf ("sks: bytesWritten=%d gtpv2 msisdn = %s\n", bytesWritten, pObj->msisdn);
                        	break;
                        case GTPV2_TYPE_APN:
				fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
				pGtpParser += 3*sizeof(uint8_t);//len+spare
				bytesWritten = rte_snprintf (pObj->apn,fwdLen+2,"%s",(uint8_t *)pGtpParser);	
				//printf ("sks: bytesWritten=%d gtpv2 apn = %s\n", bytesWritten, pObj->apn);
                        	break;
                        case GTPV1_TYPE_IMEISV:
				fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
				pGtpParser += 3*sizeof(uint8_t);//len+spare
				pObj->imeisv =  rte_cpu_to_be_64(*((uint64_t *)pGtpParser));
				//printf ("sks: gtpv2 imeisv = 0x%x\n", pObj->imeisv);
                        	break;
                        case GTPV2_TYPE_CAUSE:
				fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
				pGtpParser += 3*sizeof(uint8_t);//len+spare
				pObj->causeCode = *pGtpParser;
				//printf ("sks: gtpv2 cause = 0x%x\n", pObj->causeCode);
                                octets++;
                                break;
                        case GTPV2_TYPE_IMSI:
				fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
				pGtpParser += 3*sizeof(uint8_t); //len+spare
				pObj->imsi =  rte_cpu_to_be_64(*((uint64_t *)pGtpParser));
				//printf ("sks: gtpv2 imsi = %#" PRIx64 "\n", pObj->imsi);
                                break;
                        case GTPV1_TYPE_pTMSI:
				fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
				pGtpParser += 3*sizeof(uint8_t); //len+spare
				pObj->pTMSI =  rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
				//printf ("sks: gtpv2 ptmsi = 0x%x\n", pObj->pTMSI);
                                break;
			default:
				fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
				pGtpParser += 3*sizeof(uint8_t); //len+spare
				//printf ("sks: not needed type 0x%x\n", gtpType);
				break;
                        }

                 pGtpParser += fwdLen*sizeof(uint8_t);
                 octets +=(2+fwdLen);
		}
	printf ("FillUpGtpV2ControlIdr:sks: done\n");

	}


void FillUpGtpV1ControlIdr (struct GtpV1Header * pGtpHeader ,uint8_t *pGtpParser, struct idrHashObject *pObj, int hashLoc)
	{

	int 		octets = 0;
        uint32_t        controlTeid = 0;
        uint32_t        dataTeid = 0;
        uint8_t         gtpType;
        uint16_t        fwdLen;

	if ( pObj == NULL )
		printf ( "sks:FillUpGtpV1ControlIdr - pObj is NULL!!!\n");

    	while ((octets < rte_cpu_to_be_16(pGtpHeader->length)))
		{
                gtpType = (uint8_t)(*pGtpParser);
                //increment parser pointer so that we can pick up the value of the type
                pGtpParser += sizeof (uint8_t);
		octets++;
                printf ("sks:gtpType=0x%x\n", gtpType);
                if ( gtpType & 0x80 )
			{
			//...type TVL
			switch (gtpType)
				{
			        case GTPV1_TYPE_RAT_TYPE:
					pObj->rat =  (0x0000ff00 & rte_cpu_to_be_32(*((uint32_t *)pGtpParser)));
                                        break;
                                case GTPV1_TYPE_MSISDN:
                        		fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
					rte_snprintf (pObj->msisdn,fwdLen+2,"%s",(uint8_t *)pGtpParser);
                                        break;
                                case GTPV1_TYPE_APN:
					rte_snprintf (pObj->apn,fwdLen+2,"%s",(uint8_t *)pGtpParser);
                                        break;
                                case GTPV1_TYPE_IMEISV:
					pObj->imeisv = rte_cpu_to_be_64(*((uint64_t *)pGtpParser));
                                        break;
				}

                        fwdLen = rte_cpu_to_be_16(*((uint16_t *)pGtpParser));
                        pGtpParser += 2*sizeof(uint8_t);//...fwd 2 octets for the length field
                        pGtpParser += fwdLen*sizeof(uint8_t);
                        octets +=(2+fwdLen);
			}
		else
			{
			//...type TV
                	switch (gtpType)
				{
                                case GTPV1_TYPE_CAUSE:
					pObj->causeCode = *pGtpParser;
					pGtpParser += sizeof(uint8_t);
					octets++;
                                        break;
                        	case GTPV1_TYPE_IMSI:
					pObj->imsi = rte_cpu_to_be_64(*((uint64_t *)pGtpParser));
                        		pGtpParser += 8*sizeof(uint8_t);
                                	octets +=8;
                                	break;
                        	case GTPV1_TYPE_RAI:
                                	pGtpParser += 6*sizeof(uint8_t);
                                	octets +=6;
                                	break;
                                case GTPV1_TYPE_TLLI:
                                        pGtpParser += 4*sizeof(uint8_t);
                                        octets +=4;
                                        break;
                                case GTPV1_TYPE_pTMSI:
					pObj->pTMSI = rte_cpu_to_be_32(*((uint32_t *)pGtpParser));
                                        pGtpParser += 4*sizeof(uint8_t);
                                        octets +=4;
                                        break;
                                case GTPV1_TYPE_REORDERING_REQD:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
					break;
                                case GTPV1_TYPE_AUTH_TRIPLET:
                                        pGtpParser += 28*sizeof(uint8_t);
                                        octets	+= 28;
					break;
                                case GTPV1_TYPE_MAP_CAUSE:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
                                        break;
                                case GTPV1_TYPE_pTMSI_SIGN:
                                        pGtpParser += 3*sizeof(uint8_t);
                                        octets +=3;
                                        break;
                                case GTPV1_TYPE_MS_VALIDATED:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
                                        break;
                        	case GTPV1_TYPE_RECOVERY:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
					break;
                                case GTPV1_TYPE_SEL_MODE:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
                                        break;
                                case GTPV1_TYPE_DATA_TEID:
                                        pGtpParser += 4*sizeof(uint8_t);
                                        octets += 4;
                                        break;
                                case GTPV1_TYPE_CTRL_TEID:
                                        pGtpParser += 4*sizeof(uint8_t);
                                        octets += 4;
                                        break;
                                case GTPV1_TYPE_DATA_TEID_2:
                                        pGtpParser += 5*sizeof(uint8_t);
                                        octets += 5;
                                        break;
                        	case GTPV1_TYPE_TEARDOWN:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
					break;
                        	case GTPV1_TYPE_NSAPI:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
					break;
                        	case GTPV1_TYPE_NSAPI_CAUSE:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
					break;
                        	case GTPV1_TYPE_RAB_CONTEXT:
                                        pGtpParser += 9*sizeof(uint8_t);
                                        octets += 9;
					break;
                        	case GTPV1_TYPE_RADIO_PRIO_SMS:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
					break;
                        	case GTPV1_TYPE_RADIO_PRIO:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
                                        break;
                        	case GTPV1_TYPE_PKT_FLOW_ID:
                                        pGtpParser += 2*sizeof(uint8_t);
                                        octets += 2;
                                        break;
                                case GTPV1_TYPE_CHARGING_CHK: 
                                        pGtpParser += 2*sizeof(uint8_t);
                                        octets += 2;
                                        break;
                                case GTPV1_TYPE_TRACE_REF:
                                        pGtpParser += 2*sizeof(uint8_t);
                                        octets += 2;
                                        break;
                                case GTPV1_TYPE_TRACE_TYPE:
                                        pGtpParser += 2*sizeof(uint8_t);
                                        octets +=2;
                                        break;
                                case GTPV1_TYPE_MS_NOT_REACHABLE:
                                        pGtpParser += sizeof(uint8_t);
                                        octets++;
                                        break;
                                case GTPV1_TYPE_RADIO_PRIO_LCS:
                                        pGtpParser += 3*sizeof(uint8_t);
                                        octets += 3;
                                        break;
                        	case GTPV1_TYPE_CHARGING_ID:
                                	pGtpParser += 4*sizeof(uint8_t);
                                	octets +=4;
                                	break;
				default:
					printf ("sks_panic: unknown gtp type(%d), system may crash...\n",gtpType );
					break;
                           	}
			}
                }

	}


/*retry timer callback.  need this since timercb in dpdk currently supports only one arg
 * and the segregate function takes 2 args since we need to know how we are calling
 * segregate (thru the nic rx or thru the cb, else we will be stuck in a forever loop
 * of retrying*/

//...design for control timer - when req msg comes, start timer
//...dpdk timers cannot be stopped (my understanding per current documentation)
//...when resp msg comes, set the timerout Indiator to 2 (cannot leave it as it is since we cleanup the
//...object hash table on startup, value of timeoutindicator is 0 by default.
//...when the req timer expires, we check for the timeout indicator flag, if it is 2 set it back to 0
//...indicating no timeout occured, else we set it to 1 indicating timeout occured.
//...basically reusing the timeout indicator flag.



static void pReqRespTimeoutTimerCb (__attribute__((unused)) struct rte_timer *tim,
                            __attribute__((unused)) void * key)
        {
        //printf ("SKS:  req/resp timer cb  called\n");
        //TODO: request has timeout out, write to csv file and close out

        int hashLoc ;
	hashLoc = rte_hash_lookup (pCtrlIdrHashTable, (const void *)key);

	printf ("sks: req resp timeout, now write to the file...hashLoc=%d\n", hashLoc);

	if (hashLoc > 0 )
		{	
		writeCSVFile (hashLoc);
		}
	else
		{
		printf ("sks: did not find in hash table, so could not write to the file\n");
		}
        
        rte_free (tim);
	rte_free ((union sessionId_2tuple_host *)key);
        }

static void pRespTimeoutTimerCb (__attribute__((unused)) struct rte_timer *tim,
                            __attribute__((unused)) void * pkt )
        {
        populateIDRTable (pkt, 1);
	}

#if 0
void 
idrCreate ( struct rte_mbuf *m )
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
        struct LteInfoAppend    *pLteAppend;
	uint64_t receivedSessionId=0x0;
	uint64_t pktRxTimeSecs=0x0;
	uint64_t pktRxTimeuSecs=0x0;

        lcore_id = rte_lcore_id();
        u_int16_t  type=0x0, ip_offset=0x0;

	createIdrControlAndUserRings ();

        detectedProtocol = dpiModule ( m );

        printf ("sks: detectedProtocol = 0x%x\n", detectedProtocol);
        packet = rte_pktmbuf_mtod(m, u_char *);

        ethernet = (struct ndpi_ethhdr *) packet;
        ip_offset = sizeof(struct ndpi_ethhdr);
        type = (u_int16_t)(ntohs(ethernet->h_proto));

        while(1) {
        if(type == 0x8100 /* VLAN */) {
        type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
        ip_offset += 4;
        } else if(type == 0x8847 /* MPLS */) {
        u_int32_t label = ntohl(*((const uint32_t*)&packet[ip_offset]));

        type = 0x800, ip_offset += 4;

        while((label & 0x100) != 0x100) {
                ip_offset += 4;
                label = ntohl(*((const uint32_t*)&packet[ip_offset]));
        }
        } else if(type == 0x8864 /* PPPoE */) {
        type = 0x0800;
        ip_offset += 8;
        } else
        break;
        }

        iph = (struct ndpi_iphdr *) &packet[ip_offset];
        ip_offset += ntohs (iph->tot_len);
        pLteAppend = (struct LteInfoAppend *)&packet[ip_offset];
        printf ("sks: magic=0x%x, fragmentId=0x%x, gtpSessionId=0x%x, uTimeStamp=0x%x,secondStamp=0x%x\n", pLteAppend->magic,pLteAppend->fragmentId, pLteAppend->gtpSessionId,pLteAppend->microSecondTimeStamp, pLteAppend->secondTimeStamp);
	receivedSessionId = pLteAppend->gtpSessionId;
	pktRxTimeSecs	  = pLteAppend->secondTimeStamp;
	pktRxTimeuSecs	  = pLteAppend->microSecondTimeStamp;

	//populateIDRTable (m,0,pLteAppend->gtpSessionId,pLteAppend->secondTimeStamp,pLteAppend->microSecondTimeStamp);
		
        //rte_pktmbuf_dump(m, rte_pktmbuf_pkt_len(m));
	}
#endif

int populateIDRTable(struct rte_mbuf *m, int repeatCount )
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
        union		sessionId_2tuple_host *pSessionIdKey;
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
        struct		rte_ring * pIdrControlRing;
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
	struct		LteInfoAppend *pLteAppend;
	uint32_t	pktRxTimeSecs= 0;
	uint32_t	pktRxTimeuSecs= 0;
	uint32_t	etherPadding= 0;




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
                                        	 resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pRespTimeoutTimerCb ,(void *)m);
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
				return Aok;
                                }
                        if (ret < 0)
                                {
                                printf ("sks UP lkup key not found: pad0=0x%x,pad1=0x%x,pad2=0x%x,ip_src=0x%x,ip_dst=0x%x:0x%x:0x%x:0x%x,pad3=0x%x,pad4=0x%x,pad5=0x%x,pad6=0x%x,flags=0x%x,teid=0x%x\n",
                               newKeyV6.pad0,newKeyV6.pad1,newKeyV6.pad2,newKeyV6.ip_src[0],newKeyV6.ip_dst[0],newKeyV6.ip_dst[1],newKeyV6.ip_dst[2],newKeyV6.ip_dst[3],newKeyV6.pad3,newKeyV6.pad4,newKeyV6.pad5,newKeyV6.pad6,newKeyV6.flagsMsgTypeAndLen,newKeyV6.teid);

                                ////TODO - session not yet initiated but we have xx user data, kickoff timer and wait.
                                //printf ("sks: entry does not exist for user plane pkt, returning...repeatCount=%d\n",repeatCount);
				if (repeatCount == 0 )
					{
                                        //printf ("sks:init timer case 2...\n");
                                        struct rte_timer * pUserPlaneTimer;
                                        pUserPlaneTimer = (struct rte_timer *) rte_malloc ("userplane timer",sizeof (struct rte_timer),0);
                                        int resetReturn = 0;
                                        rte_timer_init (pUserPlaneTimer);
                                        //printf ("sks: timer reset...\n");
                                        lcore_id = rte_lcore_id ();
                                        resetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pRespTimeoutTimerCb ,(void *)m);
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
                         keyV6.xmm[0] = _mm_and_si128(data0, ipV6HashMask0); //will be garbage for now
                         keyV6.xmm[1] = _mm_and_si128(data1, ipV6HashMask3);
                         keyV6.xmm[2] = _mm_and_si128(data2, ipV6HashMask1);
                         keyV6.xmm[3] = _mm_and_si128(data3, ipV6HashMask2);
			 pSessionIdKey = (union sessionId_2tuple_host *) rte_malloc ("ctrl resp timer",5*sizeof (uint16_t),0); 
			 bzero (pSessionIdKey, sizeof(pSessionIdKey));

			 pLteAppend = (struct LteInfoAppend *)((unsigned char *)ipv6_hdr + ipv6_hdr->payload_len);

        		 pSessionIdKey->sessionId = pLteAppend->gtpSessionId;
                         lcore_id = rte_lcore_id();
                         socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );

		         rte_snprintf(name, sizeof(name), "idrControlRing%u_io%u_sId4",
       				             socketid,
                    		             lcore_id);

         		 pIdrControlRing = rte_ring_lookup (name);

        		 pktRxTimeSecs     = pLteAppend->secondTimeStamp;
        		 pktRxTimeuSecs    = pLteAppend->microSecondTimeStamp;
 
			 printf ("sks: ipv6 gtp flags=0x%x\n", rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen));
                         if (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTP_VERSION1_IN_FLAGS)
                         	{
                                //GTPv1 processing
                                pGtpHeader = (struct GtpV1Header *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
	                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpHeader  + sizeof(struct GtpV1Header) + sizeof (uint16_t));
                                printf ("sks:gtpv1, switch = 0x%x\n", (int)((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & ALL_32_BITS )));
                                if ( rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTP_SEQ_NUMBER_PRESENT )
	                        	//...advance pGtpHeader pointer towards the control and data teids
	                                pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpParser  +  sizeof (uint16_t));

	                                //printf ("sks:ctrl plane pkt - recognized pdp request 0x%x \n", (int)(*pGtpParser) );
                                if ( rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTP_NPDU_PRESENT )
	       	                        pGtpParser      = (unsigned char *) ((unsigned char *)pGtpParser + sizeof (uint8_t));

                                switch ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 ))
                                        {
                                        case GTP_PDP_UPDATE_RESPONSE:
                                        case GTP_PDP_CONTEXT_RESPONSE:
                                        case GTP_PDP_DELETE_CONTEXT_RESPONSE:
					if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_DELETE_CONTEXT_RESPONSE)
	                                      	pSessionIdKey->msgType = GTP_PDP_DELETE_CONTEXT_REQUEST;//... search msg type=req since that is what is in hash
                                        if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_UPDATE_RESPONSE)
                                                pSessionIdKey->msgType = GTP_PDP_UPDATE_REQUEST;//... search msg type=req since that is what is in hash
                                        if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_CONTEXT_RESPONSE)
                                                pSessionIdKey->msgType = GTP_PDP_CONTEXT_REQUEST;//... search msg type=req since that is what is in hash


					ret = rte_hash_lookup (pCtrlIdrHashTable, (const void *)pSessionIdKey);
					if (ret > 0 )
						{
                                                        if (pIdrControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pIdrControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIdrHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIdrHashObjectArray[lcore_id][i]);
                                                                                pIdrHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIdrHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }

                                                        pIdrHashObjectArray[lcore_id][objCount] = (struct idrHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct idrHashObject),0);
                                                        bzero (pIdrHashObjectArray[lcore_id][objCount], sizeof (struct idrHashObject));
                                                        //...downlink ip and control plane teid.
                                                        pIdrHashObjectArray[lcore_id][objCount]->sessionId              = pLteAppend->gtpSessionId;
                                                        pIdrHashObjectArray[lcore_id][objCount]->msgType                = pSessionIdKey->msgType;
                                                        pIdrHashObjectArray[lcore_id][objCount]->origMsgType            = (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 );
                                                        pIdrHashObjectArray[lcore_id][objCount]->secs                   = pktRxTimeSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->usecs                  = pktRxTimeuSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->timeoutIndicator       = 1;

                                                        FillUpGtpV1ControlIdr (pGtpHeader,pGtpParser,pIdrHashObjectArray[lcore_id][objCount], ret);


                                                        ret = rte_ring_mp_enqueue (pIdrControlRing, (void *)pIdrHashObjectArray[lcore_id][objCount]);

                                                        printf ("sks: ring %s, ring count=%u\n", pIdrControlRing->name, rte_ring_count (pIdrControlRing));
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to IdrRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pIdrControlRing));
                                                        return Aok;
						}
					else
						{
						//...Response is coming before request.  park it and retry
						if (repeatCount > 0)
							{
							printf ("Control Request timeout\n");
							return;
							}
			                        struct rte_timer * pControlRequestTimer;
                                               	pControlRequestTimer = (struct rte_timer *) rte_malloc ("ctrl resp timer",sizeof (struct rte_timer),0);
                                                int resetReturn = 0;
                                                rte_timer_init (pControlRequestTimer);
                                                lcore_id = rte_lcore_id ();
	                                        resetReturn = rte_timer_reset (pControlRequestTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pRespTimeoutTimerCb,m);
						}	
					break;
                                        case GTP_PDP_UPDATE_REQUEST:
                                        case GTP_PDP_CONTEXT_REQUEST:
                                        case GTP_PDP_DELETE_CONTEXT_REQUEST:
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_UPDATE_REQUEST)
                                                        pSessionIdKey->msgType = GTP_PDP_UPDATE_REQUEST;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_DELETE_CONTEXT_REQUEST)
                                                        pSessionIdKey->msgType = GTP_PDP_DELETE_CONTEXT_REQUEST;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_CONTEXT_REQUEST)
                                                        pSessionIdKey->msgType = GTP_PDP_CONTEXT_REQUEST;//... search msg type=req since that is what is in hash


						struct rte_timer * pControlRequestTimer;
                                                pControlRequestTimer = (struct rte_timer *) rte_malloc ("ctrl req/resp timer",sizeof (struct rte_timer),0);
                                                int resetReturn = 0;
                                                rte_timer_init (pControlRequestTimer);
                                                lcore_id = rte_lcore_id ();
						ret = rte_hash_lookup (pCtrlIdrHashTable, (const void *)pSessionIdKey);
						printf ("sks: populateIDR: gtp_pdp_context_request\n");
						if (ret > 0)
							{
							//...Duplicate
							printf ("sks: Duplicate pdp delete context request received...\n");
							return;
							}
						else
							{
	                                                resetReturn = rte_timer_reset (pControlRequestTimer,RETRY_TIMEOUT*3,SINGLE,lcore_id,pReqRespTimeoutTimerCb,(void *)pSessionIdKey);

                                                       	if (pIdrControlRing == NULL )
                                                              	{
                                                               	printf ("Cannot find ring %s\n", name);
                                                               	return Aok;
                                                               	}

                                                       	if (rte_ring_empty (pIdrControlRing))
                                                               	{
                                                               	printf ("setting all ring entries to NULL\n");
                                                               	for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                       	{
                                                                    	//...Can optimize more here TODO
                                                                       	if(pIdrHashObjectArray[lcore_id][i])
                                                                              	{
                                                                               	rte_free (pIdrHashObjectArray[lcore_id][i]);
                                                                               	pIdrHashObjectArray[lcore_id][i] = NULL;
                                                                               	}
                                                                       	}
                                                               	}

                                                       	while (pIdrHashObjectArray[lcore_id][objCount] != NULL )
                                                               	objCount++;

                                                       	if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                               	{
                                                               	printf ("FATAL: dropping pdp request msg\n");
                                                               	return Aok;
                                                               	}

                                                       	pIdrHashObjectArray[lcore_id][objCount] = (struct idrHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct idrHashObject),0);
							bzero (pIdrHashObjectArray[lcore_id][objCount], sizeof (struct idrHashObject));
                                                       	//...downlink ip and control plane teid.

                                                      	pIdrHashObjectArray[lcore_id][objCount]->sessionId      	= pLteAppend->gtpSessionId;
                                                       	pIdrHashObjectArray[lcore_id][objCount]->msgType	      	= pSessionIdKey->msgType;
                                                       	pIdrHashObjectArray[lcore_id][objCount]->secs	      		= pktRxTimeSecs;
                                                       	pIdrHashObjectArray[lcore_id][objCount]->usecs	      		= pktRxTimeuSecs;
                                                       	pIdrHashObjectArray[lcore_id][objCount]->ipV6SrcAddr[0]	     	= rte_cpu_to_be_32(keyV6.ip_src[0]);
                                                       	pIdrHashObjectArray[lcore_id][objCount]->ipV6SrcAddr[1]	     	= rte_cpu_to_be_32(keyV6.ip_src[1]);
                                                       	pIdrHashObjectArray[lcore_id][objCount]->ipV6SrcAddr[2]	     	= rte_cpu_to_be_32(keyV6.ip_src[2]);
                                                       	pIdrHashObjectArray[lcore_id][objCount]->ipV6SrcAddr[3]	     	= rte_cpu_to_be_32(keyV6.ip_src[3]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6DstAddr[0]         = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6DstAddr[1]         = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6DstAddr[2]         = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6DstAddr[3]         = rte_cpu_to_be_32(keyV6.ip_dst[3]);
							
							//...before enqueing in the ring, fill up the rest of the hash object
							//
							FillUpGtpV1ControlIdr (pGtpHeader,pGtpParser,pIdrHashObjectArray[lcore_id][objCount], ret);

                                                       	ret = rte_ring_mp_enqueue (pIdrControlRing, (void *)pIdrHashObjectArray[lcore_id][objCount]);

							printf ("sks: ring %s, ring count=%u\n", pIdrControlRing->name, rte_ring_count (pIdrControlRing));
                                                       	if (ret != 0 )
                                                               	{
                                                               	printf ("error in enqueuing to IdrRing\n");
                                                               	return Aok;
                                                               	}
                                                       	printf ("sks:ring count %d\n", rte_ring_count (pIdrControlRing));
							return Aok;
                                                       	}
                                               break;
                                               }
                                       }//gtpv1 case closure

			          if (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTP_VERSION2_IN_FLAGS)
                                        {
                                        //GTPv2 processing, but gtp header info is the same so reuse v1 hdr
                                        //printf ("sks:gtpv2, switch = 0x%x\n", (int)((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & ALL_32_BITS )));
                                        if (rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & GTPV2_TEID_PRESENT)
                                        	{
                                                pGtpV2Header = (struct GtpV2Header *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
                                                pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header) );
                                                }
                                        else
                                                {
                                                pGtpV2Header = (struct GtpV2Header_noTeid *)((unsigned char *)ipv6_hdr + sizeof(struct ipv6_hdr) + sizeof (struct udp_hdr) );
                                                pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header_noTeid) );
                                                }

                                        switch ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 ))
                                                {
                                                case GTPV2_TYPE_REL_ACC_BEARER_RSP   :
                                                case GTPV2_TYPE_DEL_SESSION_RSP      :
                                                case GTPV2_CREATE_BEARER_RESPONSE    :
                                                case GTPV2_MODIFY_BEARER_RESPONSE    :
                                                case GTPV2_CREATE_SESSION_RESPONSE   :
 
                                        	if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_TYPE_REL_ACC_BEARER_RSP)
                                                	pSessionIdKey->msgType =GTPV2_TYPE_REL_ACC_BEARER_REQ ;//... search msg type=req since that is what is in hash
                                        	if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_TYPE_DEL_SESSION_RSP)
                                                	pSessionIdKey->msgType = GTPV2_TYPE_DEL_SESSION_REQ;//... search msg type=req since that is what is in hash
                                        	if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_BEARER_RESPONSE)
                                                	pSessionIdKey->msgType = GTPV2_CREATE_BEARER_REQUEST;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_MODIFY_BEARER_RESPONSE)
                                                        pSessionIdKey->msgType =GTPV2_MODIFY_BEARER_REQUEST ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_SESSION_RESPONSE )
                                                        pSessionIdKey->msgType = GTPV2_CREATE_SESSION_REQUEST;//... search msg type=req since that is what is in hash


                                        	ret = rte_hash_lookup (pCtrlIdrHashTable, (const void *)pSessionIdKey);
                                        	if (ret > 0 )
                                                	{
                                                	ctrlIdrHashTable[ret].timeoutIndicator = 2;
                                                	ctrlIdrHashTable[ret].endmSecs = pktRxTimeSecs;
                                                	ctrlIdrHashTable[ret].enduSecs = pktRxTimeuSecs;
                                        		FillUpGtpV2ControlIdr (pGtpV2Header,pGtpParser ,NULL, ret);
                                                	}
                                        	else
                                                	{
                                                	//...Response is coming before request.  park it and retry
                                                	if (repeatCount > 0)
                                                        	{
                                                        	printf ("Control Request timeout\n");
                                                        	return;
                                                        	}
                                                	struct rte_timer * pControlRequestTimer;
                                                	pControlRequestTimer = (struct rte_timer *) rte_malloc ("ctrl resp timer",sizeof (struct rte_timer),0);
                                                	int resetReturn = 0;
                                                	rte_timer_init (pControlRequestTimer);
                                                	lcore_id = rte_lcore_id ();
                                                	resetReturn = rte_timer_reset (pControlRequestTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pRespTimeoutTimerCb,m);
                                                	}
						break;

                                                case GTPV2_TYPE_REL_ACC_BEARER_REQ   :
                                                case GTPV2_TYPE_DEL_SESSION_REQ      :
                                                case GTPV2_CREATE_BEARER_REQUEST     :
                                                case GTPV2_MODIFY_BEARER_REQUEST     :
                                                case GTPV2_CREATE_SESSION_REQUEST    :

                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_TYPE_REL_ACC_BEARER_REQ)
                                                        pSessionIdKey->msgType =GTPV2_TYPE_REL_ACC_BEARER_REQ ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_TYPE_DEL_SESSION_REQ)
                                                        pSessionIdKey->msgType = GTPV2_TYPE_DEL_SESSION_REQ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_BEARER_REQUEST)
                                                        pSessionIdKey->msgType = GTPV2_CREATE_BEARER_REQUEST;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_MODIFY_BEARER_REQUEST)
                                                        pSessionIdKey->msgType =GTPV2_MODIFY_BEARER_REQUEST ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(keyV6.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_SESSION_REQUEST )
                                                        pSessionIdKey->msgType = GTPV2_CREATE_SESSION_REQUEST;//... search msg type=req since that is what is in hash


                                                struct rte_timer * pControlRequestTimer;
                                                pControlRequestTimer = (struct rte_timer *) rte_malloc ("ctrl req/resp timer",sizeof (struct rte_timer),0);
                                                int resetReturn = 0;
                                                rte_timer_init (pControlRequestTimer);
                                                lcore_id = rte_lcore_id ();
                                                ret = rte_hash_lookup (pCtrlIdrHashTable, (const void *)pSessionIdKey);
                                                if (ret > 0)
                                                        {
                                                        //...Duplicate
                                                        printf ("sks: Duplicate pdp delete context request received...\n");
                                                        return;
                                                        }
                                                else
                                                        {
                                                        resetReturn = rte_timer_reset (pControlRequestTimer,RETRY_TIMEOUT*3,SINGLE,lcore_id,pReqRespTimeoutTimerCb,(void *)pSessionIdKey);

                                                        if (pIdrControlRing == NULL )
                                                                {                                                                
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pIdrControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIdrHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIdrHashObjectArray[lcore_id][i]);
                                                                                pIdrHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIdrHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }

                                                        pIdrHashObjectArray[lcore_id][objCount] = (struct idrHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct idrHashObject),0);
                                                        bzero (pIdrHashObjectArray[lcore_id][objCount], sizeof (struct idrHashObject));
                                                        //...downlink ip and control plane teid.

                                                        pIdrHashObjectArray[lcore_id][objCount]->sessionId              = pLteAppend->gtpSessionId;
                                                        pIdrHashObjectArray[lcore_id][objCount]->msgType                = pSessionIdKey->msgType;
                                                        pIdrHashObjectArray[lcore_id][objCount]->secs                   = pktRxTimeSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->usecs                  = pktRxTimeuSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6SrcAddr[0]         = rte_cpu_to_be_32(keyV6.ip_src[0]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6SrcAddr[1]         = rte_cpu_to_be_32(keyV6.ip_src[1]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6SrcAddr[2]         = rte_cpu_to_be_32(keyV6.ip_src[2]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6SrcAddr[3]         = rte_cpu_to_be_32(keyV6.ip_src[3]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6DstAddr[0]         = rte_cpu_to_be_32(keyV6.ip_dst[0]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6DstAddr[1]         = rte_cpu_to_be_32(keyV6.ip_dst[1]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6DstAddr[2]         = rte_cpu_to_be_32(keyV6.ip_dst[2]);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV6DstAddr[3]         = rte_cpu_to_be_32(keyV6.ip_dst[3]);


                                                        ret = rte_ring_mp_enqueue (pIdrControlRing, (void *)pIdrHashObjectArray[lcore_id][objCount]);

                                                        printf ("sks: ring %s, ring count=%u\n", pIdrControlRing->name, rte_ring_count (pIdrControlRing));
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to IdrRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pIdrControlRing));
                                                        return Aok;
                                                        }

                                                break;

						}//switch closure

                                        }//...gtpv2 closure

                                } //control plane if statement
		}//ipv6 closure
  
	if (ipPktType == PACKET_TYPE_IPV4) { if ( ipv4_hdr->next_proto_id    != IPPROTO_UDP ) {
			return Aok;
                        }
                pUdpHeader = (struct udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
		udpPortSrc = (uint16_t)(rte_cpu_to_be_16(pUdpHeader->src_port));
		udpPortDst = (uint16_t)(rte_cpu_to_be_16(pUdpHeader->dst_port));
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
                                        //sksremoveresetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pReqRespTimeoutTimerCb ,(void *)m);
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
                        printf ("sks:populateIDR first key.flagsMsgTypeAndLen = 0x%x key.ip_src=0x%x, key.ip_dst=0x%x,key.teid=0x%x\n", key.flagsMsgTypeAndLen,key.ip_src,key.ip_dst,key.teid);

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
				return Aok;
                                }
			if (ret < 0)
				{
				////TODO - session not yet initiated but we have rx user data, kickoff timer and wait.
                                printf ("sks: entry does not exist for user plane pkt, repeatCount=%d returning...\n", repeatCount);
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
                                        //sksremoveresetReturn = rte_timer_reset (pUserPlaneTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pReqRespTimeoutTimerCb ,(void *)m);
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
                                        data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)));
                                        data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i)));
					if ( (sizeof(struct ether_hdr) + rte_cpu_to_be_16(ipv4_hdr->total_length)) < 60 )
						etherPadding = 60 - (sizeof(struct ether_hdr) + rte_cpu_to_be_16(ipv4_hdr->total_length));
					printf ("sks: etherPadding = 0x%x\n",etherPadding);
                                        data2 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)   + rte_cpu_to_be_16(ipv4_hdr->total_length) + etherPadding));
                                        data3 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)   + rte_cpu_to_be_16(ipv4_hdr->total_length) + sizeof(__m128i)+ etherPadding));
                                        }
                                else
                                        {
                                        data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live) + sizeof(uint16_t)));
                                        data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i)+ sizeof(uint16_t)));
                                        if ( (sizeof(struct ether_hdr) + rte_cpu_to_be_16(ipv4_hdr->total_length)) < 60 )
                                                etherPadding = 60 - (sizeof(struct ether_hdr) + rte_cpu_to_be_16(ipv4_hdr->total_length));
                                        printf ("sks: etherPadding = 0x%x\n",etherPadding);
                                        data2 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) +sizeof(uint16_t)   + rte_cpu_to_be_16(ipv4_hdr->total_length) + etherPadding));
                                        data3 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr) +sizeof(uint16_t)  + rte_cpu_to_be_16(ipv4_hdr->total_length) + sizeof(__m128i)+ etherPadding));
                                        }
				}
			else
				{
                                data0 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv4_hdr,time_to_live)));
                                data1 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)  + sizeof (struct vlan_hdr) + offsetof(struct ipv4_hdr,time_to_live)+sizeof(__m128i)));

                                if ( (sizeof(struct ether_hdr) + rte_cpu_to_be_16(ipv4_hdr->total_length)) < 60 )
                                        etherPadding = 60 - (sizeof(struct ether_hdr) + rte_cpu_to_be_16(ipv4_hdr->total_length));
                                printf ("sks: etherPadding = 0x%x\n",etherPadding);
                                data2 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)   + rte_cpu_to_be_16(ipv4_hdr->total_length) + etherPadding));
                                data3 = _mm_loadu_si128((__m128i*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)   + rte_cpu_to_be_16(ipv4_hdr->total_length) + sizeof(__m128i)+ etherPadding));

				}

			union lteInfoRead appendHdr;
			key.xmm[0] = data0;
			key.xmm[1] = data1;
			appendHdr.xmm[0]=data2;
			appendHdr.xmm[1]=data3;

			printf ("sks:populateIDR: magic =0x%x, reserved0=0x%x, fragId=0x%x,sessId=0x%x, mTs=0x%x, sTs=0x%x \n",appendHdr.magic, appendHdr.reserved0,appendHdr.fragmentId, appendHdr.gtpSessionId,
appendHdr.microSecondTimeStamp, appendHdr.secondTimeStamp);
                         pSessionIdKey = (union sessionId_2tuple_host *) rte_malloc ("ctrl resp timer",5*sizeof (uint16_t),0);
                         bzero (pSessionIdKey, sizeof(pSessionIdKey));

                         pSessionIdKey->sessionId = appendHdr.gtpSessionId;
                         lcore_id = rte_lcore_id();
                         socketid = rte_lcore_to_socket_id(rte_lcore_id( ) );

                         rte_snprintf(name, sizeof(name), "idrControlRing%u_io%u_sId4",
                                             socketid,
                                             lcore_id);

                         pIdrControlRing = rte_ring_lookup (name);

                         pktRxTimeSecs     = appendHdr.secondTimeStamp;
                         pktRxTimeuSecs    = appendHdr.microSecondTimeStamp;

                                if (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTP_VERSION1_IN_FLAGS)
                                        {
                                        //GTPv1 processing
                                        pGtpHeader = (struct GtpV1Header *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
					pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpHeader  + sizeof(struct GtpV1Header) + sizeof (uint16_t));
                                if ( rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTP_SEQ_NUMBER_PRESENT )
                                        //...advance pGtpHeader pointer towards the control and data teids
                                        pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpParser  +  sizeof (uint16_t));

                                        //printf ("sks:ctrl plane pkt - recognized pdp request 0x%x \n", (int)(*pGtpParser) );
                                if ( rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTP_NPDU_PRESENT )
                                        pGtpParser      = (unsigned char *) ((unsigned char *)pGtpParser + sizeof (uint8_t));

					switch ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 ))
						{
						case GTP_PDP_UPDATE_RESPONSE:
                                        	case GTP_PDP_CONTEXT_RESPONSE:
                                        	case GTP_PDP_DELETE_CONTEXT_RESPONSE:
                                        	if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_DELETE_CONTEXT_RESPONSE)
                                                	pSessionIdKey->msgType = GTP_PDP_DELETE_CONTEXT_REQUEST;//... search msg type=req since that is what is in hash

                                        	if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_UPDATE_RESPONSE)
                                                	pSessionIdKey->msgType = GTP_PDP_UPDATE_REQUEST;//... search msg type=req since that is what is in hash

                                        	if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_CONTEXT_RESPONSE)
                                                	pSessionIdKey->msgType = GTP_PDP_CONTEXT_REQUEST;//... search msg type=req since that is what is in hash


						printf ("sks:populateIDR:request resp received sessId= 0x%x, msgType = 0x%x\n",  pSessionIdKey->sessionId,pSessionIdKey->msgType);

                                        	ret = rte_hash_lookup (pCtrlIdrHashTable, (const void *)pSessionIdKey);
                                        	if (ret > 0 )
                                                	{
                                                        if (pIdrControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pIdrControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIdrHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIdrHashObjectArray[lcore_id][i]);
                                                                                pIdrHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIdrHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }

                                                        pIdrHashObjectArray[lcore_id][objCount] = (struct idrHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct idrHashObject),0);
                                                        bzero (pIdrHashObjectArray[lcore_id][objCount], sizeof (struct idrHashObject));
                                                        //...downlink ip and control plane teid.
                                                        pIdrHashObjectArray[lcore_id][objCount]->sessionId              = appendHdr.gtpSessionId;
                                                        pIdrHashObjectArray[lcore_id][objCount]->msgType                = pSessionIdKey->msgType;
                                                        pIdrHashObjectArray[lcore_id][objCount]->origMsgType            = (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 );
                                                        pIdrHashObjectArray[lcore_id][objCount]->secs                   = pktRxTimeSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->usecs                  = pktRxTimeuSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->timeoutIndicator       = 1;

                                                        FillUpGtpV1ControlIdr (pGtpHeader,pGtpParser,pIdrHashObjectArray[lcore_id][objCount], ret);


                                                        ret = rte_ring_mp_enqueue (pIdrControlRing, (void *)pIdrHashObjectArray[lcore_id][objCount]);

                                                        printf ("sks: ring %s, ring count=%u\n", pIdrControlRing->name, rte_ring_count (pIdrControlRing));
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to IdrRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pIdrControlRing));
							return Aok;
                                                	}
                                        	else
                                                	{
                                                	//...Response is coming before request.  park it and retry
                                                	printf ("response came in before request....try again...\n");
                                                	if (repeatCount > 0)
                                                       		{
                                                       		printf ("Control Request timeout\n");
                                                       		return;
                                                       		}
                                                	struct rte_timer * pControlRequestTimer;
                                                	pControlRequestTimer = (struct rte_timer *) rte_malloc ("ctrl resp timer",sizeof (struct rte_timer),0);
                                                	int resetReturn = 0;
                                                	rte_timer_init (pControlRequestTimer);
                                                	lcore_id = rte_lcore_id ();
                                                	resetReturn = rte_timer_reset (pControlRequestTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pRespTimeoutTimerCb,m);
							return;
                                                	}
						break;  //ctxt req/resp case
                                        case GTP_PDP_UPDATE_REQUEST:
                                        case GTP_PDP_CONTEXT_REQUEST:
                                        case GTP_PDP_DELETE_CONTEXT_REQUEST:
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_UPDATE_REQUEST)
                                                        pSessionIdKey->msgType = GTP_PDP_UPDATE_REQUEST;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_DELETE_CONTEXT_REQUEST)
                                                        pSessionIdKey->msgType = GTP_PDP_DELETE_CONTEXT_REQUEST;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTP_PDP_CONTEXT_REQUEST)
                                                        pSessionIdKey->msgType = GTP_PDP_CONTEXT_REQUEST;//... search msg type=req since that is what is in hash


                                                struct rte_timer * pControlRequestTimer;
                                                pControlRequestTimer = (struct rte_timer *) rte_malloc ("ctrl req/resp timer",sizeof (struct rte_timer),0);
                                                int resetReturn = 0;
                                                rte_timer_init (pControlRequestTimer);
                                                lcore_id = rte_lcore_id ();
                                                ret = rte_hash_lookup (pCtrlIdrHashTable, (const void *)pSessionIdKey);
						printf ("sks:populateIDR:requests received sessId= 0x%x, msgType = 0x%x\n", pSessionIdKey->sessionId,pSessionIdKey->msgType);

                                                if (ret > 0)
                                                        {
                                                        //...Duplicate
                                                        printf ("sks: Duplicate pdp delete context request received...\n");
                                                        return;
                                                        }
                                                else
                                                        {
                                                        resetReturn = rte_timer_reset (pControlRequestTimer,RETRY_TIMEOUT*3,SINGLE,lcore_id,pReqRespTimeoutTimerCb,(void *)pSessionIdKey);

                                                        if (pIdrControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pIdrControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIdrHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIdrHashObjectArray[lcore_id][i]);
                                                                                pIdrHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIdrHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
			 printf ("sks:populateIDR key.flagsMsgTypeAndLen = 0x%x key.ip_src=0x%x, key.ip_dst=0x%x,rxtim=%x/%x\n", key.flagsMsgTypeAndLen,key.ip_src,key.ip_dst,pktRxTimeSecs,pktRxTimeuSecs);
                                                                return Aok;
                                                                }

                                                        pIdrHashObjectArray[lcore_id][objCount] = (struct idrHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct idrHashObject),0);
                                                        bzero (pIdrHashObjectArray[lcore_id][objCount], sizeof (struct idrHashObject));
                                                        //...downlink ip and control plane teid.

                                                        pIdrHashObjectArray[lcore_id][objCount]->sessionId              = appendHdr.gtpSessionId;
                                                        pIdrHashObjectArray[lcore_id][objCount]->gtpVersion             = 1;
                                                        pIdrHashObjectArray[lcore_id][objCount]->msgType                = pSessionIdKey->msgType;
                                                        pIdrHashObjectArray[lcore_id][objCount]->origMsgType            = (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 );
                                                        pIdrHashObjectArray[lcore_id][objCount]->secs                   = pktRxTimeSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->usecs                  = pktRxTimeuSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV4SrcAddr         	= rte_cpu_to_be_32(key.ip_src);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV4DstAddr         	= rte_cpu_to_be_32(key.ip_dst);

							FillUpGtpV1ControlIdr (pGtpHeader,pGtpParser,pIdrHashObjectArray[lcore_id][objCount], ret);

                                                        ret = rte_ring_mp_enqueue (pIdrControlRing, (void *)pIdrHashObjectArray[lcore_id][objCount]);

                                                        printf ("sks: ring %s, ring count=%u\n", pIdrControlRing->name, rte_ring_count (pIdrControlRing));
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to IdrRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pIdrControlRing));
                                                        return Aok;
                                                        }
                                                break;

						}
					}//gtpv1 case closure

                                  if (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTP_VERSION2_IN_FLAGS)
                                        {
                                        if (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & GTPV2_TEID_PRESENT)
                                                {
                                                pGtpV2Header = (struct GtpV2Header *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
                                                pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header) );
                                                }
                                        else
                                                {
                                                pGtpV2Header = (struct GtpV2Header_noTeid *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr) + sizeof (struct udp_hdr) );
                                                pGtpParser = (unsigned char * ) ( (unsigned char *)pGtpV2Header  + sizeof(struct GtpV2Header_noTeid) );
                                                }
					printf ("sks: populateIDR: gtpv2 pkt detected msgtype = 0x%x\n", (rte_cpu_to_be_32(key.flagsMsgTypeAndLen)& 0x00FF0000));
                                        switch ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 ))
                                                {
                                        	case GTPV2_TYPE_REL_ACC_BEARER_RSP   :
                                        	case GTPV2_TYPE_DEL_SESSION_RSP      :
                                        	case GTPV2_CREATE_BEARER_RESPONSE    :
                                        	case GTPV2_MODIFY_BEARER_RESPONSE    :
                                        	case GTPV2_CREATE_SESSION_RESPONSE   :

                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_TYPE_REL_ACC_BEARER_RSP)
                                                        pSessionIdKey->msgType =GTPV2_TYPE_REL_ACC_BEARER_REQ ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_TYPE_DEL_SESSION_RSP)
                                                        pSessionIdKey->msgType = GTPV2_TYPE_DEL_SESSION_REQ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_BEARER_RESPONSE)
                                                        pSessionIdKey->msgType = GTPV2_CREATE_BEARER_REQUEST;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_MODIFY_BEARER_RESPONSE)
                                                        pSessionIdKey->msgType =GTPV2_MODIFY_BEARER_REQUEST ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_SESSION_RESPONSE )
                                                        pSessionIdKey->msgType = GTPV2_CREATE_SESSION_REQUEST;//... search msg type=req since that is what is in hash

                                                ret = rte_hash_lookup (pCtrlIdrHashTable, (const void *)pSessionIdKey);
                                                if (ret > 0 )
                                                        {
                                                        if (pIdrControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pIdrControlRing))
                                                                {
                                                                printf ("setting all ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIdrHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIdrHashObjectArray[lcore_id][i]);
                                                                                pIdrHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIdrHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }

                                                        pIdrHashObjectArray[lcore_id][objCount] = (struct idrHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct idrHashObject),0);
                                                        bzero (pIdrHashObjectArray[lcore_id][objCount], sizeof (struct idrHashObject));
                                                        //...downlink ip and control plane teid.
                                                        pIdrHashObjectArray[lcore_id][objCount]->sessionId              = appendHdr.gtpSessionId;
                                                        pIdrHashObjectArray[lcore_id][objCount]->msgType                = pSessionIdKey->msgType;
                                                        pIdrHashObjectArray[lcore_id][objCount]->origMsgType            = (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 );
                                                        pIdrHashObjectArray[lcore_id][objCount]->secs                   = pktRxTimeSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->usecs                  = pktRxTimeuSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->timeoutIndicator       = 1;

                                                        FillUpGtpV2ControlIdr (pGtpV2Header,pGtpParser,pIdrHashObjectArray[lcore_id][objCount], ret);


                                                        ret = rte_ring_mp_enqueue (pIdrControlRing, (void *)pIdrHashObjectArray[lcore_id][objCount]);
                                                        printf ("sks: ring %s, ring count=%u\n", pIdrControlRing->name, rte_ring_count (pIdrControlRing));
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to IdrRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pIdrControlRing));
                                                        return Aok;

                                                        }
                                                else
                                                        {
                                                        //...Response is coming before request.  park it and retry
                                                        printf ("populateIDR: response came in before request, trying again....\n");
                                                        if (repeatCount > 0)
                                                                {
                                                                printf ("Control Request timeout\n");
                                                                return;
                                                                }
                                                        struct rte_timer * pControlRequestTimer;
                                                        pControlRequestTimer = (struct rte_timer *) rte_malloc ("ctrl resp timer",sizeof (struct rte_timer),0);
                                                        int resetReturn = 0;
                                                        rte_timer_init (pControlRequestTimer);
                                                        lcore_id = rte_lcore_id ();
                                                        resetReturn = rte_timer_reset (pControlRequestTimer,RETRY_TIMEOUT,SINGLE,lcore_id,pRespTimeoutTimerCb,m);
                                                        }
                                                break;  //ctxt req/resp case


						case GTPV2_TYPE_REL_ACC_BEARER_REQ   :
                                                case GTPV2_TYPE_DEL_SESSION_REQ      :
                                                case GTPV2_CREATE_BEARER_REQUEST     :
                                                case GTPV2_MODIFY_BEARER_REQUEST     :
                                                case GTPV2_CREATE_SESSION_REQUEST    :

                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_TYPE_REL_ACC_BEARER_REQ)
                                                        pSessionIdKey->msgType =GTPV2_TYPE_REL_ACC_BEARER_REQ ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_TYPE_DEL_SESSION_REQ)
                                                        pSessionIdKey->msgType = GTPV2_TYPE_DEL_SESSION_REQ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_BEARER_REQUEST)
                                                        pSessionIdKey->msgType = GTPV2_CREATE_BEARER_REQUEST;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_MODIFY_BEARER_REQUEST)
                                                        pSessionIdKey->msgType =GTPV2_MODIFY_BEARER_REQUEST ;//... search msg type=req since that is what is in hash
                                                if ((rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 )== GTPV2_CREATE_SESSION_REQUEST )
                                                        pSessionIdKey->msgType = GTPV2_CREATE_SESSION_REQUEST;//... search msg type=req since that is what is in hash


                                                struct rte_timer * pControlRequestTimer;
                                                pControlRequestTimer = (struct rte_timer *) rte_malloc ("ctrl req/resp timer",sizeof (struct rte_timer),0);
                                                int resetReturn = 0;
                                                rte_timer_init (pControlRequestTimer);
                                                lcore_id = rte_lcore_id ();
                                                ret = rte_hash_lookup (pCtrlIdrHashTable, (const void *)pSessionIdKey);
                                                if (ret > 0)
                                                        {
                                                        //...Duplicate
                                                        printf ("sks: Duplicate pdp delete context request received...\n");
                                                        return;
                                                        }
                                                else
                                                        {
							printf ("populateIDR:sks: gtpv2 req msg rx, creating hash entry\n");
                                                        resetReturn = rte_timer_reset (pControlRequestTimer,RETRY_TIMEOUT*3,SINGLE,lcore_id,pReqRespTimeoutTimerCb,(void *)pSessionIdKey);

                                                        if (pIdrControlRing == NULL )
                                                                {
                                                                printf ("Cannot find ring %s\n", name);
                                                                return Aok;
                                                                }

                                                        if (rte_ring_empty (pIdrControlRing))
                                                                {
                                                                printf ("setting all idr ring entries to NULL\n");
                                                                for (i=0;i<MAX_HASH_OBJECT_PER_REQUEST;i++)
                                                                        {
                                                                        //...Can optimize more here TODO
                                                                        if(pIdrHashObjectArray[lcore_id][i])
                                                                                {
                                                                                rte_free (pIdrHashObjectArray[lcore_id][i]);
                                                                                pIdrHashObjectArray[lcore_id][i] = NULL;
                                                                                }
                                                                        }
                                                                }

                                                        while (pIdrHashObjectArray[lcore_id][objCount] != NULL )
                                                                objCount++;

                                                        if (objCount > MAX_HASH_OBJECT_PER_REQUEST )
                                                                {
                                                                printf ("FATAL: dropping pdp request msg\n");
                                                                return Aok;
                                                                }
                                                        pIdrHashObjectArray[lcore_id][objCount] = (struct idrHashObject *) rte_malloc ("hash object  v6 array",sizeof(struct idrHashObject),0);
                                                        bzero (pIdrHashObjectArray[lcore_id][objCount], sizeof (struct idrHashObject));
                                                        //...downlink ip and control plane teid.

                                                        pIdrHashObjectArray[lcore_id][objCount]->sessionId              = appendHdr.gtpSessionId;
                                                        pIdrHashObjectArray[lcore_id][objCount]->msgType                = pSessionIdKey->msgType;
                                                        pIdrHashObjectArray[lcore_id][objCount]->origMsgType            = (rte_cpu_to_be_32(key.flagsMsgTypeAndLen) & 0x00FF0000 );

                                                        pIdrHashObjectArray[lcore_id][objCount]->secs                   = pktRxTimeSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->usecs                  = pktRxTimeuSecs;
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV4SrcAddr            = rte_cpu_to_be_32(key.ip_src);
                                                        pIdrHashObjectArray[lcore_id][objCount]->ipV4DstAddr            = rte_cpu_to_be_32(key.ip_dst);

							printf ("populateIDR:sks:lcoreid(%u), objCount(%u),sid=0x%x,mtype=0x%x\n", lcore_id, objCount,appendHdr.gtpSessionId, pSessionIdKey->msgType);

                                                	FillUpGtpV2ControlIdr (pGtpV2Header,pGtpParser ,pIdrHashObjectArray[lcore_id][objCount], ret);
                                                        ret = rte_ring_mp_enqueue (pIdrControlRing, (void *)pIdrHashObjectArray[lcore_id][objCount]);

                                                        //printf ("sks: ring %s, ring count=%u\n", pIdrControlRing->name, rte_ring_count (pIdrControlRing));
                                                        if (ret != 0 )
                                                                {
                                                                printf ("error in enqueuing to IdrRing\n");
                                                                return Aok;
                                                                }
                                                        printf ("sks:ring count %d\n", rte_ring_count (pIdrControlRing));
                                                        return Aok;
                                                        }
                                                break;
						} //...switch end

                                        }//...gtpv2 closure

                                } //control plane if statement
                        }//ipv4 if statement

	return Aok;
}



