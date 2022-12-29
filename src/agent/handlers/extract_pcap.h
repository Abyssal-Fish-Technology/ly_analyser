
#include <features.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

/* Courtesy of Curt Sampson  <cjs@cynic.net> */
#include <netinet/if_ether.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define LONG_SNAPLEN             1600

typedef struct ether80211q {
  u_int16_t vlanId;
  u_int16_t protoType;
} Ether80211q;

#ifndef TH_FIN
#define	TH_FIN	0x01
#endif
#ifndef TH_SYN
#define	TH_SYN	0x02
#endif
#ifndef TH_RST
#define	TH_RST	0x04
#endif
#ifndef TH_PUSH
#define	TH_PUSH	0x08
#endif
#ifndef TH_ACK
#define	TH_ACK	0x10
#endif
#ifndef TH_URG
#define	TH_URG	0x20
#endif

// /*
//  * TCP header.
//  * Per RFC 793, September, 1981.
//  */
// struct tcphdr {
// 	u_short	th_sport;		/* source port */
// 	u_short	th_dport;		/* destination port */
// 	tcp_seq	th_seq;			/* sequence number */
// 	tcp_seq	th_ack;			/* acknowledgement number */
// #if BYTE_ORDER == LITTLE_ENDIAN
// 	u_char	th_x2:4,		/* (unused) */
// 		th_off:4;		/* data offset */
// #else
// 	u_char	th_off:4,		/* data offset */
// 		th_x2:4;		/* (unused) */
// #endif
// 	u_char	th_flags;
// 	u_short	th_win;			/* window */
// 	u_short	th_sum;			/* checksum */
// 	u_short	th_urp;			/* urgent pointer */
// };

// /* ********************************************* */

// struct ip {
// #if BYTE_ORDER == LITTLE_ENDIAN
// 	u_char	ip_hl:4,		/* header length */
// 		ip_v:4;			/* version */
// #else
// 	u_char	ip_v:4,			/* version */
// 		ip_hl:4;		/* header length */
// #endif
// 	u_char	ip_tos;			/* type of service */
// 	short	ip_len;			/* total length */
// 	u_short	ip_id;			/* identification */
// 	short	ip_off;			/* fragment offset field */
// #define	IP_DF 0x4000			/* dont fragment flag */
// #define	IP_MF 0x2000			/* more fragments flag */
// #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
// 	u_char	ip_ttl;			/* time to live */
// 	u_char	ip_p;			/* protocol */
// 	u_short	ip_sum;			/* checksum */
// 	struct	in_addr ip_src,ip_dst;	/* source and dest address */
// };

// /* ********************************************* */

// /*
//  * Udp protocol header.
//  * Per RFC 768, September, 1981.
//  */
// struct udphdr {
// 	u_short	uh_sport;		/* source port */
// 	u_short	uh_dport;		/* destination port */
// 	short	uh_ulen;		/* udp length */
// 	u_short	uh_sum;			/* udp checksum */
// };



struct icmp_hdr
{
  u_int8_t  icmp_type;	 /* type of message, see below */
  u_int8_t  icmp_code;	 /* type sub code */
  u_int16_t icmp_cksum;	 /* ones complement checksum of struct */
  u_int16_t icmp_identifier, icmp_seqnum;

};


typedef struct ipAddress {
  u_int8_t ipVersion; /* Either 4 or 6 */
  
  union {
    struct in6_addr ipv6;
    u_int32_t ipv4;
  } ipType;
} IpAddress;


#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif

#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6		0x86DD	/* IPv6 protocol */
#endif

#ifndef ETHERTYPE_MPLS
#define	ETHERTYPE_MPLS		0x8847	/* MPLS protocol */
#endif

#ifndef ETHERTYPE_MPLS_MULTI
#define ETHERTYPE_MPLS_MULTI	0x8848	/* MPLS multicast packet */
#endif

#ifndef ETHERTYPE_PPPoE
#define	ETHERTYPE_PPPoE		0x8864	/* PPP over Ethernet */
#endif

struct ether_mpls_header {
  u_char label, exp, bos;
  u_char ttl;
};

struct ppp_header {
  u_int8_t address, control;
  u_int16_t proto;
};

#define NULL_HDRLEN             4

#ifndef ETHER_ADDR_LEN
#define	ETHER_ADDR_LEN	6
#endif

struct	ether_vlan_header {
  u_char    evl_dhost[ETHER_ADDR_LEN];
  u_char    evl_shost[ETHER_ADDR_LEN];
  u_int16_t evl_encap_proto;
  u_int16_t evl_tag;
  u_int16_t evl_proto;
};

#ifndef DLT_ANY
#define DLT_ANY 113
#endif

/* BSD AF_ values. */
#define BSD_AF_INET             2
#define BSD_AF_INET6_BSD        24      /* OpenBSD (and probably NetBSD), BSD/OS */
#define BSD_AF_INET6_FREEBSD    28
#define BSD_AF_INET6_DARWIN     30


struct h_t{
  u_int32_t h_sec;
  u_int32_t h_usec;
  u_int32_t caplen;
  u_int32_t len;
};