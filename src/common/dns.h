#ifndef _DNS_H_
#define _DNS_H_

#include <stdint.h>

#ifndef DNS_PERIOD
#define DNS_PERIOD 300
#endif

#ifndef NAMESERVER_PORT
#define NAMESERVER_PORT 53
#endif

#ifndef DNS_FILENAME_LENGTH
#define DNS_FILENAME_LENGTH strlen("dnscapd.yyyymmddhhMM")
#endif

#ifndef DNS_HEADER_LENGTH
#define DNS_HEADER_LENGTH 12
#endif

#ifndef MAX_DOMAIN_LENGTH
#define MAX_DOMAIN_LENGTH 256
#endif

#ifndef DNS_FILE_MAGIC
#define DNS_FILE_MAGIC 0xDCF0
#endif

#ifndef DNS_RECORD_LENGTH
#define DNS_RECORD_LENGTH sizeof(dns_record_t)
#endif

/*
 * Structure for ip address;
 */
typedef struct ip_addr_s {
	union {
		struct {
			uint32_t	fill1[2];
			uint32_t	_v4;
			uint32_t	fill2;
		};
		uint64_t		_v6[2];
	} ip_union;
} ip_addr_t;

#define v4 ip_union._v4
#define v6 ip_union._v6

/*
 * Structure for dns file header;
 */
typedef struct dns_file_header_s {
	uint16_t type;
	uint16_t length;
	uint8_t  ip_type;
	uint8_t  fill[11];
} dns_file_header_t;

/*
 * Structure for dns record;
 */
typedef struct dns_record_s {
	int64_t timestamp;

	ip_addr_t client_ip;

	ip_addr_t server_ip;

	uint8_t  domain[MAX_DOMAIN_LENGTH];

	ip_addr_t resolved_ip;

	uint8_t  reserved[8];
} dns_record_t;

#define DNS_LIST_UNUSED 0x0000
#define DNS_LIST_PENDING 0x0001

/*
 * Structure for dns record list;
 */
typedef struct dns_record_list_s {
	dns_record_t record;
	int flags;
	struct dns_record_list_s *next;
} dns_record_list_t;

#endif
