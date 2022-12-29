/*
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: nflowcache.h 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#ifndef _NFLOWCACHE_H
#define _NFLOWCACHE_H 1

/* Definitions */

/*
 * Flow Table
 * In order to aggregate flows or to generate any flow statistics, the flows passed the filter
 * are stored into an internal hash table.
 */

/* Element of the Flow Table ( cache ) */
typedef struct FlowTableRecord {
	// record chain - points to next record with same hash in case of a hash collision
	struct FlowTableRecord *next;	

	// Hash papameters
	uint32_t	hash;		// the full 32bit hash value
	char		*hash_key;	// all keys in sequence to generate the hash 

	// flow counter parameters for FLOWS, INPACKETS, INBYTES, OUTPACKETS, OUTBYTES
	uint64_t	counter[5];


	uint32_t    popular_service;
	uint32_t    service;
	uint32_t    scanner;
	uint32_t    whitelist;
	uint32_t    blacklist;
	//add for l7_proto ,proto name
	char        proto_name[8];
	//add for dns
	char        qname[DOMAIN_LEN];
	uint16_t    qtype;
	uint16_t    qclass;
	//add for http
	char        http_url[URL_LEN];
	char        http_host[HOST_LEN];
	char        http_req_method[8];
	char        http_mime[40];
	char        http_user_agent[USER_AGENT_LEN];
	char        http_cookie[COOKIE_LEN];
	uint16_t    http_ret_code;

	//add for service
	char        service_type[SERVICE_TYPE_LEN];
	char        service_name[SERVICE_NAME_LEN];
	char        service_version[SERVICE_VERSION_LEN];
  uint64_t    service_time;

  //add for icmp
  char        icmp_data[ICMP_DATA_LEN];
  uint16_t    icmp_seq_num;
  uint32_t    icmp_payload_len;

  //add for device
  char        dev_type[DEV_TYPE_LEN];
  char        dev_name[DEV_NAME_LEN];
  char        dev_vendor[DEV_VENDOR_LEN];
  char        dev_model[DEV_MODEL_LEN];
  uint64_t    dev_time;

  //add for OS
  char        os_type[OS_TYPE_LEN];
  char        os_name[OS_NAME_LEN];
  char        os_version[OS_VERSION_LEN];
  uint64_t    os_time;

  //add for middle ware
  char        midware_type[MID_WARE_TYPE_LEN];
  char        midware_name[MID_WARE_NAME_LEN];
  char        midware_version[MID_WARE_VERSION_LEN];
  uint64_t    midware_time;

  //threat
  char        threat_type[THREAT_TYPE_LEN];
  char        threat_name[THREAT_NAME_LEN];
  char        threat_version[THREAT_VERSION_LEN];
  uint64_t    threat_time;

	extension_map_t	*map_ref;
	exporter_info_record_t *exp_ref;
	// flow record follows
	// flow data size may vary depending on the number of extensions
	// common_record_t already contains a pointer to more data ( extensions ) at the end
	common_record_t	flowrecord;

	// no further vars beyond this point! The flow record above has additional data.
} FlowTableRecord_t;

typedef struct MemoryHandle_s {
	/* 
	 * to speedup aggregation/record statistics, the internal hash tables use their own memory management.
	 * memory is allocated with malloc in chunks of MemBlockSize. All memory blocks are kept in the
	 * memblock array. Memory blocks are allocated on request up to the number of MaxMemBlocks. If more 
	 * blocks are requested, the memblock array is automatically extended.
	 * Memory allocated from a memblock is aligned accoording ALIGN
	 */

	uint32_t	BlockSize;		/* max size of each pre-allocated memblock */

	/* memory blocks - containing the flow records and keys */
	void		**memblock;		/* array holding all NumBlocks allocated memory blocks */
	uint32_t 	MaxBlocks;		/* Size of memblock array */
	uint32_t 	NumBlocks;		/* number of allocated flow blocks in memblock array */
	uint32_t	CurrentBlock;	/* Index of current memblock to allocate memory from */
	uint32_t 	Allocted;		/* Number of bytes already allocated in memblock */

} MemoryHandle_t;

#ifdef __x86_64
# 	define ALIGN_MASK 0xFFFFFFF8
#else
# 	define ALIGN_MASK 0xFFFFFFFC
#endif

// number of bits for hash width for floe table
// Size: 0 < HashBits < 32
// typically 20 - tradeoff memory/speed
#define HashBits 20

// Each pre-allocated memory block is 10M
#define MemBlockSize 10*1024*1024
#define MaxMemBlocks	256


typedef struct hash_FlowTable {
	/* hash table data */
	uint16_t 			NumBits;		/* width of the hash table */
	uint32_t			IndexMask;		/* Mask which corresponds to NumBits */
	uint32_t			NumRecords;		/* number of records in table */
	FlowTableRecord_t 	**bucket;		/* Hash entry point: points to elements in the flow block */
	FlowTableRecord_t 	**bucketcache;	/* in case of index collisions, this array points to the last element with that index */

	uint32_t			keylen;			/* key length of hash key as number of 4byte ints */
	uint32_t			keysize;		/* size of key in bytes */

	/* use a MemoryHandle for the table */
	MemoryHandle_t		mem;
  // added by lxh start
  void * keymem;
  void * bidirkeymem;
  // added by lxh end

	/* src/dst IP aggr masks - use to properly maks the IP before printing */
	uint64_t			IPmask[4];		// 0-1 srcIP, 2-3 dstIP
	int					has_masks;
	int					apply_netbits;	// bit 0: src, bit 1: dst

} hash_FlowTable;

hash_FlowTable *GetFlowTable(void);

int Init_FlowTable(void);

void Dispose_FlowTable(void);

char *VerifyStat(uint16_t Aggregate_Bits);

int SetStat(char *str, int *element_stat, int *flow_stat);

void InsertFlow(common_record_t *raw_record, master_record_t *flow_record);

void AddFlow(common_record_t *raw_record, master_record_t *flow_record );

int SetBidirAggregation( void );

int ParseAggregateMask( char *arg, char **aggr_fmt  );

master_record_t *GetMasterAggregateMask(void);

#endif //_NFLOWCACHE_H
