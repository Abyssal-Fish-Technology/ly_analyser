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
 *  $Id: netflow_v9.c 55 2010-02-02 16:02:58Z haag $
 *
 *  $LastChangedRevision: 55 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "nfnet.h"
#include "nf_common.h"
#include "util.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "netflow_v9.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

// a few handy macros
#define GET_FLOWSET_ID(p) 	  (Get_val16(p))
#define GET_FLOWSET_LENGTH(p) (Get_val16((void *)((p) + 2)))

#define GET_TEMPLATE_ID(p) 	  (Get_val16(p))
#define GET_TEMPLATE_COUNT(p) (Get_val16((void *)((p) + 2)))

#define GET_OPTION_TEMPLATE_ID(p) 	  		  		 (Get_val16(p))
#define GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(p)   (Get_val16((void *)((p) + 2)))
#define GET_OPTION_TEMPLATE_OPTION_LENGTH(p)   		 (Get_val16((void *)((p) + 4)))

#include "inline.c"

extern int verbose;
extern extension_descriptor_t extension_descriptor[];
extern uint32_t Max_num_extensions;
extern uint32_t default_sampling;
extern uint32_t overwrite_sampling;

typedef struct sequence_map_s {
/* sequence definition:
	 just move a certain number of bytes          -> moveXX
	 set a certain number of output bytes to zero -> zeroXX
	 process input data into appropriate output   -> AnyName
 */
#define nop								0
#define move8							1
#define move16						2
#define move32						3
#define move40						4
#define move48						5
#define move56						6
#define move64						7
#define move128						8
#define move32_sampling		9
#define move64_sampling		10
#define move_mac					11
#define move_mpls					12
#define move_ulatency			13
#define move_slatency			14
#define Time64Mili				15
#define saveICMP					16
#define zero8							17
#define zero16						18
#define zero32						19
#define zero64						20
#define zero128						21
#define move_8						22
#define move_256					23
#define move_40						24
#define move_64						25
#define move_128					26
#define move_32						27
#define move_16						28

	uint32_t	id;				// sequence ID as defined above
	uint16_t	input_offset;	// copy/process data at this input offset
	uint16_t	output_offset;	// copy final data to this output offset
	void		*stack;			// optionally copy data onto this stack
} sequence_map_t;


typedef struct input_translation_s {
	struct input_translation_s	*next;
	uint32_t	flags;
	time_t		updated;
	uint32_t	id;
	uint32_t	input_record_size;
	uint32_t	output_record_size;

	// tmp vars needed while processing the data record
//	uint64_t	flow_start;				// start time in msec
//	uint64_t	flow_end;				// end time in msec
	uint32_t	ICMP_offset;			// offset of ICMP type/code in data stream
	uint64_t    packets;				// total packets - sampling corrected
	uint64_t    bytes;					// total bytes - sampling corrected
	uint64_t    out_packets;			// total out packets - sampling corrected
	uint64_t    out_bytes;				// total out bytes - sampling corrected
	uint32_t	sampler_offset;
	uint32_t	sampler_size;
	uint32_t	engine_offset;
	uint32_t	received_offset;
	uint32_t	router_ip_offset;

	// extension map infos
	uint32_t	extension_map_changed;		// map changed while refreshing
	extension_info_t 	 extension_info;	// the nfcap extension map, reflecting this template

	// sequence map information
	uint32_t	number_of_sequences;	// number of sequences for the translate 
	sequence_map_t *sequence;			// sequence map

} input_translation_t;

typedef struct exporter_v9_domain_s {
	// identical to generic_exporter_t
	struct exporter_v9_domain_s	*next;

	// generic exporter information
	exporter_info_record_t info;

	uint64_t	packets;			// number of packets sent by this exporter
	uint64_t	flows;				// number of flow records sent by this exporter
	uint32_t	sequence_failure;	// number of sequence failues

	// generic sampler
	generic_sampler_t		*sampler;
	// end of generic_exporter_t

	// exporter parameters
	uint64_t	boot_time;
	// sequence
	int64_t		last_sequence;
	int64_t		sequence;
	int			first;

	// sampling information: 
	// each flow source may have several sampler applied
	// tags #48, #49, #50
	// each sampler is assinged a sampler struct

	// global sampling information #34 #35
	// stored in a sampler with id = -1;

	// translation table
	input_translation_t	*input_translation_table; 
	input_translation_t *current_table;
} exporter_v9_domain_t;


/* module limited globals */
static struct v9_element_map_s {
	uint16_t	id;			// v9 element id 
	uint16_t	length;		// type of this element ( input length )
	uint16_t	out_length;	// type of this element ( output length )
	uint32_t	sequence;	// output length
	uint32_t	zero_sequence;	// 
	uint16_t	extension;	// maps into nfdump extension ID
} v9_element_map[] = {
	{0, 0, 0},
	// packets and bytes are always stored in 64bits
	{ NF9_IN_BYTES, 			 _4bytes,  _8bytes, move32_sampling, zero64, COMMON_BLOCK },
	{ NF9_IN_BYTES, 			 _8bytes,  _8bytes, move64_sampling, zero64, COMMON_BLOCK },
	{ NF9_IN_PACKETS, 			 _4bytes,  _8bytes, move32_sampling, zero64, COMMON_BLOCK },
	{ NF9_IN_PACKETS, 			 _8bytes,  _8bytes, move64_sampling, zero64, COMMON_BLOCK },

	{ NF9_FLOWS_AGGR, 			 _4bytes,  _4bytes, move32, zero32, EX_AGGR_FLOWS_4 },
	{ NF9_FLOWS_AGGR, 			 _8bytes,  _8bytes, move64, zero64, EX_AGGR_FLOWS_8 },
	{ NF9_IN_PROTOCOL, 		 	 _1byte,   _1byte,  move8,  zero8, COMMON_BLOCK },
	{ NF9_SRC_TOS, 		 	 	 _1byte,   _1byte,  move8,  zero8, COMMON_BLOCK },
	{ NF9_TCP_FLAGS, 		  	 _1byte,   _1byte,  move8,  zero8, COMMON_BLOCK },
	{ NF9_L4_SRC_PORT, 		 	 _2bytes,  _2bytes, move16, zero16, COMMON_BLOCK },
	{ NF9_IPV4_SRC_ADDR,		 _4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_SRC_MASK, 	 		 _1byte,   _1byte,  move8, zero8, EX_MULIPLE },
	{ NF9_INPUT_SNMP, 			 _2bytes,  _2bytes, move16, zero16, EX_IO_SNMP_2 },
	{ NF9_INPUT_SNMP, 			 _4bytes,  _4bytes, move32, zero32, EX_IO_SNMP_4 },
	{ NF9_L4_DST_PORT, 		 	 _2bytes,  _2bytes, move16, zero16, COMMON_BLOCK },
	{ NF9_IPV4_DST_ADDR,		 _4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_DST_MASK, 	 		 _1byte,   _1byte,  move8, zero8, EX_MULIPLE },
	{ NF9_OUTPUT_SNMP, 			 _2bytes,  _2bytes, move16, zero16, EX_IO_SNMP_2 },
	{ NF9_OUTPUT_SNMP, 			 _4bytes,  _4bytes, move32, zero32, EX_IO_SNMP_4 },
	{ NF9_V4_NEXT_HOP,		 	 _4bytes,  _4bytes, move32, zero32, EX_NEXT_HOP_v4 },
	{ NF9_SRC_AS, 			 	 _2bytes,  _2bytes, move16, zero16, EX_AS_2 },
	{ NF9_SRC_AS, 			 	 _4bytes,  _4bytes, move32, zero32, EX_AS_4 },
	{ NF9_DST_AS, 			 	 _2bytes,  _2bytes, move16, zero16, EX_AS_2 },
	{ NF9_DST_AS, 			 	 _4bytes,  _4bytes, move32, zero32, EX_AS_4 },
	{ NF9_BGP_V4_NEXT_HOP,		 _4bytes,  _4bytes, move32, zero32, EX_NEXT_HOP_BGP_v4 },
	{ NF9_LAST_SWITCHED, 		 _4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_FIRST_SWITCHED, 		 _4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_OUT_BYTES, 			 _4bytes,  _4bytes, move32_sampling, zero32, EX_OUT_BYTES_4 },
	{ NF9_OUT_BYTES, 			 _8bytes,  _8bytes, move64_sampling, zero64, EX_OUT_BYTES_8 },
	{ NF9_OUT_PKTS, 			 _4bytes,  _4bytes, move32_sampling, zero32, EX_OUT_PKG_4 },
	{ NF9_OUT_PKTS, 			 _8bytes,  _8bytes, move64_sampling, zero64, EX_OUT_PKG_8 },
	{ NF9_IPV6_SRC_ADDR,		 _16bytes, _16bytes, move128, zero128, COMMON_BLOCK },
	{ NF9_IPV6_DST_ADDR,		 _16bytes, _16bytes, move128, zero128, COMMON_BLOCK },
	{ NF9_IPV6_SRC_MASK, 	 	 _1byte,   _1byte,  move8, zero8, EX_MULIPLE },
	{ NF9_IPV6_DST_MASK, 	 	 _1byte,   _1byte,  move8, zero8, EX_MULIPLE },
	/* XXX fix */
	{ NF9_IPV6_FLOW_LABEL, 		 _4bytes,  _4bytes, nop, nop, COMMON_BLOCK },

	{ NF9_ICMP_TYPE, 			 _2bytes,  _2bytes, nop, nop, COMMON_BLOCK },
	// sampling
	{ NF9_SAMPLING_INTERVAL, 	 _4bytes,  _4bytes, move32, zero32, COMMON_BLOCK },
	{ NF9_SAMPLING_ALGORITHM,  	 _1byte,   _1byte, move8, zero8, COMMON_BLOCK },

	{ NF9_ENGINE_TYPE,  	 	 _1byte,   _1byte, move8, zero8, EX_ROUTER_ID },
	{ NF9_ENGINE_ID,  	 	 	 _1byte,   _1byte, move8, zero8, EX_ROUTER_ID },

	// sampling
	{ NF9_FLOW_SAMPLER_ID, 	 	 _1byte,   _1byte, nop, nop, COMMON_BLOCK },
	{ NF9_FLOW_SAMPLER_ID, 	 	 _2bytes,  _2bytes, nop, nop, COMMON_BLOCK },
	{ FLOW_SAMPLER_MODE, 	 	 _1byte,   _1byte, nop, nop, COMMON_BLOCK },
	{ NF9_FLOW_SAMPLER_RANDOM_INTERVAL, _4bytes, _4bytes, nop, nop, COMMON_BLOCK },

	{ NF9_DST_TOS, 		 	 	 _1byte,   _1byte, move8,  zero8, COMMON_BLOCK },

	{ NF9_IN_SRC_MAC, 			 _6bytes,  _8bytes, move_mac, zero64, EX_MAC_1},
	{ NF9_OUT_DST_MAC, 	 		 _6bytes,  _8bytes, move_mac, zero64, EX_MAC_1},

	{ NF9_SRC_VLAN, 			 _2bytes,  _2bytes, move16, zero16, EX_VLAN}, 
	{ NF9_DST_VLAN, 			 _2bytes,  _2bytes, move16, zero16, EX_VLAN},

	{ NF9_DIRECTION, 	 	 	 _1byte,   _1byte,  move8, zero8, EX_MULIPLE },

	{ NF9_V6_NEXT_HOP,			 _16bytes, _16bytes, move128, zero128, EX_NEXT_HOP_v6 },
	{ NF9_BPG_V6_NEXT_HOP,	 	 _16bytes, _16bytes, move128, zero128, EX_NEXT_HOP_BGP_v6 },

	// mpls
	{ NF9_MPLS_LABEL_1, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_2, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_3, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_4, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_5, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_6, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_7, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_8, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_9, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},
	{ NF9_MPLS_LABEL_10, 	 	 _3bytes,  _4bytes, move_mpls, zero32, EX_MPLS},

	{ NF9_IN_DST_MAC, 		 	 _6bytes,  _8bytes, move_mac, zero64, EX_MAC_2},
	{ NF9_OUT_SRC_MAC, 		 	 _6bytes,  _8bytes, move_mac, zero64, EX_MAC_2},

	{ NF9_FORWARDING_STATUS, 	 _1byte,   _1byte, move8, zero8, COMMON_BLOCK },

	// nprobe latency extension
	{ NF9_NPROBE_CLIENT_NW_DELAY_USEC, 	 _4bytes, _8bytes, move_ulatency, zero64, EX_LATENCY },
	{ NF9_NPROBE_SERVER_NW_DELAY_USEC, 	 _4bytes, _8bytes, move_ulatency, zero64, EX_LATENCY },
	{ NF9_NPROBE_APPL_LATENCY_USEC, 	 _4bytes, _8bytes, move_ulatency, zero64, EX_LATENCY },
	{ NF9_NPROBE_CLIENT_NW_DELAY_SEC, 	 _4bytes, _8bytes, move_slatency, nop, EX_LATENCY },
	{ NF9_NPROBE_SERVER_NW_DELAY_SEC, 	 _4bytes, _8bytes, move_slatency, nop, EX_LATENCY },
	{ NF9_NPROBE_APPL_LATENCY_SEC, 	 	 _4bytes, _8bytes, move_slatency, nop, EX_LATENCY },

	{ NF9_BGP_ADJ_NEXT_AS, 			 	 _4bytes,  _4bytes, move32, zero32, EX_BGPADJ },
	{ NF9_BGP_ADJ_PREV_AS, 			 	 _4bytes,  _4bytes, move32, zero32, EX_BGPADJ },

	//add for l7_proto
	{ NF9_L7_PROTO, _8bytes, _8bytes, move_8, zero64, EX_L7_PROTO},
	//add for dns
	{ NF9_DNS_QNAME, _128bytes, _128bytes, move_128, zero32, EX_DNS},
	{ NF9_DNS_QTYPE, _2bytes, _2bytes, move16, zero16, EX_DNS },
	{ NF9_DNS_QCLASS, _2bytes, _2bytes, move16, zero16, EX_DNS },
	//add for http
	{ NF9_HTTP_URL,						_128bytes,	_128bytes,	move_128,	zero32, EX_HTTP },
	{ NF9_HTTP_USER_AGENT,		_128bytes,	_128bytes,	move_128,	zero32, EX_HTTP },
	{ NF9_HTTP_COOKIE,				_128bytes,	_128bytes,	move_128,	zero32, EX_HTTP },
	{ NF9_HTTP_HOST,					_64bytes,		_64bytes,		move_64,	zero32, EX_HTTP },
	{ NF9_HTTP_REQ_METHOD,		_8bytes,		_8bytes,		move_8,		zero64, EX_HTTP },
	{ NF9_HTTP_MIME,					_40bytes,		_40bytes,		move_40,	zero32, EX_HTTP },
	{ NF9_HTTP_RET_CODE,			_2bytes,		_2bytes,		move16,		zero16, EX_HTTP },
	//add for srv
	{ NF9_SERVICE_TYPE,				_32bytes,	_32bytes,	move_32,	zero32, EX_SERVICE },
	{ NF9_SERVICE_NAME,				_32bytes,	_32bytes,	move_32,	zero32, EX_SERVICE },
	{ NF9_SERVICE_VERSION,		_16bytes,	_16bytes,	move_16,	zero16, EX_SERVICE },
	{ NF9_SERVICE_TIME,		    _8bytes,	_8bytes,	move64,	zero64, EX_SERVICE },
  //add for icmp
  { NF9_ICMP_DATA,        _128bytes,  _128bytes,  move_128, zero32, EX_ICMP },
  { NF9_ICMP_SEQ_NUM,      _2bytes,    _2bytes,    move16,   zero16, EX_ICMP },
  { NF9_ICMP_PAYLOAD_LEN,   _4bytes,    _4bytes,    move32,   zero32, EX_ICMP },
  //add for device
  { NF9_DEV_TYPE,        _32bytes,  _32bytes,  move_32, zero32, EX_DEVICE },
  { NF9_DEV_NAME,        _32bytes,  _32bytes,  move_32, zero32, EX_DEVICE },
  { NF9_DEV_VENDOR,      _32bytes,  _32bytes,  move_32, zero32, EX_DEVICE },
  { NF9_DEV_MODEL,       _16bytes,  _16bytes,  move_16, zero16, EX_DEVICE },
	{ NF9_DEV_TIME,		    _8bytes,	_8bytes,	move64,	zero64, EX_DEVICE },
  //add for OS
  { NF9_OS_TYPE,    _32bytes,   _32bytes,    move_32,   zero32, EX_OS },
  { NF9_OS_NAME,    _32bytes,   _32bytes,    move_32,   zero32, EX_OS },
  { NF9_OS_VERSION, _16bytes,   _16bytes,    move_16,   zero16, EX_OS },
	{ NF9_OS_TIME,		    _8bytes,	_8bytes,	move64,	zero64, EX_OS },
  //add for middle ware
  { NF9_MIDWARE_TYPE,    _32bytes,   _32bytes,    move_32,   zero32, EX_MIDWARE },
  { NF9_MIDWARE_NAME,    _32bytes,   _32bytes,    move_32,   zero32, EX_MIDWARE },
  { NF9_MIDWARE_VERSION, _16bytes,   _16bytes,    move_16,   zero16, EX_MIDWARE },
	{ NF9_MIDWARE_TIME,		    _8bytes,	_8bytes,	move64,	zero64, EX_MIDWARE },
  //threat
  { NF9_THREAT_TYPE,    _32bytes,   _32bytes,    move_32,   zero32, EX_THREAT },
  { NF9_THREAT_NAME,    _32bytes,   _32bytes,    move_32,   zero32, EX_THREAT },
  { NF9_THREAT_VERSION, _16bytes,   _16bytes,    move_16,   zero16, EX_THREAT },
	{ NF9_THREAT_TIME,		    _8bytes,	_8bytes,	move64,	zero64, EX_THREAT },


    

	{0, 0, 0}
};

/* 
 * tmp cache while processing template records
 * array index = extension id, 
 * value = 1 -> extension exists, 0 -> extension does not exists
 */

static struct cache_s {
	struct element_param_s {
		uint16_t index;
		uint16_t found;
		uint16_t offset;
		uint16_t length;
	}			*lookup_info;		// 65535 element 16byte to map potentially
									// all possible elements
	uint32_t	max_v9_elements;
	uint32_t	*common_extensions;

} cache;


typedef struct output_templates_s {
	struct output_templates_s 	*next;
	uint32_t			flags;
	extension_map_t		*extension_map;		// extension map;
	time_t				time_sent;
	uint32_t			record_length;		// length of the data record resulting from this template
	uint32_t			flowset_length;		// length of the flowset record
	template_flowset_t *template_flowset;
} output_template_t;

#define MAX_LIFETIME 60

static output_template_t	*output_templates;
static uint64_t	boot_time;	// in msec
static uint16_t				template_id;
static uint32_t				Max_num_v9_tags;
static uint32_t				processed_records;

/* local function prototypes */
static void InsertSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_sampler_id, uint16_t sampler_id_length, 
	uint16_t offset_sampler_mode, uint16_t offset_sampler_interval);

static void InsertStdSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_std_sampler_interval, 
	uint16_t offset_std_sampler_algorithm);

static void InsertSampler( FlowSource_t *fs, exporter_v9_domain_t *exporter, int32_t id, uint16_t mode, uint32_t interval);

static inline void Process_v9_templates(exporter_v9_domain_t *exporter, void *template_flowset, FlowSource_t *fs);

static inline void Process_v9_option_templates(exporter_v9_domain_t *exporter, void *option_template_flowset, FlowSource_t *fs);

static inline void Process_v9_data(exporter_v9_domain_t *exporter, void *data_flowset, FlowSource_t *fs, input_translation_t *table );

static inline void Process_v9_option_data(exporter_v9_domain_t *exporter, void *data_flowset, FlowSource_t *fs);

static inline exporter_v9_domain_t *GetExporter(FlowSource_t *fs, uint32_t exporter_id);

static inline input_translation_t *GetTranslationTable(exporter_v9_domain_t *exporter, uint16_t id);

static input_translation_t *setup_translation_table (exporter_v9_domain_t *exporter, uint16_t id, uint16_t input_record_size);

static input_translation_t *add_translation_table(exporter_v9_domain_t *exporter, uint16_t id);

static output_template_t *GetOutputTemplate(uint32_t flags, extension_map_t *extension_map);

static void Append_Record(send_peer_t *peer, master_record_t *master_record);

static uint16_t	Get_val16(void *p);

static uint32_t	Get_val32(void *p);

static uint64_t	Get_val64(void *p);

/* local variables */


// for sending netflow v9
static netflow_v9_header_t	*v9_output_header;

/* functions */

#include "nffile_inline.c"

int Init_v9(void) {
int i;

	output_templates = NULL;

// moded by lxh start
	cache.lookup_info	    = (cache_s::element_param_s*)calloc(65536, sizeof(cache_s::element_param_s));
// moded by lxh end
	cache.common_extensions = (uint32_t *)malloc((Max_num_extensions+1)*sizeof(uint32_t));
	if ( !cache.common_extensions || !cache.lookup_info ) {
		syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return 0;
	}

	// init the helper element table
	for (i=1; v9_element_map[i].id != 0; i++ ) {
		uint32_t Type = v9_element_map[i].id;
		// multiple same type - save first index only
		// iterate through same Types afterwards
		if ( cache.lookup_info[Type].index == 0 ) 
			cache.lookup_info[Type].index  = i;
	}
	cache.max_v9_elements = i;

	syslog(LOG_DEBUG,"Init v9: Max number of v9 tags: %u", cache.max_v9_elements);


	return 1;
	
} // End of Init_v9

static inline exporter_v9_domain_t *GetExporter(FlowSource_t *fs, uint32_t exporter_id) {
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];
exporter_v9_domain_t **e = (exporter_v9_domain_t **)&(fs->exporter_data);

	while ( *e ) {
		if ( (*e)->info.id == exporter_id && (*e)->info.version == 9 && 
			 (*e)->info.ip.v6[0] == fs->ip.v6[0] && (*e)->info.ip.v6[1] == fs->ip.v6[1]) 
			return *e;
		e = &((*e)->next);
	}

	if ( fs->sa_family == AF_INET ) {
		uint32_t _ip = htonl(fs->ip.v4);
		inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
	} else if ( fs->sa_family == AF_INET6 ) {
		uint64_t _ip[2];
		_ip[0] = htonll(fs->ip.v6[0]);
		_ip[1] = htonll(fs->ip.v6[1]);
		inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
	} else {
		strncpy(ipstr, "<unknown>", IP_STRING_LEN);
	}

	// nothing found
	*e = (exporter_v9_domain_t *)malloc(sizeof(exporter_v9_domain_t));
	if ( !(*e)) {
		syslog(LOG_ERR, "Process_v9: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_v9_domain_t));
	(*e)->info.header.type  = ExporterInfoRecordType;
	(*e)->info.header.size  = sizeof(exporter_info_record_t);
	(*e)->info.version 		= 9;
	(*e)->info.id 			= exporter_id;
	(*e)->info.ip			= fs->ip;
	(*e)->info.sa_family	= fs->sa_family;
	(*e)->info.sysid 		= 0;

	(*e)->first	 			= 1;
	(*e)->sequence_failure	= 0;

	(*e)->sampler 	 = NULL;
	(*e)->next	 	 = NULL;

	FlushInfoExporter(fs, &((*e)->info));

	dbg_printf("Process_v9: New exporter: SysID: %u, Domain: %u, IP: %s\n", 
		(*e)->info.sysid, exporter_id, ipstr);
	syslog(LOG_INFO, "Process_v9: New exporter: SysID: %u, Domain: %u, IP: %s\n", 
		(*e)->info.sysid, exporter_id, ipstr);


	return (*e);

} // End of GetExporter

static inline uint32_t MapElement(uint16_t Type, uint16_t Length, uint16_t Offset) {
int	index;

	index = cache.lookup_info[Type].index;
	if ( index )  {
		while ( index && v9_element_map[index].id == Type ) {
			if ( Length == v9_element_map[index].length ) {
				cache.lookup_info[Type].found  = 1;
				cache.lookup_info[Type].offset = Offset;
				cache.lookup_info[Type].length = Length;
				cache.lookup_info[Type].index  = index;
				dbg_printf("found extension %u for type: %u, input length: %u output length: %u Extension: %u\n", 
					v9_element_map[index].extension, v9_element_map[index].id, 
					v9_element_map[index].length, v9_element_map[index].out_length, v9_element_map[index].extension);
				return v9_element_map[index].extension;
			} 
			index++;
		}
	}
	dbg_printf("Skip unknown element type: %u, Length: %u\n", 
		Type, Length);

	return 0;

} // End of MapElement

static inline input_translation_t *GetTranslationTable(exporter_v9_domain_t *exporter, uint16_t id) {
input_translation_t *table;

	if ( exporter->current_table && ( exporter->current_table->id == id ) )
		return exporter->current_table;

	table = exporter->input_translation_table;
	while ( table ) {
		if ( table->id == id ) {
			exporter->current_table = table;
			return table;
		}

		table = table->next;
	}

	dbg_printf("[%u] Get translation table %u: %s\n", exporter->info.id, id, table == NULL ? "not found" : "found");

	exporter->current_table = table;
	return table;

} // End of GetTranslationTable

static input_translation_t *add_translation_table(exporter_v9_domain_t *exporter, uint16_t id) {
input_translation_t **table;

	table = &(exporter->input_translation_table);
	while ( *table ) {
		table = &((*table)->next);
	}

	// Allocate enough space for all potential v9 tags, which we support in v9_element_map
	// so template refreshing may change the table size without danger of overflowing 
// moded by lxh start
	*table = (input_translation_t*)malloc(sizeof(input_translation_t));
// moded by lxh end
	if ( !(*table) ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}
// moded by lxh start
	(*table)->sequence = (sequence_map_t*)calloc(cache.max_v9_elements, sizeof(sequence_map_t));
// moded by lxh end
	if ( !(*table)->sequence ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}

	(*table)->id   = id;
	(*table)->next = NULL;

	dbg_printf("[%u] Get new translation table %u\n", exporter->info.id, id);

	return *table;

} // End of add_translation_table

static inline void PushSequence(input_translation_t *table, uint16_t Type, uint32_t *offset, void *stack) {
uint32_t i = table->number_of_sequences;
uint32_t index = cache.lookup_info[Type].index;

	if ( table->number_of_sequences >= cache.max_v9_elements ) {
		syslog(LOG_ERR, "Process_v9: Software bug! Sequence table full. at %s line %d", 
			__FILE__, __LINE__);
		dbg_printf("Software bug! Sequence table full. at %s line %d", 
			__FILE__, __LINE__);
		return;
	}

	if ( cache.lookup_info[Type].found ) {
			table->sequence[i].id = v9_element_map[index].sequence;
			table->sequence[i].input_offset  = cache.lookup_info[Type].offset;
			table->sequence[i].output_offset = *offset;
			table->sequence[i].stack = stack;
	} else {
			table->sequence[i].id = v9_element_map[index].zero_sequence;
			table->sequence[i].input_offset  = 0;
			table->sequence[i].output_offset = *offset;
			table->sequence[i].stack = NULL;
	}
	dbg_printf("Push: sequence: %u, Type: %u, length: %u, out length: %u, id: %u, in offset: %u, out offset: %u\n",
		i, Type, v9_element_map[index].length, v9_element_map[index].out_length, table->sequence[i].id, 
		table->sequence[i].input_offset, table->sequence[i].output_offset);
	table->number_of_sequences++;
	(*offset) += v9_element_map[index].out_length;

} // End of PushSequence


static input_translation_t *setup_translation_table (exporter_v9_domain_t *exporter, uint16_t id, uint16_t input_record_size) {
input_translation_t *table;
extension_map_t 	*extension_map;
uint32_t			i, ipv6, offset, next_extension;
size_t				size_required;

	ipv6 = 0;

	table = GetTranslationTable(exporter, id);
	if ( !table ) {
		syslog(LOG_INFO, "Process_v9: [%u] Add template %u", exporter->info.id, id);
		table = add_translation_table(exporter, id);
		if ( !table ) {
			return NULL;
		}
		// Add an extension map
		// The number of extensions for this template is currently unknown
		// Allocate enough space for all configured extensions - some may be unused later
		// make sure memory is 4byte alligned
		size_required = Max_num_extensions * sizeof(uint16_t) + sizeof(extension_map_t);
		size_required = (size_required + 3) &~(size_t)3;
// moded by lxh start
		extension_map = (extension_map_t*)malloc(size_required);
// moded by lxh end
		if ( !extension_map ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return  NULL;
		}
		extension_map->type 	   = ExtensionMapType;
		// Set size to an empty tablee - will be adapted later
		extension_map->size 	   = sizeof(extension_map_t);
		extension_map->map_id 	   = INIT_ID;
		// packed record size still unknown at this point - will be added later
		extension_map->extension_size = 0;

		table->extension_info.map 	 = extension_map;
		table->extension_map_changed = 1;
	} else {
		extension_map = table->extension_info.map;

		// reset size/extension size - it's refreshed automatically
		extension_map->size 	   	  = sizeof(extension_map_t);
		extension_map->extension_size = 0;

		dbg_printf("[%u] Refresh template %u\n", exporter->info.id, id);

		// very noisy with somee exporters
		// syslog(LOG_DEBUG, "Process_v9: [%u] Refresh template %u", exporter->info.id, id);
	}
	// clear current table
	memset((void *)table->sequence, 0, cache.max_v9_elements * sizeof(sequence_map_t));
	table->number_of_sequences = 0;

	table->updated  		= time(NULL);
	table->flags			= 0;
	table->ICMP_offset		= 0;
	table->sampler_offset 	= 0;
	table->sampler_size		= 0;
	table->engine_offset 	= 0;
	table->received_offset 	= 0;
	table->router_ip_offset = 0;

	dbg_printf("[%u] Fill translation table %u\n", exporter->info.id, id);

	// fill table
	table->id 			= id;

	/* 
	 * common data block: The common record is expected in the output stream. If not available
	 * in the template, fill values with 0
	 */

	// All required extensions
	offset = BYTE_OFFSET_first;
	PushSequence( table, NF9_FIRST_SWITCHED, &offset, NULL);
	offset = BYTE_OFFSET_first + 4;
	PushSequence( table, NF9_LAST_SWITCHED, &offset, NULL);
	offset = BYTE_OFFSET_first + 8;
	PushSequence( table, NF9_FORWARDING_STATUS, &offset, NULL);

	PushSequence( table, NF9_TCP_FLAGS, &offset, NULL);
	PushSequence( table, NF9_IN_PROTOCOL, &offset, NULL);
	PushSequence( table, NF9_SRC_TOS, &offset, NULL);

	PushSequence( table, NF9_L4_SRC_PORT, &offset, NULL);
	PushSequence( table, NF9_L4_DST_PORT, &offset, NULL);

	/* IP addresss record
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty v4 address.
	 */
	if ( cache.lookup_info[NF9_IPV4_SRC_ADDR].found ) {
		// IPv4 addresses 
		PushSequence( table, NF9_IPV4_SRC_ADDR, &offset, NULL);
		PushSequence( table, NF9_IPV4_DST_ADDR, &offset, NULL);
	} else if ( cache.lookup_info[NF9_IPV6_SRC_ADDR].found ) {
		// IPv6 addresses 
		PushSequence( table, NF9_IPV6_SRC_ADDR, &offset, NULL);
		PushSequence( table, NF9_IPV6_DST_ADDR, &offset, NULL);
		// mark IPv6 
		table->flags	|= FLAG_IPV6_ADDR;
		ipv6 = 1;
	} else {
		// should not happen, assume empty IPv4 addresses
		PushSequence( table, NF9_IPV4_SRC_ADDR, &offset, NULL);
		PushSequence( table, NF9_IPV4_DST_ADDR, &offset, NULL);
	}

	/* packet counter
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty 4 bytes value
	 */
	PushSequence( table, NF9_IN_PACKETS, &offset, &table->packets);
	// fix: always have 64bit counters due to possible sampling
	SetFlag(table->flags, FLAG_PKG_64);

	PushSequence( table, NF9_IN_BYTES, &offset, &table->bytes);
	// fix: always have 64bit counters due to possible sampling
	SetFlag(table->flags, FLAG_BYTES_64);

	// Optional extensions
	next_extension = 0;
	for (i=4; i <= Max_num_extensions; i++ ) {
		uint32_t map_index = i;

		if ( cache.common_extensions[i] == 0 )
			continue;

		switch(i) {
			case EX_IO_SNMP_2:
				PushSequence( table, NF9_INPUT_SNMP, &offset, NULL);
				PushSequence( table, NF9_OUTPUT_SNMP, &offset, NULL);
				break;
			case EX_IO_SNMP_4:
				PushSequence( table, NF9_INPUT_SNMP, &offset, NULL);
				PushSequence( table, NF9_OUTPUT_SNMP, &offset, NULL);
				break;
			case EX_AS_2:
				PushSequence( table, NF9_SRC_AS, &offset, NULL);
				PushSequence( table, NF9_DST_AS, &offset, NULL);
				break;
			case EX_AS_4:
				PushSequence( table, NF9_SRC_AS, &offset, NULL);
				PushSequence( table, NF9_DST_AS, &offset, NULL);
				break;
			case EX_MULIPLE:
				PushSequence( table, NF9_DST_TOS, &offset, NULL);
				PushSequence( table, NF9_DIRECTION, &offset, NULL);
				if ( ipv6 ) {
					// IPv6
					PushSequence( table, NF9_IPV6_SRC_MASK, &offset, NULL);
					PushSequence( table, NF9_IPV6_DST_MASK, &offset, NULL);
				} else {
					// IPv4
					PushSequence( table, NF9_SRC_MASK, &offset, NULL);
					PushSequence( table, NF9_DST_MASK, &offset, NULL);
				}
				break;
			case EX_NEXT_HOP_v4:
				PushSequence( table, NF9_V4_NEXT_HOP, &offset, NULL);
				break;
			case EX_NEXT_HOP_v6:
				PushSequence( table, NF9_V6_NEXT_HOP, &offset, NULL);
				SetFlag(table->flags, FLAG_IPV6_NH);
				break;
			case EX_NEXT_HOP_BGP_v4:
				PushSequence( table, NF9_BGP_V4_NEXT_HOP, &offset, NULL);
				break;
			case EX_NEXT_HOP_BGP_v6:
				PushSequence( table, NF9_BPG_V6_NEXT_HOP, &offset, NULL);
				SetFlag(table->flags, FLAG_IPV6_NHB);
				break;
			case EX_VLAN:
				PushSequence( table, NF9_SRC_VLAN, &offset, NULL);
				PushSequence( table, NF9_DST_VLAN, &offset, NULL);
				break;
			case EX_OUT_PKG_4:
				PushSequence( table, NF9_OUT_PKTS, &offset, &table->out_packets);
				break;
			case EX_OUT_PKG_8:
				PushSequence( table, NF9_OUT_PKTS, &offset, &table->out_packets);
				break;
			case EX_OUT_BYTES_4:
				PushSequence( table, NF9_OUT_BYTES, &offset, &table->out_bytes);
				break;
			case EX_OUT_BYTES_8:
				PushSequence( table, NF9_OUT_BYTES, &offset, &table->out_bytes);
				break;
			case EX_AGGR_FLOWS_4:
				PushSequence( table, NF9_FLOWS_AGGR, &offset, NULL);
				break;
			case EX_AGGR_FLOWS_8:
				PushSequence( table, NF9_FLOWS_AGGR, &offset, NULL);
				break;
			case EX_MAC_1:
				PushSequence( table, NF9_IN_SRC_MAC, &offset, NULL);
				PushSequence( table, NF9_OUT_DST_MAC, &offset, NULL);
				break;
			case EX_MAC_2:
				PushSequence( table, NF9_IN_DST_MAC, &offset, NULL);
				PushSequence( table, NF9_OUT_SRC_MAC, &offset, NULL);
				break;
			case EX_MPLS:
				PushSequence( table, NF9_MPLS_LABEL_1, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_2, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_3, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_4, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_5, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_6, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_7, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_8, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_9, &offset, NULL);
				PushSequence( table, NF9_MPLS_LABEL_10, &offset, NULL);
				break;
			case EX_ROUTER_IP_v4:
			case EX_ROUTER_IP_v6:
				if ( exporter->info.sa_family == PF_INET6 ) {
					table->router_ip_offset = offset;
					dbg_printf("Router IPv6: Offset: %u, olen: %u\n", offset, 16 );
					// not an entry for the translateion table.
					// but reserve space in the output record for IPv6
					offset			 	   += 16;
					SetFlag(table->flags, FLAG_IPV6_EXP);
					map_index = EX_ROUTER_IP_v6;
				} else {
					table->router_ip_offset = offset;
					dbg_printf("Router IPv4: Offset: %u, olen: %u\n", offset, 4 );
					// not an entry for the translateion table.
					// but reserve space in the output record for IPv4
					offset				   += 4;
					ClearFlag(table->flags, FLAG_IPV6_EXP);
					map_index = EX_ROUTER_IP_v4;
				}
				break;
			case EX_ROUTER_ID:
				table->engine_offset = offset;
				dbg_printf("Engine offset: %u\n", offset);
				offset += 2;
				dbg_printf("Skip 2 unused bytes. Next offset: %u\n", offset);
				PushSequence( table, NF9_ENGINE_TYPE, &offset, NULL);
				PushSequence( table, NF9_ENGINE_ID, &offset, NULL);
				// unused fill element for 32bit alignment
				break;
			case EX_RECEIVED:
				table->received_offset = offset;
				dbg_printf("Received offset: %u\n", offset);
				offset				   += 8;
				break;
			case EX_LATENCY: {
				// it's bit of a hack, but .. sigh ..
				uint32_t i = table->number_of_sequences;

				// Insert a zero64 as subsequent sequences add values
				table->sequence[i].id = zero64;
				table->sequence[i].input_offset  = 0;
				table->sequence[i].output_offset = offset;
				table->sequence[i].stack = NULL;
				table->number_of_sequences++;
				dbg_printf("Zero latency at offset: %u\n", offset);

				PushSequence( table, NF9_NPROBE_CLIENT_NW_DELAY_SEC, &offset, NULL);
				offset -= 8;
				PushSequence( table, NF9_NPROBE_CLIENT_NW_DELAY_USEC, &offset, NULL);

				table->sequence[i].id = zero64;
				table->sequence[i].input_offset  = 0;
				table->sequence[i].output_offset = offset;
				table->sequence[i].stack = NULL;
				table->number_of_sequences++;
				dbg_printf("Zero latency at offset: %u\n", offset);

				PushSequence( table, NF9_NPROBE_SERVER_NW_DELAY_SEC, &offset, NULL);
				offset -= 8;
				PushSequence( table, NF9_NPROBE_SERVER_NW_DELAY_USEC, &offset, NULL);

				table->sequence[i].id = zero64;
				table->sequence[i].input_offset  = 0;
				table->sequence[i].output_offset = offset;
				table->sequence[i].stack = NULL;
				table->number_of_sequences++;
				dbg_printf("Zero latency at offset: %u\n", offset);

				PushSequence( table, NF9_NPROBE_APPL_LATENCY_SEC, &offset, NULL);
				offset -= 8;
				PushSequence( table, NF9_NPROBE_APPL_LATENCY_USEC, &offset, NULL);

				} break;
			case EX_BGPADJ:
				PushSequence( table, NF9_BGP_ADJ_NEXT_AS, &offset, NULL);
				PushSequence( table, NF9_BGP_ADJ_PREV_AS, &offset, NULL);
				break;
			//add for l7_proto
			case EX_L7_PROTO:
				PushSequence( table, NF9_L7_PROTO, &offset, NULL);
				break;
			//add for dns
			case EX_DNS: 
				PushSequence( table, NF9_DNS_QNAME, &offset, NULL);
				PushSequence( table, NF9_DNS_QTYPE, &offset, NULL);
				PushSequence( table, NF9_DNS_QCLASS, &offset, NULL);
				break;
			//add for http
			case EX_HTTP:
				PushSequence( table, NF9_HTTP_URL, &offset, NULL);
				PushSequence( table, NF9_HTTP_HOST, &offset, NULL);
				PushSequence( table, NF9_HTTP_REQ_METHOD, &offset, NULL);
				PushSequence( table, NF9_HTTP_MIME, &offset, NULL);
				PushSequence( table, NF9_HTTP_USER_AGENT, &offset, NULL);
				PushSequence( table, NF9_HTTP_COOKIE, &offset, NULL);
				PushSequence( table, NF9_HTTP_RET_CODE, &offset, NULL);
				break;

			//add for http
			case EX_SERVICE:
				PushSequence( table, NF9_SERVICE_TYPE, &offset, NULL);
				PushSequence( table, NF9_SERVICE_NAME, &offset, NULL);
				PushSequence( table, NF9_SERVICE_VERSION, &offset, NULL);
				PushSequence( table, NF9_SERVICE_TIME, &offset, NULL);
				break;
      //add for icmp
      case EX_ICMP:
        PushSequence( table, NF9_ICMP_DATA, &offset, NULL);
        PushSequence( table, NF9_ICMP_SEQ_NUM, &offset, NULL);
        offset += 2;
        PushSequence( table, NF9_ICMP_PAYLOAD_LEN, &offset, NULL);
        break;
      case EX_DEVICE:
        PushSequence( table, NF9_DEV_TYPE, &offset, NULL);
        PushSequence( table, NF9_DEV_NAME, &offset, NULL);
        PushSequence( table, NF9_DEV_VENDOR, &offset, NULL);
        PushSequence( table, NF9_DEV_MODEL, &offset, NULL);
        PushSequence( table, NF9_DEV_TIME, &offset, NULL);
        break;
      case EX_OS:
        PushSequence( table, NF9_OS_TYPE, &offset, NULL);
        PushSequence( table, NF9_OS_NAME, &offset, NULL);
        PushSequence( table, NF9_OS_VERSION, &offset, NULL);
        PushSequence( table, NF9_OS_TIME, &offset, NULL);
        break;
      case EX_MIDWARE:
        PushSequence( table, NF9_MIDWARE_TYPE, &offset, NULL);
        PushSequence( table, NF9_MIDWARE_NAME, &offset, NULL);
        PushSequence( table, NF9_MIDWARE_VERSION, &offset, NULL);
        PushSequence( table, NF9_MIDWARE_TIME, &offset, NULL);
        break;
      case EX_THREAT:
        PushSequence( table, NF9_THREAT_TYPE, &offset, NULL);
        PushSequence( table, NF9_THREAT_NAME, &offset, NULL);
        PushSequence( table, NF9_THREAT_VERSION, &offset, NULL);
        PushSequence( table, NF9_THREAT_TIME, &offset, NULL);
        break;
		}
		extension_map->size += sizeof(uint16_t);
		extension_map->extension_size += extension_descriptor[map_index].size;

		// found extension in map_index must be the same as in map - otherwise map is dirty
		if ( extension_map->ex_id[next_extension] != map_index ) {
			// dirty map - needs to be refreshed in output stream
			extension_map->ex_id[next_extension] = map_index;
			table->extension_map_changed = 1;

		}
		next_extension++;

	}
	extension_map->ex_id[next_extension++] = 0;

	// make sure map is aligned
	if ( extension_map->size & 0x3 ) {
		extension_map->ex_id[next_extension] = 0;
		extension_map->size = ( extension_map->size + 3 ) &~ 0x3;
	}

	table->output_record_size = offset;
	table->input_record_size  = input_record_size;

	/* ICMP hack for v9  */
	// for netflow historical reason, ICMP type/code goes into dst port field
	// remember offset, for decoding
	if ( cache.lookup_info[NF9_ICMP_TYPE].found && cache.lookup_info[NF9_ICMP_TYPE].length == 2 ) {
		table->ICMP_offset = cache.lookup_info[NF9_ICMP_TYPE].offset;
	}

	/* Sampler ID */
	if ( cache.lookup_info[NF9_FLOW_SAMPLER_ID].found ) {
		if ( cache.lookup_info[NF9_FLOW_SAMPLER_ID].length == 1 ) {
			table->sampler_offset = cache.lookup_info[NF9_FLOW_SAMPLER_ID].offset;
			table->sampler_size = 1;
			dbg_printf("1 byte Sampling ID included at offset %u\n", table->sampler_offset);
		} else if ( cache.lookup_info[NF9_FLOW_SAMPLER_ID].length == 2 ) {
			table->sampler_offset = cache.lookup_info[NF9_FLOW_SAMPLER_ID].offset;
			table->sampler_size = 2;
			dbg_printf("2 byte Sampling ID included at offset %u\n", table->sampler_offset);
		}  else {
			syslog(LOG_ERR, "Process_v9: Unexpected SAMPLER ID field length: %d", 
				cache.lookup_info[NF9_FLOW_SAMPLER_ID].length);
			dbg_printf("Unexpected SAMPLER ID field length: %d", 
				cache.lookup_info[NF9_FLOW_SAMPLER_ID].length);

		}
	} else {
		dbg_printf("No Sampling ID found\n");
	}

#ifdef DEVEL
	if ( table->extension_map_changed ) {
		printf("Extension Map id=%u changed!\n", extension_map->map_id);
	} else {
		printf("[%u] template %u unchanged\n", exporter->info.id, id);
	}

	printf("Process_v9: Check extension map: id: %d, size: %u, extension_size: %u\n", 
		extension_map->map_id, extension_map->size, extension_map->extension_size);
	{ int i;
	for (i=0; i<table->number_of_sequences; i++ ) {
		printf("Sequence %i: id: %u, in offset: %u, out offset: %u, stack: %llu\n",
			i, table->sequence[i].id, table->sequence[i].input_offset, table->sequence[i].output_offset, 
			(unsigned long long)table->sequence[i].stack);
	}
	printf("Flags: 0x%x\n", table->flags); 
	printf("Input record size: %u, output record size: %u\n", 
		table->input_record_size, table->output_record_size);
	}
	PrintExtensionMap(extension_map);
#endif

	return table;

} // End of setup_translation_table

static void InsertSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_sampler_id, uint16_t sampler_id_length,
	uint16_t offset_sampler_mode, uint16_t offset_sampler_interval) {
option_offset_t	**t;

	t = &(fs->option_offset_table);
	while ( *t ) {
		if ( (*t)->id == id ) { // table already known to us - update data
			dbg_printf("Found existing sampling info in template %i\n", id);
			break;
		}
	
		t = &((*t)->next);
	}

	if ( *t == NULL ) {	// new table
		dbg_printf("Allocate new sampling info from template %i\n", id);
		*t = (option_offset_t *)calloc(1, sizeof(option_offset_t));
		if ( !*t ) {
			fprintf(stderr, "malloc() allocation error: %s\n", strerror(errno));
			return ;
		} 
		dbg_printf("Process_v9: New sampler: ID %i, mode: %i, interval: %i\n", 
			offset_sampler_id, offset_sampler_mode, offset_sampler_interval);
	}	// else existing table

	dbg_printf("Insert/Update sampling info from template %i\n", id);
	SetFlag((*t)->flags, HAS_SAMPLER_DATA);
	(*t)->id 				= id;
	(*t)->offset_id			= offset_sampler_id;
	(*t)->sampler_id_length = sampler_id_length;
	(*t)->offset_mode		= offset_sampler_mode;
	(*t)->offset_interval	= offset_sampler_interval;

} // End of InsertSamplerOffset

static void InsertStdSamplerOffset( FlowSource_t *fs, uint16_t id, uint16_t offset_std_sampler_interval, uint16_t offset_std_sampler_algorithm) {
option_offset_t	**t;

	t = &(fs->option_offset_table);
	while ( *t ) {
		if ( (*t)->id == id ) { // table already known to us - update data
			dbg_printf("Found existing std sampling info in template %i\n", id);
			break;
		}
	
		t = &((*t)->next);
	}

	if ( *t == NULL ) {	// new table
		dbg_printf("Allocate new std sampling info from template %i\n", id);
		*t = (option_offset_t *)calloc(1, sizeof(option_offset_t));
		if ( !*t ) {
			fprintf(stderr, "malloc() allocation error: %s\n", strerror(errno));
			return ;
		} 
		syslog(LOG_ERR, "Process_v9: New std sampler: interval: %i, algorithm: %i", 
			offset_std_sampler_interval, offset_std_sampler_algorithm);
	}	// else existing table

	dbg_printf("Insert/Update sampling info from template %i\n", id);
	SetFlag((*t)->flags, HAS_STD_SAMPLER_DATA);
	(*t)->id 				= id;
	(*t)->offset_id			= 0;
	(*t)->offset_mode		= 0;
	(*t)->offset_interval	= 0;
	(*t)->offset_std_sampler_interval	= offset_std_sampler_interval;
	(*t)->offset_std_sampler_algorithm	= offset_std_sampler_algorithm;
	
} // End of InsertStdSamplerOffset

static inline void Process_v9_templates(exporter_v9_domain_t *exporter, void *template_flowset, FlowSource_t *fs) {
void				*v9_template;
input_translation_t *translation_table;
uint16_t	id, count, Offset;
uint32_t	size_left, size_required, num_extensions, num_v9tags;
int			i;

	size_left = GET_FLOWSET_LENGTH(template_flowset) - 4; // -4 for flowset header -> id and length
	v9_template  = template_flowset + 4;					  // the template description begins at offset 4

	// process all templates in flowset, as long as any bytes are left
	size_required = 0;
	Offset 		  = 0;
	while (size_left) {
		void *p;
		v9_template = v9_template + size_required;

		// clear helper tables
		memset((void *)cache.common_extensions, 0,  (Max_num_extensions+1)*sizeof(uint32_t));
		memset((void *)cache.lookup_info, 0, 65536 * sizeof(cache_s::element_param_s));
		for (i=1; v9_element_map[i].id != 0; i++ ) {
			uint32_t Type = v9_element_map[i].id;
			if ( v9_element_map[i].id == v9_element_map[i-1].id )
				continue;
			cache.lookup_info[Type].index  = i;
			// other elements cleard be memset
		}

		id 	  = GET_TEMPLATE_ID(v9_template);
		count = GET_TEMPLATE_COUNT(v9_template);
		size_required = 4 + 4 * count;	// id + count = 4 bytes, and 2 x 2 bytes for each entry

		dbg_printf("\n[%u] Template ID: %u\n", exporter->info.id, id);
		dbg_printf("template size: %u buffersize: %u\n", size_required, size_left);

		if ( size_left < size_required ) {
			syslog(LOG_ERR, "Process_v9: [%u] buffer size error: expected %u available %u", 
				exporter->info.id, size_required, size_left);
			size_left = 0;
			continue;
		}

		Offset = 0;
		num_extensions = 0;		// number of extensions
		num_v9tags = 0;			// number of optional v9 tags 

		p = v9_template + 4;		// type/length pairs start at template offset 4
		for(i=0; i<count; i++ ) {
			uint16_t Type, Length;
			uint32_t ext_id;

			Type   = Get_val16(p); p = p + 2;
			Length = Get_val16(p); p = p + 2;
			num_v9tags++;

			// map v9 tag to extension id - if != 0 then when we support it.
			ext_id = MapElement(Type, Length, Offset);

			// do we store this extension? enabled != 0
			// more than 1 v9 tag may map to an extension - so count this extension once only
			if ( ext_id && extension_descriptor[ext_id].enabled ) {
				if ( cache.common_extensions[ext_id] == 0 ) {
					cache.common_extensions[ext_id] = 1;
					num_extensions++;
				}
			} 
			Offset += Length;
		}

		// as the router IP address extension is not part announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_ROUTER_IP_v4].enabled ) {
			if ( cache.common_extensions[EX_ROUTER_IP_v4] == 0 ) {
				cache.common_extensions[EX_ROUTER_IP_v4] = 1;
				num_extensions++;
			}
			dbg_printf("Add sending router IP address (%s) => Extension: %u\n", 
				fs->sa_family == PF_INET6 ? "ipv6" : "ipv4", EX_ROUTER_IP_v4);
		}
	
		// as the router IP address extension is not part announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_ROUTER_ID].enabled ) {
			if ( cache.common_extensions[EX_ROUTER_ID] == 0 ) {
				cache.common_extensions[EX_ROUTER_ID] = 1;
				num_extensions++;
			}
			dbg_printf("Force add router ID (engine type/ID), Extension: %u\n", EX_ROUTER_ID);
		}

		// as the received time is not announced in a template, we need to deal with it here
		if ( extension_descriptor[EX_RECEIVED].enabled ) {
			if ( cache.common_extensions[EX_RECEIVED] == 0 ) {
				cache.common_extensions[EX_RECEIVED] = 1;
				num_extensions++;
			}
			dbg_printf("Force add packet received time, Extension: %u\n", EX_RECEIVED);
		}
	
		dbg_printf("Parsed %u v9 tags, total %u extensions\n", num_v9tags, num_extensions);

#ifdef DEVEL
		{
			int i;
			for (i=0; i<=Max_num_extensions; i++ ) {
				if ( cache.common_extensions[i] ) {
					printf("Enabled extension: %2i: %s\n", i, extension_descriptor[i].description);
				}
			}
		}
#endif

		translation_table = setup_translation_table(exporter, id, Offset);
		if (translation_table->extension_map_changed ) {
			translation_table->extension_map_changed = 0;
			// refresh he map in the ouput buffer
			dbg_printf("Translation Table changed! Add extension map ID: %i\n", translation_table->extension_info.map->map_id);
			AddExtensionMap(fs, translation_table->extension_info.map);
			dbg_printf("Translation Table added! map ID: %i\n", translation_table->extension_info.map->map_id);
		}
		size_left -= size_required;
		processed_records++;

		dbg_printf("\n");

	} // End of while size_left

} // End of Process_v9_templates

static inline void Process_v9_option_templates(exporter_v9_domain_t *exporter, void *option_template_flowset, FlowSource_t *fs) {
void		*option_template, *p;
uint32_t	size_left, nr_scopes, nr_options, i;
uint16_t	id, scope_length, option_length, offset, sampler_id_length;
uint16_t	offset_sampler_id, offset_sampler_mode, offset_sampler_interval, found_sampler;
uint16_t	offset_std_sampler_interval, offset_std_sampler_algorithm, found_std_sampling;

	i = 0;	// keep compiler happy
	size_left 		= GET_FLOWSET_LENGTH(option_template_flowset) - 4; // -4 for flowset header -> id and length
	option_template = option_template_flowset + 4;
	id 	  			= GET_OPTION_TEMPLATE_ID(option_template); 
	scope_length 	= GET_OPTION_TEMPLATE_OPTION_SCOPE_LENGTH(option_template);
	option_length 	= GET_OPTION_TEMPLATE_OPTION_LENGTH(option_template);

	if ( scope_length & 0x3 ) {
		syslog(LOG_ERR, "Process_v9: [%u] scope length error: length %u not multiple of 4", 
			exporter->info.id, scope_length);
		return;
	}

	if ( option_length & 0x3 ) {
		syslog(LOG_ERR, "Process_v9: [%u] option length error: length %u not multiple of 4", 
			exporter->info.id, option_length);
		return;
	}

	if ( (scope_length + option_length) > size_left ) {
		syslog(LOG_ERR, "Process_v9: [%u] option template length error: size left %u too small for %u scopes length and %u options length", 
			exporter->info.id, size_left, scope_length, option_length);
		return;
	}

	nr_scopes  = scope_length >> 2;
	nr_options = option_length >> 2;

	dbg_printf("\n[%u] Option Template ID: %u\n", exporter->info.id, id);
	dbg_printf("Scope length: %u Option length: %u\n", scope_length, option_length);

	sampler_id_length			 = 0;
	offset_sampler_id 			 = 0;
	offset_sampler_mode 		 = 0;
	offset_sampler_interval 	 = 0;
	offset_std_sampler_interval  = 0;
	offset_std_sampler_algorithm = 0;
	found_sampler				 = 0;
	found_std_sampling			 = 0;
	offset = 0;

	p = option_template + 6;	// start of length/type data
	for ( i=0; i<nr_scopes; i++ ) {
#ifdef DEVEL
		uint16_t type 	= Get_val16(p);
#endif
		p = p + 2;

		uint16_t length = Get_val16(p); p = p + 2;
		offset += length;
		dbg_printf("Scope field Type: %u, length %u\n", type, length);
	}

	for ( ; i<(nr_scopes+nr_options); i++ ) {
		uint16_t type 	= Get_val16(p); p = p + 2;
		uint16_t length = Get_val16(p); p = p + 2;
		uint32_t index  = cache.lookup_info[type].index;
		dbg_printf("Option field Type: %u, length %u\n", type, length);
		if ( !index ) {
			dbg_printf("Unsupported: Option field Type: %u, length %u\n", type, length);
			continue;
		}
		while ( index && v9_element_map[index].id == type ) {
			if ( length == v9_element_map[index].length ) {
				break;
			}
			index++;
		}

		if ( index && v9_element_map[index].length != length ) {
			syslog(LOG_ERR,"Process_v9: Option field Type: %u, length %u not supported\n", type, length);
			dbg_printf("Process_v9: Option field Type: %u, length %u not supported\n", type, length);
			continue;
		}
		switch (type) {
			// general sampling
			case NF9_SAMPLING_INTERVAL:
				offset_std_sampler_interval = offset;
				found_std_sampling++;
				break;
			case NF9_SAMPLING_ALGORITHM:
				offset_std_sampler_algorithm = offset;
				found_std_sampling++;
				break;

			// individual samplers
			case NF9_FLOW_SAMPLER_ID:
				offset_sampler_id = offset;
				sampler_id_length = length;
				found_sampler++;
				break;
			case FLOW_SAMPLER_MODE:
				offset_sampler_mode = offset;
				found_sampler++;
				break;
			case NF9_FLOW_SAMPLER_RANDOM_INTERVAL:
				offset_sampler_interval = offset;
				found_sampler++;
				break;
		}
		offset += length;
	}

	if ( found_sampler == 3 ) { // need all three tags
		dbg_printf("[%u] Sampling information found\n", exporter->info.id);
		InsertSamplerOffset(fs, id, offset_sampler_id, sampler_id_length, offset_sampler_mode, offset_sampler_interval);
	} else if ( found_std_sampling == 2 ) { // need all two tags
		dbg_printf("[%u] Std sampling information found\n", exporter->info.id);
		InsertStdSamplerOffset(fs, id, offset_std_sampler_interval, offset_std_sampler_algorithm);
	} else {
		dbg_printf("[%u] No Sampling information found\n", exporter->info.id);
	}
	dbg_printf("\n");
	processed_records++;

} // End of Process_v9_option_templates


static inline void Process_v9_data(exporter_v9_domain_t *exporter, void *data_flowset, FlowSource_t *fs, input_translation_t *table ){
uint64_t			start_time, end_time, sampling_rate;
uint32_t			size_left, First, Last;
uint8_t				*in, *out;
int					i;
char				*string;

	size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length

	// map input buffer as a byte array
	in  	  = (uint8_t *)(data_flowset + 4);	// skip flowset header

	dbg_printf("[%u] Process data flowset size: %u\n", exporter->info.id, size_left);

	// Check if sampling is announced
	if ( table->sampler_offset && exporter->sampler  ) {
		generic_sampler_t *sampler = exporter->sampler;
		uint32_t sampler_id;
		if ( table->sampler_size == 2 ) {
			sampler_id = Get_val16((void *)&in[table->sampler_offset]);
		} else {
			sampler_id = in[table->sampler_offset];
		}
printf("Extract sampler: %u\n", sampler_id);
		// usually not that many samplers, so following a chain is not too expensive.
		while ( sampler && sampler->info.id != sampler_id ) 
			sampler = sampler->next;

		if ( sampler ) {
			sampling_rate = sampler->info.interval;
			dbg_printf("[%u] Sampling ID %u available\n", exporter->info.id, sampler_id);
			dbg_printf("[%u] Sampler_offset : %u\n", exporter->info.id, table->sampler_offset);
			dbg_printf("[%u] Sampler Data : %s\n", exporter->info.id, exporter->sampler == NULL ? "not available" : "available");
			dbg_printf("[%u] Sampling rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
		} else {
			sampling_rate = default_sampling;
			dbg_printf("[%u] Sampling ID %u not (yet) available\n", exporter->info.id, sampler_id);
		}

	} else {
		generic_sampler_t *sampler = exporter->sampler;
		while ( sampler && sampler->info.id != -1 ) 
			sampler = sampler->next;

		if ( sampler ) {
			sampling_rate = sampler->info.interval;
			dbg_printf("[%u] Std sampling available for this flow source: Rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
		} else {
			sampling_rate = default_sampling;
			dbg_printf("[%u] No Sampling record found\n", exporter->info.id);
		}
	}

	if ( overwrite_sampling > 0 )  {
		sampling_rate = overwrite_sampling;
		dbg_printf("[%u] Hard overwrite sampling rate: %llu\n", exporter->info.id, (long long unsigned)sampling_rate);
	} 

	if ( sampling_rate != 1 )
		SetFlag(table->flags, FLAG_SAMPLED);

	while (size_left) {
		common_record_t		*data_record;

		if ( (size_left < table->input_record_size) ) {
			if ( size_left > 3 ) {
				//syslog(LOG_WARNING,"Process_v9: Corrupt data flowset? Pad bytes: %u", size_left);
				dbg_printf("Process_v9: Corrupt data flowset? Pad bytes: %u, table record_size: %u\n", 
					size_left, table->input_record_size);
			}
			size_left = 0;
			continue;
		}

		// check for enough space in output buffer
		if ( !CheckBufferSpace(fs->nffile, table->output_record_size) ) {
			// this should really never occur, because the buffer gets flushed ealier
			syslog(LOG_ERR,"Process_v9: output buffer size error. Abort v9 record processing");
			dbg_printf("Process_v9: output buffer size error. Abort v9 record processing");
			return;
		}
		processed_records++;

		// map file record to output buffer
		data_record	= (common_record_t *)fs->nffile->buff_ptr;
		// map output buffer as a byte array
		out 	  = (uint8_t *)data_record;

		dbg_printf("[%u] Process data record: %u addr: %llu, in record size: %u, buffer size_left: %u\n", 
			exporter->info.id, processed_records, (long long unsigned)((ptrdiff_t)in - (ptrdiff_t)data_flowset), 
			table->input_record_size, size_left);

		// fill the data record
		data_record->flags 		    = table->flags;
		data_record->size  		    = table->output_record_size;
		data_record->type  		    = CommonRecordType;
			data_record->ext_map	    = table->extension_info.map->map_id;
		data_record->exporter_sysid = exporter->info.sysid;

		table->packets 		  	    = 0;
		table->bytes 		  	    = 0;

		// apply copy and processing sequence
		for ( i=0; i<table->number_of_sequences; i++ ) {
			int input_offset  = table->sequence[i].input_offset;
			int output_offset = table->sequence[i].output_offset;
			void *stack = table->sequence[i].stack;
			switch (table->sequence[i].id) {
				case nop:
					break;
				case move8:
					out[output_offset] = in[input_offset];
					break;
				case move16:
					*((uint16_t *)&out[output_offset]) = Get_val16((void *)&in[input_offset]);
					break;
				
				case move_8:
					memcpy((void *)&out[output_offset],(void *)&in[input_offset],8);
					out[output_offset+8] = 0;      // trailing 0 for string
					break;
        case move_16:
          memcpy((void *)&out[output_offset],(void *)&in[input_offset],16);
          out[output_offset+16] = 0;
          break;
				case move_256:
					memcpy((void *)&out[output_offset],(void *)&in[input_offset],256);
					out[output_offset+256] = 0;
					break;
				case move_64:
					memcpy((void *)&out[output_offset],(void *)&in[input_offset],64);
					out[output_offset+64] = 0;
					break;
				case move_128:
					memcpy((void *)&out[output_offset],(void *)&in[input_offset],128);
					out[output_offset+128] = 0;
          break;
				case move_32:
					memcpy((void *)&out[output_offset],(void *)&in[input_offset],32);
					out[output_offset+32] = 0;
					break;
				case move_40:
					memcpy((void *)&out[output_offset],(void *)&in[input_offset],40);
					out[output_offset+40] = 0;
					break;
				case move32:
					*((uint32_t *)&out[output_offset]) = Get_val32((void *)&in[input_offset]);
					break;
				case move40:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val40((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case move48:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val64 = Get_val48((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case move56:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val56((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case move64: 
					{ type_mask_t t;
						t.val.val64 = Get_val64((void *)&in[input_offset]);

						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					} break;
				case move128: 
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						
						t.val.val64 = Get_val64((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset]) 	  = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4])  = t.val.val32[1];

						t.val.val64 = Get_val64((void *)&in[input_offset+8]);
						*((uint32_t *)&out[output_offset+8])  = t.val.val32[0];
						*((uint32_t *)&out[output_offset+12]) = t.val.val32[1];
					} break;
				case move32_sampling:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val64 = Get_val32((void *)&in[input_offset]);
						t.val.val64 *= sampling_rate;
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
							*(uint64_t *)stack = t.val.val64;
					} break;
				case move64_sampling:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val64 = Get_val64((void *)&in[input_offset]);

						t.val.val64 *= sampling_rate;
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
							*(uint64_t *)stack = t.val.val64;
					} break;
				case move_mac:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = Get_val48((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset])   = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case move_mpls:
					*((uint32_t *)&out[output_offset]) = Get_val24((void *)&in[input_offset]);
					break;
				case move_ulatency:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val32[0] = *((uint32_t *)&out[output_offset]);
						t.val.val32[1] = *((uint32_t *)&out[output_offset+4]);

						t.val.val64 += Get_val32((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset])   = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					} break;
				case move_slatency:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
						t.val.val32[0] = *((uint32_t *)&out[output_offset]);
						t.val.val32[1] = *((uint32_t *)&out[output_offset+4]);

						// update sec to usec
						t.val.val64 += 1000000 * Get_val32((void *)&in[input_offset]);
						*((uint32_t *)&out[output_offset])   = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					} break;
				case Time64Mili:
					{ uint64_t DateMiliseconds = Get_val64((void *)&in[input_offset]);
						*(uint64_t *)stack = DateMiliseconds;

					} break;

				// zero sequences for unavailable elements
				case zero8:
					out[output_offset] = 0;
					break;
				case zero16:
					*((uint16_t *)&out[output_offset]) = 0;
					break;
				case zero32:
					*((uint32_t *)&out[output_offset]) = 0;
					break;
				case zero64: 
						*((uint64_t *)&out[output_offset]) = 0;
					 break;
				case zero128: 
						*((uint64_t *)&out[output_offset]) = 0;
						*((uint64_t *)&out[output_offset+8]) = 0;
					break;
				
				default:
					syslog(LOG_ERR, "Process_v9: Software bug! Unknown Sequence: %u. at %s line %d", 
						table->sequence[i].id, __FILE__, __LINE__);
					dbg_printf("Software bug! Unknown Sequence: %u. at %s line %d", 
						table->sequence[i].id, __FILE__, __LINE__);
			}
		}


		// Ungly ICMP hack for v9, because some IOS version are lazzy
		// most of them send ICMP in dst port field some don't some have both
		if ( data_record->prot == IPPROTO_ICMP || data_record->prot == IPPROTO_ICMPV6 ) {
			if ( table->ICMP_offset ) {
				data_record->dstport = Get_val16((void *)&in[table->ICMP_offset]);
			}
			if ( data_record->dstport == 0 && data_record->srcport != 0 ) {
				// some IOSes are even lazzier and map ICMP code in src port - ughh
				data_record->dstport = data_record->srcport;
				data_record->srcport = 0;
			}
		}

		First = data_record->first;
		Last  = data_record->last;

		if ( First > Last )
			/* First in msec, in case of msec overflow, between start and end */
			start_time = exporter->boot_time - 0x100000000LL + (uint64_t)First;
		else
			start_time = (uint64_t)First + exporter->boot_time;

		/* end time in msecs */
		end_time = (uint64_t)Last + exporter->boot_time;

		data_record->first 		= start_time/1000;
		data_record->msec_first	= start_time - data_record->first*1000;
	
		data_record->last 		= end_time/1000;
		data_record->msec_last	= end_time - data_record->last*1000;

		if ( data_record->first == 0 && data_record->last == 0 )
			data_record->last = 0;

		// update first_seen, last_seen
		if ( start_time < fs->first_seen )
			fs->first_seen = start_time;
		if ( end_time > fs->last_seen )
			fs->last_seen = end_time;

		// check if we need to record the router IP address
		if ( table->router_ip_offset ) {
			int output_offset = table->router_ip_offset;
			if ( exporter->info.sa_family == PF_INET6 ) {
				/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
				type_mask_t t;
						
				t.val.val64 = exporter->info.ip.v6[0];
				*((uint32_t *)&out[output_offset]) 	  = t.val.val32[0];
				*((uint32_t *)&out[output_offset+4])  = t.val.val32[1];

				t.val.val64 = exporter->info.ip.v6[1];
				*((uint32_t *)&out[output_offset+8])  = t.val.val32[0];
				*((uint32_t *)&out[output_offset+12]) = t.val.val32[1];
			} else {
				*((uint32_t *)&out[output_offset]) = exporter->info.ip.v4;
			}
		}

		// Ugly hack. CISCO never really implemented #38/#39 tags in the records - so take it from the 
		// header, unless some data is filled in
		if ( table->engine_offset ) {
			if ( *((uint32_t *)&out[table->engine_offset]) == 0 ) {
				tpl_ext_25_t *tpl = (tpl_ext_25_t *)&out[table->engine_offset];
				tpl->engine_type = ( exporter->info.id >> 8 ) & 0xFF;
				tpl->engine_id	 = exporter->info.id & 0xFF;
			}
		}

		// check, if we need to store the packet received time
		if ( table->received_offset ) {
			type_mask_t t;
			t.val.val64 = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);
				*((uint32_t *)&out[table->received_offset])   = t.val.val32[0];
				*((uint32_t *)&out[table->received_offset+4]) = t.val.val32[1];
		}

		switch (data_record->prot ) { // switch protocol of
			case IPPROTO_ICMP:
				fs->nffile->stat_record->numflows_icmp++;
				fs->nffile->stat_record->numpackets_icmp  += table->packets;
				fs->nffile->stat_record->numbytes_icmp    += table->bytes;
				break;
			case IPPROTO_TCP:
				fs->nffile->stat_record->numflows_tcp++;
				fs->nffile->stat_record->numpackets_tcp   += table->packets;
				fs->nffile->stat_record->numbytes_tcp     += table->bytes;
				break;
			case IPPROTO_UDP:
				fs->nffile->stat_record->numflows_udp++;
				fs->nffile->stat_record->numpackets_udp   += table->packets;
				fs->nffile->stat_record->numbytes_udp     += table->bytes;
				break;
			default:
				fs->nffile->stat_record->numflows_other++;
				fs->nffile->stat_record->numpackets_other += table->packets;
				fs->nffile->stat_record->numbytes_other   += table->bytes;
		}
		exporter->flows++;
		fs->nffile->stat_record->numflows++;
		fs->nffile->stat_record->numpackets	+= table->packets;
		fs->nffile->stat_record->numbytes	+= table->bytes;
	
		if ( fs->xstat ) {
			uint32_t bpp = table->packets ? table->bytes/table->packets : 0;
			if ( bpp > MAX_BPP ) 
				bpp = MAX_BPP;
			if ( data_record->prot == IPPROTO_TCP ) {
				fs->xstat->bpp_histogram->tcp.bpp[bpp]++;
				fs->xstat->bpp_histogram->tcp.count++;

				fs->xstat->port_histogram->src_tcp.port[data_record->srcport]++;
				fs->xstat->port_histogram->dst_tcp.port[data_record->dstport]++;
				fs->xstat->port_histogram->src_tcp.count++;
				fs->xstat->port_histogram->dst_tcp.count++;
			} else if ( data_record->prot == IPPROTO_UDP ) {
				fs->xstat->bpp_histogram->udp.bpp[bpp]++;
				fs->xstat->bpp_histogram->udp.count++;

				fs->xstat->port_histogram->src_udp.port[data_record->srcport]++;
				fs->xstat->port_histogram->dst_udp.port[data_record->dstport]++;
				fs->xstat->port_histogram->src_udp.count++;
				fs->xstat->port_histogram->dst_udp.count++;
			}
		}

		if ( verbose ) {
			master_record_t master_record;
			ExpandRecord_v2((common_record_t *)data_record, &(table->extension_info), &(exporter->info), &master_record);
			format_file_block_record(&master_record, &string, 0);
			printf("%s\n", string);
		}

		fs->nffile->block_header->size  += data_record->size;
		fs->nffile->block_header->NumRecords++;
		fs->nffile->buff_ptr	= (common_record_t *)((pointer_addr_t)data_record + data_record->size);

		// advance input
		size_left 		   -= table->input_record_size;
		in  	  		   += table->input_record_size;

		// buffer size sanity check
		if ( fs->nffile->block_header->size  > BUFFSIZE ) {
			// should never happen
			syslog(LOG_ERR,"### Software error ###: %s line %d", __FILE__, __LINE__);
			syslog(LOG_ERR,"Process v9: Output buffer overflow! Flush buffer and skip records.");
			syslog(LOG_ERR,"Buffer size: %u > %u", fs->nffile->block_header->size, BUFFSIZE);

			// reset buffer
			fs->nffile->block_header->size 		= 0;
			fs->nffile->block_header->NumRecords = 0;
			fs->nffile->buff_ptr = (void *)((pointer_addr_t)fs->nffile->block_header + sizeof(data_block_header_t) );
			return;
		}
	}

} // End of Process_v9_data

static inline void 	Process_v9_option_data(exporter_v9_domain_t *exporter, void *data_flowset, FlowSource_t *fs) {
option_offset_t *offset_table;
uint32_t	id, size_left;
uint8_t		*in;

	id 	= GET_FLOWSET_ID(data_flowset);

	offset_table = fs->option_offset_table;
	while ( offset_table && offset_table->id != id )
		offset_table = offset_table->next;

	if ( !offset_table ) {
		// should never happen - catch it anyway
		syslog(LOG_ERR, "Process_v9: Panic! - No Offset table found! : %s line %d", __FILE__, __LINE__);
		return;
	}

	size_left = GET_FLOWSET_LENGTH(data_flowset) - 4; // -4 for data flowset header -> id and length
	dbg_printf("[%u] Process option data flowset size: %u\n", exporter->info.id, size_left);

	// map input buffer as a byte array
	in	  = (uint8_t *)(data_flowset + 4);	// skip flowset header

	if ( TestFlag(offset_table->flags, HAS_SAMPLER_DATA) ) {
		int32_t  id;
		uint16_t mode;
		uint32_t interval;
		if (offset_table->sampler_id_length == 2) {
			id = Get_val16((void *)&in[offset_table->offset_id]);
		} else {
			id = in[offset_table->offset_id];
		}
		mode 	 = in[offset_table->offset_mode];
		interval = Get_val32((void *)&in[offset_table->offset_interval]); 
	
		dbg_printf("Extracted Sampler data:\n");
		dbg_printf("Sampler ID      : %u\n", id);
		dbg_printf("Sampler mode    : %u\n", mode);
		dbg_printf("Sampler interval: %u\n", interval);
	
		InsertSampler(fs, exporter, id, mode, interval);
	}

	if ( TestFlag(offset_table->flags, HAS_STD_SAMPLER_DATA) ) {
		int32_t  id 	  = -1;
		uint16_t mode 	  = in[offset_table->offset_std_sampler_algorithm];
		uint32_t interval = Get_val32((void *)&in[offset_table->offset_std_sampler_interval]);

		InsertSampler(fs, exporter, id, mode, interval);

		dbg_printf("Extracted Std Sampler data:\n");
		dbg_printf("Sampler ID       : %u\n", id);
		dbg_printf("Sampler algorithm: %u\n", mode);
		dbg_printf("Sampler interval : %u\n", interval);

		syslog(LOG_INFO, "Set std sampler: algorithm: %u, interval: %u\n", 
				mode, interval);
		dbg_printf("Set std sampler: algorithm: %u, interval: %u\n", 
				mode, interval);
	}
	processed_records++;

} // End of Process_v9_option_data

void Process_v9(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
exporter_v9_domain_t	*exporter;
void				*flowset_header;
option_template_flowset_t	*option_flowset;
netflow_v9_header_t	*v9_header;
int64_t 			distance;
uint32_t 			expected_records, flowset_id, flowset_length, exporter_id;
ssize_t				size_left;
static int pkg_num = 0;

	pkg_num++;

	size_left = in_buff_cnt;
	if ( size_left < NETFLOW_V9_HEADER_LENGTH ) {
		syslog(LOG_ERR, "Process_v9: Too little data for v9 packet: '%lli'", (long long)size_left);
		return;
	}

	// map v9 data structure to input buffer
	v9_header 	= (netflow_v9_header_t *)in_buff;
	exporter_id = ntohl(v9_header->source_id);

	exporter	= GetExporter(fs, exporter_id);
	if ( !exporter ) {
		syslog(LOG_ERR,"Process_v9: Exporter NULL: Abort v9 record processing");
		return;
	}
	exporter->packets++;

	/* calculate boot time in msec */
		v9_header->SysUptime 	= ntohl(v9_header->SysUptime);
		v9_header->unix_secs	= ntohl(v9_header->unix_secs);
	exporter->boot_time  	= (uint64_t)1000 * (uint64_t)(v9_header->unix_secs) - (uint64_t)v9_header->SysUptime;
	
	expected_records 		= ntohs(v9_header->count);
	flowset_header 			= (void *)v9_header + NETFLOW_V9_HEADER_LENGTH;

	size_left -= NETFLOW_V9_HEADER_LENGTH;

	dbg_printf("\n[%u] Next packet: %i %u records, buffer: %li \n", exporter_id, pkg_num, expected_records, size_left);
	// sequence check
	if ( exporter->first ) {
		exporter->last_sequence = ntohl(v9_header->sequence);
		exporter->sequence 	  	= exporter->last_sequence;
		exporter->first			= 0;
	} else {
		exporter->last_sequence = exporter->sequence;
		exporter->sequence 	  = ntohl(v9_header->sequence);
		distance 	  = exporter->sequence - exporter->last_sequence;
		// handle overflow
		if (distance < 0) {
			distance = 0xffffffff + distance  +1;
		}
		if (distance != 1) {
			exporter->sequence_failure++;
			fs->nffile->stat_record->sequence_failure++;
			dbg_printf("[%u] Sequence error: last seq: %lli, seq %lli dist %lli\n", 
				exporter->info.id, (long long)exporter->last_sequence, (long long)exporter->sequence, (long long)distance);
			
			/*
			if ( report_seq ) 
				syslog(LOG_ERR,"Flow sequence mismatch. Missing: %lli packets", delta(last_count,distance));
			*/
		}
	}

	processed_records = 0;

	// iterate over all flowsets in export packet, while there are bytes left
	flowset_length = 0;
	while (size_left) {
		flowset_header = flowset_header + flowset_length;

		flowset_id 		= GET_FLOWSET_ID(flowset_header);
		flowset_length 	= GET_FLOWSET_LENGTH(flowset_header);
			
		dbg_printf("[%u] Next flowset: %u, length: %u buffersize: %li addr: %llu\n", 
			exporter->info.id, flowset_id, flowset_length, size_left, 
			(long long unsigned)(flowset_header - in_buff) );

		if ( flowset_length == 0 ) {
			/* 	this should never happen, as 4 is an empty flowset 
				and smaller is an illegal flowset anyway ...
				if it happends, we can't determine the next flowset, so skip the entire export packet
			 */
			syslog(LOG_ERR,"Process_v9: flowset zero length error.");
			dbg_printf("Process_v9: flowset zero length error.\n");
			return;
		}

		// possible padding
		if ( flowset_length <= 4 ) {
			size_left = 0;
			continue;
		}

		if ( flowset_length > size_left ) {
			dbg_printf("flowset length error. Expected bytes: %u > buffersize: %lli", 
				flowset_length, (long long)size_left);
			syslog(LOG_ERR,"Process_v9: flowset length error. Expected bytes: %u > buffersize: %lli", 
				flowset_length, (long long)size_left);
			size_left = 0;
			continue;
		}

#ifdef DEVEL
		if ( (ptrdiff_t)fs->nffile->buff_ptr & 0x3 ) {
			fprintf(stderr, "PANIC: alignment error!! \n");
			exit(255);
		}
#endif

		switch (flowset_id) {
			case NF9_TEMPLATE_FLOWSET_ID:
				Process_v9_templates(exporter, flowset_header, fs);
				break;
			case NF9_OPTIONS_FLOWSET_ID:
				option_flowset = (option_template_flowset_t *)flowset_header;
				syslog(LOG_DEBUG,"Process_v9: Found options flowset: template %u", ntohs(option_flowset->template_id));
				Process_v9_option_templates(exporter, flowset_header, fs);
				break;
			default: {
				input_translation_t *table;
				if ( flowset_id < NF9_MIN_RECORD_FLOWSET_ID ) {
					dbg_printf("Invalid flowset id: %u\n", flowset_id);
					syslog(LOG_ERR,"Process_v9: Invalid flowset id: %u", flowset_id);
				} else {

					dbg_printf("[%u] ID %u Data flowset\n", exporter->info.id, flowset_id);

					table = GetTranslationTable(exporter, flowset_id);
					if ( table ) {
						Process_v9_data(exporter, flowset_header, fs, table);
					} else if ( HasOptionTable(fs, flowset_id) ) {
						Process_v9_option_data(exporter, flowset_header, fs);
					} else {
						// maybe a flowset with option data
						dbg_printf("Process v9: [%u] No table for id %u -> Skip record\n", 
							exporter->info.id, flowset_id);
					}
				}
			}
		}

		// next flowset
		size_left -= flowset_length;

	} // End of while 

#ifdef DEVEL
	if ( processed_records != expected_records ) {
		syslog(LOG_ERR, "Process_v9: Processed records %u, expected %u", processed_records, expected_records);
		printf("Process_v9: Processed records %u, expected %u\n", processed_records, expected_records);
	}
#endif

	return;
	
} /* End of Process_v9 */

/*
 * functions for sending netflow v9 records
 */

void Init_v9_output(send_peer_t *peer) {
int i;

	v9_output_header = (netflow_v9_header_t *)peer->send_buffer;
	v9_output_header->version 		= htons(9);
	v9_output_header->SysUptime		= 0;
	v9_output_header->unix_secs		= 0;
	v9_output_header->count 		= 0;
	v9_output_header->source_id 	= htonl(1);
	template_id						= NF9_MIN_RECORD_FLOWSET_ID;
	peer->buff_ptr = (void *)((pointer_addr_t)v9_output_header + (pointer_addr_t)sizeof(netflow_v9_header_t));	

	// set the max number of v9 tags, we support.
	Max_num_v9_tags = 0;
	for (i=1; v9_element_map[i].id != 0; i++ ) {
		if ( v9_element_map[i].id != v9_element_map[i-1].id ) 
			Max_num_v9_tags++;
	}

} // End of Init_v9_output

static output_template_t *GetOutputTemplate(uint32_t flags, extension_map_t *extension_map) {
output_template_t **t;
template_record_t	*fields;
uint32_t	i, count, record_length;

	t = &output_templates;
	// search for the template, which corresponds to our flags and extension map
	while ( *t ) {
		if ( (*t)->flags == flags &&  (*t)->extension_map == extension_map ) 
			return *t;
		t = &((*t)->next);
	}

	// nothing found, otherwise we would not get here
	*t = (output_template_t *)malloc(sizeof(output_template_t));
	if ( !(*t)) {
		fprintf(stderr, "Panic! malloc() %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		exit(255);
	}
	memset((void *)(*t), 0, sizeof(output_template_t));
	(*t)->next	 		 = NULL;
	(*t)->flags	 		 = flags;
	(*t)->extension_map  = extension_map;
	(*t)->time_sent		 = 0;
	(*t)->template_flowset = (template_flowset_t*)malloc(sizeof(template_flowset_t) + ((Max_num_v9_tags * 4))); // 4 for 2 x uint16_t: type/length

	count 			= 0;
	record_length 	= 0;
	fields = (*t)->template_flowset->fields;

	// Fill the template flowset in the order of the common_record_t 
	// followed be the available extensions
	fields->record[count].type	 = htons(NF9_FIRST_SWITCHED);
	fields->record[count].length = htons(4);
	record_length 				+= 4;
	count++;

	fields->record[count].type   = htons(NF9_LAST_SWITCHED);
	fields->record[count].length = htons(4);
	record_length 				+= 4;
	count++;

	fields->record[count].type   = htons(NF9_FORWARDING_STATUS);
	fields->record[count].length = htons(1);
	record_length 				+= 1;
	count++;

	fields->record[count].type   = htons(NF9_TCP_FLAGS);
	fields->record[count].length = htons(1);
	record_length 				+= 1;
	count++;

	fields->record[count].type   = htons(NF9_IN_PROTOCOL);
	fields->record[count].length = htons(1);
	record_length 				+= 1;
	count++;

	fields->record[count].type   = htons(NF9_SRC_TOS);
	fields->record[count].length = htons(1);
	record_length 				+= 1;
	count++;

	fields->record[count].type   = htons(NF9_L4_SRC_PORT);
	fields->record[count].length = htons(2);
	record_length 				+= 2;
	count++;

	fields->record[count].type   = htons(NF9_L4_DST_PORT);
	fields->record[count].length = htons(2);
	record_length 				+= 2;
	count++;

		fields->record[count].type   = htons(NF9_ICMP_TYPE);
		fields->record[count].length = htons(2);
		record_length               += 2;
		count++;

	// common record processed

	// fill in IP address tags
	if ( (flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6 addresses
		fields->record[count].type   = htons(NF9_IPV6_SRC_ADDR);
		fields->record[count].length = htons(16);
		record_length 				+= 16;
		count++;
		fields->record[count].type   = htons(NF9_IPV6_DST_ADDR);
		fields->record[count].length = htons(16);
		record_length 				+= 16;
	} else { // IPv4 addresses
		fields->record[count].type   = htons(NF9_IPV4_SRC_ADDR);
		fields->record[count].length = htons(4);
		record_length 				+= 4;
		count++;
		fields->record[count].type   = htons(NF9_IPV4_DST_ADDR);
		fields->record[count].length = htons(4);
		record_length 				+= 4;
	}
	count++;

	// packet counter
	fields->record[count].type  = htons(NF9_IN_PACKETS);
	if ( (flags & FLAG_PKG_64) != 0 ) {  // 64bit packet counter
		fields->record[count].length = htons(8);
		record_length 				+= 8;
	} else {
		fields->record[count].length = htons(4);
		record_length 				+= 4;
	}
	count++;

	// bytes counter
	fields->record[count].type  = htons(NF9_IN_BYTES);
	if ( (flags & FLAG_BYTES_64) != 0 ) { // 64bit byte counter
		fields->record[count].length = htons(8);
		record_length 				+= 8;
	} else {
		fields->record[count].length = htons(4);
		record_length 				+= 4;
	}
	count++;
	// process extension map 
	i = 0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2:
				fields->record[count].type   = htons(NF9_INPUT_SNMP);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;

				fields->record[count].type   = htons(NF9_OUTPUT_SNMP);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;
				break;
			case EX_IO_SNMP_4:	// input/output SNMP 4 byte
				fields->record[count].type   = htons(NF9_INPUT_SNMP);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;

				fields->record[count].type   = htons(NF9_OUTPUT_SNMP);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_AS_2:	// srcas/dstas 2 byte
				fields->record[count].type   = htons(NF9_SRC_AS);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;

				fields->record[count].type   = htons(NF9_DST_AS);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;
				break;
			case EX_AS_4:	// srcas/dstas 4 byte
				fields->record[count].type   = htons(NF9_SRC_AS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;

				fields->record[count].type   = htons(NF9_DST_AS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_MULIPLE: {
				uint16_t src_mask, dst_mask;
				fields->record[count].type   = htons(NF9_DST_TOS);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;

				fields->record[count].type   = htons(NF9_DIRECTION);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;

				if ( (flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6 addresses
					src_mask = NF9_IPV6_SRC_MASK;
					dst_mask = NF9_IPV6_DST_MASK;
				} else { // IPv4 addresses
					src_mask = NF9_SRC_MASK;
					dst_mask = NF9_DST_MASK;
				}

				fields->record[count].type   = htons(src_mask);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;

				fields->record[count].type   = htons(dst_mask);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;
				} break;
			case EX_NEXT_HOP_v4:
				fields->record[count].type   = htons(NF9_V4_NEXT_HOP);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_NEXT_HOP_v6:
				fields->record[count].type   = htons(NF9_V6_NEXT_HOP);
				fields->record[count].length = htons(16);
				record_length 				+= 16;
				count++;
				break;
			case EX_NEXT_HOP_BGP_v4:
				fields->record[count].type   = htons(NF9_BGP_V4_NEXT_HOP);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_NEXT_HOP_BGP_v6:
				fields->record[count].type   = htons(NF9_BPG_V6_NEXT_HOP);
				fields->record[count].length = htons(16);
				record_length 				+= 16;
				count++;
				break;
			case EX_VLAN:
				fields->record[count].type   = htons(NF9_SRC_VLAN);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;

				fields->record[count].type   = htons(NF9_DST_VLAN);
				fields->record[count].length = htons(2);
				record_length 				+= 2;
				count++;
				break;
			case EX_OUT_PKG_4:
				fields->record[count].type   = htons(NF9_OUT_PKTS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_OUT_PKG_8:
				fields->record[count].type   = htons(NF9_OUT_PKTS);
				fields->record[count].length = htons(8);
				record_length 				+= 8;
				count++;
				break;
			case EX_OUT_BYTES_4:
				fields->record[count].type   = htons(NF9_OUT_BYTES);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_OUT_BYTES_8:
				fields->record[count].type   = htons(NF9_OUT_BYTES);
				fields->record[count].length = htons(8);
				record_length 				+= 8;
				count++;
				break;
			case EX_AGGR_FLOWS_4:
				fields->record[count].type   = htons(NF9_FLOWS_AGGR);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;
			case EX_AGGR_FLOWS_8:
				fields->record[count].type   = htons(NF9_FLOWS_AGGR);
				fields->record[count].length = htons(8);
				record_length 				+= 8;
				count++;
				break;
			case EX_MAC_1:
				fields->record[count].type   = htons(NF9_IN_SRC_MAC);
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;

				fields->record[count].type   = htons(NF9_OUT_DST_MAC);
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;
				break;
			case EX_MAC_2:
				fields->record[count].type   = htons(NF9_IN_DST_MAC);
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;

				fields->record[count].type   = htons(NF9_OUT_SRC_MAC);
				fields->record[count].length = htons(6);
				record_length 				+= 6;
				count++;
				break;
			case EX_MPLS:
				fields->record[count].type   = htons(NF9_MPLS_LABEL_1);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_2);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_3);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_4);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_5);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_6);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_7);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_8);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_9);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				fields->record[count].type   = htons(NF9_MPLS_LABEL_10);
				fields->record[count].length = htons(3);
				record_length 				+= 3;
				count++;

				break;
			case EX_ROUTER_ID:
				fields->record[count].type   = htons(NF9_ENGINE_TYPE);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;

				fields->record[count].type   = htons(NF9_ENGINE_ID);
				fields->record[count].length = htons(1);
				record_length 				+= 1;
				count++;
				break;
			case EX_BGPADJ:
				fields->record[count].type   = htons(NF9_BGP_ADJ_NEXT_AS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;

				fields->record[count].type   = htons(NF9_BGP_ADJ_PREV_AS);
				fields->record[count].length = htons(4);
				record_length 				+= 4;
				count++;
				break;

			// default: other extensions are not (yet) recognised
		}
	}

	(*t)->template_flowset->flowset_id   = htons(NF9_TEMPLATE_FLOWSET_ID);
	(*t)->flowset_length				 = 4 * (2+count); // + 2 for the header

	// add proper padding for 32bit boundary
	if ( ((*t)->flowset_length & 0x3 ) != 0 ) 
		(*t)->flowset_length += (4 - ((*t)->flowset_length & 0x3 ));
	(*t)->template_flowset->length  	 = htons((*t)->flowset_length);

	(*t)->record_length		= record_length;

	fields->template_id		= htons(template_id++);
	fields->count			= htons(count);

	return *t;

} // End of GetOutputTemplate

static void Append_Record(send_peer_t *peer, master_record_t *master_record) {
extension_map_t *extension_map = master_record->map_ref;
uint32_t	i, t1, t2;
uint16_t	icmp;

	t1 	= (uint32_t)(1000LL * (uint64_t)master_record->first + master_record->msec_first - boot_time);
	t2	= (uint32_t)(1000LL * (uint64_t)master_record->last  + master_record->msec_last - boot_time);
		master_record->first	= htonl(t1);
		master_record->last		= htonl(t2);

		master_record->srcport	= htons(master_record->srcport);
		master_record->dstport	= htons(master_record->dstport);

	// if it's an ICMP send it in the appropriate v9 tag
	if ( master_record->prot == IPPROTO_ICMP || master_record->prot == IPPROTO_ICMPV6  ) { // it's an ICMP
		icmp = master_record->dstport;
		master_record->dstport = 0;
	} else {
		icmp = 0;
	}
	// write the first 16 bytes of the master_record starting with first up to and including dst port
	memcpy(peer->buff_ptr, (void *)&master_record->first, 16);
	peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 16);

	// write ICMP type/code
	memcpy(peer->buff_ptr, (void *)&icmp,2);
	peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 2);

	// IP address info
	if ((master_record->flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6
		master_record->v6.srcaddr[0] = htonll(master_record->v6.srcaddr[0]);
		master_record->v6.srcaddr[1] = htonll(master_record->v6.srcaddr[1]);
		master_record->v6.dstaddr[0] = htonll(master_record->v6.dstaddr[0]);
		master_record->v6.dstaddr[1] = htonll(master_record->v6.dstaddr[1]);
		memcpy(peer->buff_ptr, master_record->v6.srcaddr, 4 * sizeof(uint64_t));
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 4 * sizeof(uint64_t));
	} else {
		Put_val32(htonl(master_record->v4.srcaddr), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
		Put_val32(htonl(master_record->v4.dstaddr), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// packet counter
	if ((master_record->flags & FLAG_PKG_64) != 0 ) { // 64bit counters
		Put_val64(htonll(master_record->dPkts), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
	} else {
		Put_val32(htonl((uint32_t)master_record->dPkts), peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// bytes counter
	if ((master_record->flags & FLAG_BYTES_64) != 0 ) { // 64bit counters
		Put_val64(htonll(master_record->dOctets),peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
	} else {
		Put_val32(htonl((uint32_t)master_record->dOctets),peer->buff_ptr);
		peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
	}

	// send now optional extensions according the extension map
	i=0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2: {
				uint16_t in, out;

				in  = htons(master_record->input);
				Put_val16(in, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));

				out = htons(master_record->output);
				Put_val16(out, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				} break;
			case EX_IO_SNMP_4:
				Put_val32(htonl(master_record->input), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				Put_val32(htonl(master_record->output), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_AS_2: { // srcas/dstas 2 byte
				uint16_t src, dst;

				src = htons(master_record->srcas);
				Put_val16(src, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));

				dst = htons(master_record->dstas);
				Put_val16(dst, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				} break;
			case EX_AS_4:  // srcas/dstas 4 byte
				Put_val32(htonl(master_record->srcas), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				Put_val32(htonl(master_record->dstas), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)peer->buff_ptr;
				tpl->dst_tos  = master_record->dst_tos;
				tpl->dir 	  = master_record->dir;
				tpl->src_mask = master_record->src_mask;
				tpl->dst_mask = master_record->dst_mask;
				peer->buff_ptr = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v4:
				Put_val32(htonl(master_record->ip_nexthop.v4), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_NEXT_HOP_v6: 
				Put_val64(htonll(master_record->ip_nexthop.v6[0]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				Put_val64(htonll(master_record->ip_nexthop.v6[1]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_NEXT_HOP_BGP_v4: 
				Put_val32(htonl(master_record->bgp_nexthop.v4), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_NEXT_HOP_BGP_v6: 
				Put_val64(htonll(master_record->bgp_nexthop.v6[0]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				Put_val64(htonll(master_record->bgp_nexthop.v6[1]), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_VLAN: 
				Put_val16(htons(master_record->src_vlan), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				Put_val16(htons(master_record->dst_vlan), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint16_t));
				break;
			case EX_OUT_PKG_4: 
				Put_val32(htonl(master_record->out_pkts), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_OUT_PKG_8:
				Put_val64(htonll(master_record->out_pkts), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_OUT_BYTES_4:
				Put_val32(htonl(master_record->out_bytes), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_OUT_BYTES_8:
				Put_val64(htonll(master_record->out_bytes), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_AGGR_FLOWS_4:
				Put_val32(htonl(master_record->aggr_flows), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;
			case EX_AGGR_FLOWS_8:
				Put_val64(htonll(master_record->aggr_flows), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint64_t));
				break;
			case EX_MAC_1: {
				uint64_t	val64;
				val64 = htonll(master_record->in_src_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				val64 = htonll(master_record->out_dst_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				} break;
			case EX_MAC_2: {
				uint64_t	val64;
				val64 = htonll(master_record->in_dst_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				val64 = htonll(master_record->out_src_mac);
				Put_val48(val64, peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 6);	// 48 bits

				} break;
			case EX_MPLS: {
				uint32_t val32, i;
				for ( i=0; i<10; i++ ) {
					val32 = htonl(master_record->mpls_label[i]);
					Put_val24(val32, peer->buff_ptr);
					peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + 3);	// 24 bits
				}
				} break;
			case EX_ROUTER_ID: {
				uint8_t *u = (uint8_t *)peer->buff_ptr;
				*u++ = master_record->engine_type;
				*u++ = master_record->engine_id;
				peer->buff_ptr = (void *)u;
				} break;
			case EX_BGPADJ:
				Put_val32(htonl(master_record->bgpNextAdjacentAS), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				Put_val32(htonl(master_record->bgpPrevAdjacentAS), peer->buff_ptr);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + sizeof(uint32_t));
				break;

			// default: ignore all other extension, as we do not understand them
		}
	}

} // End of Append_Record

int Add_v9_output_record(master_record_t *master_record, send_peer_t *peer) {
static data_flowset_t		*data_flowset;
static output_template_t	*v9_template;
static uint32_t	last_flags = 0;
static extension_map_t *last_map = NULL;
static int	record_count, template_count, flowset_count, packet_count;
uint32_t	required_size;
void		*endwrite;
time_t		now = time(NULL);

#ifdef DEVEL
//	char		*string;
//	format_file_block_record(master_record, 1, &string, 0);
//	dbg_printf("%s\n", string);
#endif

	if ( !v9_output_header->unix_secs ) {	// first time a record is added
		// boot time is set one day back - assuming that the start time of every flow does not start ealier
		boot_time	   = (uint64_t)(master_record->first - 86400)*1000;
		v9_output_header->unix_secs = htonl(master_record->first - 86400);
		v9_output_header->sequence  = 0;
		peer->buff_ptr  = (void *)((pointer_addr_t)peer->send_buffer + NETFLOW_V9_HEADER_LENGTH);
		record_count   = 0;
		template_count = 0;
		flowset_count  = 0;
		packet_count   = 0;
		data_flowset   = NULL;

		// write common blocksize from frst up to including dstas for one write (memcpy)
//		common_block_size = (pointer_addr_t)&master_record->fill - (pointer_addr_t)&master_record->first;

	} else if ( flowset_count == 0 ) {	// after a buffer flush
		packet_count++;
		v9_output_header->sequence = htonl(packet_count);
	}

	if ( data_flowset ) {
		// output buffer contains already a data flowset
		if ( last_flags == master_record->flags && last_map == master_record->map_ref ) {
			// same id as last record
			// if ( now - template->time_sent > MAX_LIFETIME )
			if ( (record_count & 0xFFF) == 0 ) {	// every 4096 flow records
				uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;
				uint8_t	align   = length & 0x3;
				if ( align != 0 ) {
					length += ( 4 - align );
					data_flowset->length = htons(length);
					peer->buff_ptr += align;
				}
				// template refresh is needed
				// terminate the current data flowset
				data_flowset = NULL;
				if ( (pointer_addr_t)peer->buff_ptr + v9_template->flowset_length > (pointer_addr_t)peer->endp ) {
					// not enough space for template flowset => flush buffer first
					record_count   = 0;
					flowset_count  = 0;
					template_count = 0;
					peer->flush = 1;
					return 1;	// return to flush buffer
				}
				memcpy(peer->buff_ptr, (void *)v9_template->template_flowset, v9_template->flowset_length);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + v9_template->flowset_length);
				v9_template->time_sent = now;
				flowset_count++;
				template_count++;

				// open a new data flow set at this point in the output buffer
				data_flowset = (data_flowset_t *)peer->buff_ptr;
				data_flowset->flowset_id = v9_template->template_flowset->fields[0].template_id;
				peer->buff_ptr = (void *)data_flowset->data;
				flowset_count++;
			} // else Add record

		} else {
			// record with different template id
			// terminate the current data flowset
			uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;
			uint8_t	align   = length & 0x3;
			if ( align != 0 ) {
				length += ( 4 - align );
				data_flowset->length = htons(length);
				peer->buff_ptr += align;
			}
			data_flowset = NULL;

			last_flags 	= master_record->flags;
			last_map	= master_record->map_ref;
			v9_template 	= GetOutputTemplate(last_flags, master_record->map_ref);
			if ( now - v9_template->time_sent > MAX_LIFETIME ) {
				// refresh template is needed
				endwrite= (void *)((pointer_addr_t)peer->buff_ptr + v9_template->flowset_length + sizeof(data_flowset_t));
				if ( endwrite > peer->endp ) {
					// not enough space for template flowset => flush buffer first
					record_count   = 0;
					flowset_count  = 0;
					template_count = 0;
					peer->flush = 1;
					return 1;	// return to flush the buffer
				}
				memcpy(peer->buff_ptr, (void *)v9_template->template_flowset, v9_template->flowset_length);
				peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + v9_template->flowset_length);
				v9_template->time_sent = now;
				flowset_count++;
				template_count++;
			}
			// open a new data flow set at this point in the output buffer
			data_flowset = (data_flowset_t *)peer->buff_ptr;
			data_flowset->flowset_id = v9_template->template_flowset->fields[0].template_id;
			peer->buff_ptr = (void *)data_flowset->data;
			flowset_count++;
		}
	} else {
		// output buffer does not contain a data flowset
		peer->buff_ptr = (void *)((pointer_addr_t)v9_output_header + (pointer_addr_t)sizeof(netflow_v9_header_t));	
		last_flags = master_record->flags;
		last_map	= master_record->map_ref;
		v9_template = GetOutputTemplate(last_flags, master_record->map_ref);
		if ( now - v9_template->time_sent > MAX_LIFETIME ) {
			// refresh template
			endwrite= (void *)((pointer_addr_t)peer->buff_ptr + v9_template->flowset_length + sizeof(data_flowset_t));
			if ( endwrite > peer->endp ) {
				// this must never happen!
				fprintf(stderr, "Panic: Software error in %s line %d\n", __FILE__, __LINE__);
				fprintf(stderr, "buffer %p, buff_ptr %p template length %x, endbuff %p\n", 
					peer->send_buffer, peer->buff_ptr, v9_template->flowset_length + (uint32_t)sizeof(data_flowset_t), peer->endp );
				exit(255);
			}
			memcpy(peer->buff_ptr, (void *)v9_template->template_flowset, v9_template->flowset_length);
			peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + v9_template->flowset_length);
			v9_template->time_sent = now;
			flowset_count++;
			template_count++;
		}
		// open a new data flow set at this point in the output buffer
		data_flowset = (data_flowset_t *)peer->buff_ptr;
		data_flowset->flowset_id = v9_template->template_flowset->fields[0].template_id;
		peer->buff_ptr = (void *)data_flowset->data;
		flowset_count++;
	}
	// now add the record

	required_size = v9_template->record_length;

	endwrite = (void *)((pointer_addr_t)peer->buff_ptr + required_size);
	if ( endwrite > peer->endp ) {
		uint16_t length = (pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset;

		// flush the buffer
		data_flowset->length = htons(length);
		if ( length == 4 ) {	// empty flowset
			peer->buff_ptr = (void *)data_flowset;
		} 
		data_flowset = NULL;
		v9_output_header->count = htons(record_count+template_count);
		record_count   = 0;
		template_count = 0;
		flowset_count  = 0;
		peer->flush    = 1;
		return 1;	// return to flush buffer
	}

	// this was a long way up to here, now we can add the data
	Append_Record(peer, master_record);

	data_flowset->length = htons((pointer_addr_t)peer->buff_ptr - (pointer_addr_t)data_flowset);
	record_count++;
	v9_output_header->count = htons(record_count+template_count);

	return 0;

} // End of Add_v9_output_record


static void InsertSampler( FlowSource_t *fs, exporter_v9_domain_t *exporter, int32_t id, uint16_t mode, uint32_t interval) {
generic_sampler_t *sampler;

	if ( !exporter->sampler ) {
		// no samplers so far 
		sampler = (generic_sampler_t *)malloc(sizeof(generic_sampler_t));
		if ( !sampler ) {
			syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			return;
		}

		sampler->info.header.type = SamplerInfoRecordype;
		sampler->info.header.size = sizeof(sampler_info_record_t);
		sampler->info.exporter_sysid = exporter->info.sysid;
		sampler->info.id 	   = id;
		sampler->info.mode 	   = mode;
		sampler->info.interval = interval;
		sampler->next 		   = NULL;
		exporter->sampler = sampler;

		FlushInfoSampler(fs, &(sampler->info));
		syslog(LOG_INFO, "Add new sampler: ID: %i, mode: %u, interval: %u\n", 
			id, mode, interval);
		dbg_printf("Add new sampler: ID: %i, mode: %u, interval: %u\n", 
			id, mode, interval);

	} else {
		sampler = exporter->sampler;
		while ( sampler ) {
			// test for update of existing sampler
			if ( sampler->info.id == id ) {
				// found same sampler id - update record
				syslog(LOG_INFO, "Update existing sampler id: %i, mode: %u, interval: %u\n", 
					id, mode, interval);
				dbg_printf("Update existing sampler id: %i, mode: %u, interval: %u\n", 
					id, mode, interval);

				// we update only on changes
				if ( mode != sampler->info.mode || interval != sampler->info.interval ) {
					FlushInfoSampler(fs, &(sampler->info));
					sampler->info.mode 	   = mode;
					sampler->info.interval = interval;
				} else {
					dbg_printf("Sampler unchanged!\n");
				}

				break;
			}

			// test for end of chain
			if ( sampler->next == NULL ) {
				// end of sampler chain - insert new sampler
				sampler->next = (generic_sampler_t *)malloc(sizeof(generic_sampler_t));
				if ( !sampler->next ) {
					syslog(LOG_ERR, "Process_v9: Panic! malloc(): %s line %d: %s", __FILE__, __LINE__, strerror (errno));
					return;
				}
				sampler = sampler->next;

				sampler->info.header.type 	 = SamplerInfoRecordype;
				sampler->info.header.size 	 = sizeof(sampler_info_record_t);
				sampler->info.exporter_sysid = exporter->info.sysid;
				sampler->info.id 	   = id;
				sampler->info.mode 	   = mode;
				sampler->info.interval = interval;
				sampler->next 		   = NULL;

				FlushInfoSampler(fs, &(sampler->info));


				syslog(LOG_INFO, "Append new sampler: ID: %u, mode: %u, interval: %u\n", 
					id, mode, interval);
				dbg_printf("Append new sampler: ID: %u, mode: %u, interval: %u\n", 
					id, mode, interval);
				break;
			}

			// advance
			sampler = sampler->next;
		}

	} 
	
} // End of InsertSampler

