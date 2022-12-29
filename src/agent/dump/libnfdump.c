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
 *  $Id: nfdump.c 69 2010-09-09 07:17:43Z haag $
 *
 *  $LastChangedRevision: 69 $
 *	
 *
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "nf_common.h"
#include "rbtree.h"
#include "multi_nftree.h"
#include "nfprof.h"
#include "nflowcache.h"
#include "nfstat.h"
#include "nfexport.h"
#include "ipconv.h"
#include "util.h"
#include "flist.h"

/* hash parameters */
#define NumPrealloc 128000

#define AGGR_SIZE 7

/* Global Variables */

extern char	*FilterFilename;
extern uint32_t loopcnt;
extern extension_descriptor_t extension_descriptor[];
extern generic_exporter_t **exporter_list;

const char *nfdump_version = VERSION;
typedef void (*flow_callback_t)(master_record_t*);

typedef struct context_t {
flow_callback_t flow_callback;
int sep; // how many seconds will returning result be separated by 
uint64_t total_bytes;
uint32_t total_flows;
uint32_t skipped_blocks;
uint32_t is_anonymized;
time_t 	t_first_flow, t_last_flow;
char	Ident[IDENTLEN];
char	newIdent[IDENTLEN];
char* wfile, *record_header;
const char *print_order;
printer_t print_header, print_record;
time_t twin_start, twin_end;
int do_tag, element_stat, bidir, date_sorted, compress, do_xstat, GuessDir,
    topN, quiet, pipe_output, csv_output, flow_stat, aggregate, plain_numbers;
uint64_t limitflows;
nfprof_t profile_data;
stat_record_t sum_stat;
CompiledFilter* compiled_filter;
char *proto_name;
char *qname;
uint16_t qtype;
} Context;

int hash_hit; 
int hash_miss;
int hash_skip;
extension_map_list_t extension_map_list;
/*
 * Output Formats:
 * User defined output formats can be compiled into nfdump, for easy access
 * The format has the same syntax as describe in nfdump(1) -o fmt:<format>
 *
 * A format description consists of a single line containing arbitrary strings
 * and format specifier as described below:
 *
 * 	%ts		// Start Time - first seen
 * 	%te		// End Time	- last seen
 * 	%td		// Duration
 * 	%pr		// Protocol
 * 	%sa		// Source Address
 * 	%da		// Destination Address
 * 	%sap	// Source Address:Port
 * 	%dap	// Destination Address:Port
 * 	%sp		// Source Port
 * 	%dp		// Destination Port
 *  %nh		// Next-hop IP Address
 *  %nhb	// BGP Next-hop IP Address
 * 	%sas	// Source AS
 * 	%das	// Destination AS
 * 	%in		// Input Interface num
 * 	%out	// Output Interface num
 * 	%pkt	// Packets - default input
 * 	%ipkt	// Input Packets
 * 	%opkt	// Output Packets
 * 	%byt	// Bytes - default input
 * 	%ibyt	// Input Bytes
 * 	%obyt	// Output Bytes
 * 	%fl		// Flows
 * 	%flg	// TCP Flags
 * 	%tos	// Tos - Default src
 * 	%stos	// Src Tos
 * 	%dtos	// Dst Tos
 * 	%dir	// Direction: ingress, egress
 * 	%smk	// Src mask
 * 	%dmk	// Dst mask
 * 	%fwd	// Forwarding Status
 * 	%svln	// Src Vlan
 * 	%dvln	// Dst Vlan
 * 	%ismc	// Input Src Mac Addr
 * 	%odmc	// Output Dst Mac Addr
 * 	%idmc	// Output Src Mac Addr
 * 	%osmc	// Input Dst Mac Addr
 * 	%mpls1	// MPLS label 1
 * 	%mpls2	// MPLS label 2
 * 	%mpls3	// MPLS label 3
 * 	%mpls4	// MPLS label 4
 * 	%mpls5	// MPLS label 5
 * 	%mpls6	// MPLS label 6
 * 	%mpls7	// MPLS label 7
 * 	%mpls8	// MPLS label 8
 * 	%mpls9	// MPLS label 9
 * 	%mpls10	// MPLS label 10
 *
 * 	%bps	// bps - bits per second
 * 	%pps	// pps - packets per second
 * 	%bpp	// bps - Bytes per package
 *
 * The nfdump standard output formats line, long and extended are defined as follows:
 */

#define FORMAT_line "%ts %td %pr %sap -> %dap %pkt %byt %fl"

#define FORMAT_long "%ts %td %pr %sap -> %dap %flg %tos %pkt %byt %fl"

#define FORMAT_extended "%ts %td %pr %sap -> %dap %flg %tos %pkt %byt %pps %bps %bpp %fl"

#define FORMAT_biline "%ts %td %pr %sap <-> %dap %opkt %ipkt %obyt %ibyt %fl"

#define FORMAT_bilong "%ts %td %pr %sap <-> %dap %flg %tos %opkt %ipkt %obyt %ibyt %fl"

/* The appropriate header line is compiled automatically.
 *
 * For each defined output format a v6 long format automatically exists as well e.g.
 * line -> line6, long -> long6, extended -> extended6
 * v6 long formats need more space to print IP addresses, as IPv6 addresses are printed in full length,
 * where as in standard output format IPv6 addresses are condensed for better readability.
 * 
 * Define your own output format and compile it into nfdumnp:
 * 1. Define your output format string.
 * 2. Test the format using standard syntax -o "fmt:<your format>"
 * 3. Create a #define statement for your output format, similar than the standard output formats above.
 * 4. Add another line into the printmap[] struct below BEFORE the last NULL line for you format:
 *    { "formatname", format_special, FORMAT_definition, NULL },
 *   The first parameter is the name of your format as recognized on the command line as -o <formatname>
 *   The second parameter is always 'format_special' - the printing function.
 *   The third parameter is your format definition as defined in #define.
 *   The forth parameter is always NULL for user defined formats.
 * 5. Recompile nfdump
 */

// Assign print functions for all output options -o
// Teminated with a NULL record
printmap_t printmap[] = {
	{ "raw",		format_file_block_record,  	NULL 			},
	{ "line", 		format_special,      		FORMAT_line 	},
	{ "long", 		format_special, 			FORMAT_long 	},
	{ "extended",	format_special, 			FORMAT_extended	},
	{ "biline", 	format_special,      		FORMAT_biline 	},
	{ "bilong", 	format_special,      		FORMAT_bilong 	},
	{ "pipe", 		flow_record_to_pipe,      	NULL 			},
	{ "csv", 		flow_record_to_csv,      	NULL 			},
// add your formats here

// This is always the last line
	{ NULL,			NULL,                       NULL			}
};

#define DefaultMode "line"

// For automatic output format generation in case of custom aggregation
#define AggrPrependFmt	"%ts %td "
#define AggrAppendFmt	"%pkt %byt %bps %bpp %fl"

// compare at most 16 chars
#define MAXMODELEN	16	

/* Function Prototypes */
static void usage(char *name);

static void PrintSummary(stat_record_t *stat_record, int plain_numbers, int csv_output);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"


static void OutputAndDestroy(Context* context);
static void process_data(Context* context);
void process_flow( int argc, char **argv, flow_callback_t flow_callback );
//void * process_flow( int argc, char **argv, flow_callback_t flow_callback );


static void usage(char *name) {
		printf("usage %s [options] [\"filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-a\t\tAggregate netflow data.\n"
					"-A <expr>[/net]\tHow to aggregate: ',' sep list of tags see nfdump(1)\n"
					"\t\tor subnet aggregation: srcip4/24, srcip6/64.\n"
					"-b\t\tAggregate netflow records as bidirectional flows.\n"
					"-B\t\tAggregate netflow records as bidirectional flows - Guess direction.\n"
					"-r <file>\tread input from file\n"
					"-w <file>\twrite output to file\n"
					"-f\t\tread netflow filter from file\n"
					"-n\t\tDefine number of top N. \n"
					"-c\t\tLimit number of records to display\n"
					"-D <dns>\tUse nameserver <dns> for host lookup.\n"
					"-N\t\tPrint plain numbers\n"
					"-s <expr>[/<order>]\tGenerate statistics for <expr> any valid record element.\n"
					"\t\tand ordered by <order>: packets, bytes, flows, bps pps and bpp.\n"
					"-q\t\tQuiet: Do not print the header and bottom stat lines.\n"
					"-H Add xstat histogram data to flow file.(default 'no')\n"
					"-i <ident>\tChange Ident to <ident> in file given by -r.\n"
					"-j <file>\tCompress/Uncompress file.\n"
					"-z\t\tCompress flows in output file. Used in combination with -w.\n"
					"-l <expr>\tSet limit on packets for line and packed output format.\n"
					"\t\tkey: 32 character string or 64 digit hex string starting with 0x.\n"
					"-L <expr>\tSet limit on bytes for line and packed output format.\n"
					"-I \t\tPrint netflow summary statistics info from file, specified by -r.\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"\t\t/dir/dir1:dir2:dir3 Read the same files from '/dir/dir1' '/dir/dir2' and '/dir/dir3'.\n"
					"\t\trequests either -r filename or -R firstfile:lastfile without pathnames\n"
					"-m\t\tPrint netflow data date sorted. Only useful with -M\n"
					"-R <expr>\tRead input from sequence of files.\n"
					"\t\t/any/dir  Read all files in that directory.\n"
					"\t\t/dir/file Read all files beginning with 'file'.\n"
					"\t\t/dir/file1:file2: Read all files from 'file1' to file2.\n"
					"-o <mode>\tUse <mode> to print out netflow records:\n"
					"\t\t raw      Raw record dump.\n"
					"\t\t line     Standard output line format.\n"
					"\t\t long     Standard output line format with additional fields.\n"
					"\t\t extended Even more information.\n"
					"\t\t csv      ',' separated, machine parseable output format.\n"
					"\t\t pipe     '|' separated legacy machine parseable output format.\n"
					"\t\t\tmode may be extended by '6' for full IPv6 listing. e.g.long6, extended6.\n"
					"-E <file>\tPrint exporter ans sampling info for collected flows.\n"
          "-P <protoname>\tchose a l7 proto name.\n"
          "-Q <qname>\tDns request domain name.\n"
          "-C <qtype>\tDns request type.\n"
					"-v <file>\tverify netflow data file. Print version and blocks.\n"
					"-x <file>\tverify extension records in netflow data file.\n"
					"-X\t\tDump Filtertable and exit (debug option).\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-t <time>\ttime window for filtering packets\n"
					"\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n", name);
} /* usage */


static void PrintSummary(stat_record_t *stat_record, int plain_numbers, int csv_output) {
static double	duration;
uint64_t	bps, pps, bpp;
char 		byte_str[32], packet_str[32], bps_str[32], pps_str[32], bpp_str[32];

	bps = pps = bpp = 0;
	if ( stat_record->last_seen ) {
		duration = stat_record->last_seen - stat_record->first_seen;
		duration += ((double)stat_record->msec_last - (double)stat_record->msec_first) / 1000.0;
	} else {
		// no flows to report
		duration = 0;
	}
	if ( duration > 0 && stat_record->last_seen > 0 ) {
		bps = ( stat_record->numbytes << 3 ) / duration;	// bits per second. ( >> 3 ) -> * 8 to convert octets into bits
		pps = stat_record->numpackets / duration;			// packets per second
		bpp = stat_record->numpackets ? stat_record->numbytes / stat_record->numpackets : 0;    // Bytes per Packet
	}
	if ( csv_output ) {
		printf("Summary\n");
		printf("flows,bytes,packets,avg_bps,avg_pps,avg_bpp\n");
		printf("%llu,%llu,%llu,%llu,%llu,%llu\n",
			(long long unsigned)stat_record->numflows, (long long unsigned)stat_record->numbytes, 
			(long long unsigned)stat_record->numpackets, (long long unsigned)bps, 
			(long long unsigned)pps, (long long unsigned)bpp );
	} else if ( plain_numbers ) {
		printf("Summary: total flows: %llu, total bytes: %llu, total packets: %llu, avg bps: %llu, avg pps: %llu, avg bpp: %llu\n",
			(long long unsigned)stat_record->numflows, (long long unsigned)stat_record->numbytes, 
			(long long unsigned)stat_record->numpackets, (long long unsigned)bps, 
			(long long unsigned)pps, (long long unsigned)bpp );
	} else {
		format_number(stat_record->numbytes, byte_str, VAR_LENGTH);
		format_number(stat_record->numpackets, packet_str, VAR_LENGTH);
		format_number(bps, bps_str, VAR_LENGTH);
		format_number(pps, pps_str, VAR_LENGTH);
		format_number(bpp, bpp_str, VAR_LENGTH);
		printf("Summary: total flows: %llu, total bytes: %s, total packets: %s, avg bps: %s, avg pps: %s, avg bpp: %s\n",
		(unsigned long long)stat_record->numflows, byte_str, packet_str, bps_str, pps_str, bpp_str );
	}

} // End of PrintSummary

void process_data(Context *context)
{
common_record_t 	*flow_record;
master_record_t		*master_record;
nffile_t			*nffile_w, *nffile_r;
xstat_t				*xstat;
stat_record_t 		*stat_record = &context->sum_stat;
int 				done, write_file;

int flow_stat = context->aggregate || context->flow_stat;
uint64_t limitflows = context->limitflows;
int sort_flows = context->print_order != NULL;

#ifdef COMPAT15
int	v1_map_done = 0;
#endif

// added by lxh start
printer_t tmp_print_record = context->print_record;
// added by lxh end

	// time window of all matched flows
	memset((void *)stat_record, 0, sizeof(stat_record_t));
	stat_record->first_seen = 0x7fffffff;
	stat_record->msec_first = 999;

	// Do the logic first

	// print flows later, when all records are processed and sorted
	// flow limits apply at that time
	if ( sort_flows ) {
// moded by lxh start
		//print_record = NULL;
		tmp_print_record = NULL;
// moded by lxh end
		limitflows   = 0;
	}

	// do not print flows when doing any stats
	if ( flow_stat || context->element_stat ) {
// moded by lxh start
		//print_record = NULL;
		tmp_print_record = NULL;
// moded by lxh end
		limitflows   = 0;
	}

	// do not write flows to file, when doing any stats
	// -w may apply for flow_stats later
	write_file = !(sort_flows || flow_stat || context->element_stat) && context->wfile;
	nffile_r = NULL;
	nffile_w = NULL;
	xstat  	 = NULL;

	// Get the first file handle
	nffile_r = GetNextFile(NULL, context->twin_start, context->twin_end);
	if ( !nffile_r ) {
		LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return;
	}
	if ( nffile_r == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return;
	}

	// preset time window of all processed flows to the stat record in first flow file
	context->t_first_flow = nffile_r->stat_record->first_seen;
	context->t_last_flow  = nffile_r->stat_record->last_seen;

	// store infos away for later use
	// although multiple files may be processed, it is assumed that all 
	// have the same settings
	context->is_anonymized = IP_ANONYMIZED(nffile_r);
	strncpy(context->Ident, nffile_r->file_header->ident, IDENTLEN);
	context->Ident[IDENTLEN-1] = '\0';

	// prepare output file if requested
	if ( write_file ) {
		nffile_w = OpenNewFile(context->wfile, NULL, context->compress, IP_ANONYMIZED(nffile_r), NULL );
		if ( !nffile_w ) {
			if ( nffile_r ) {
				CloseFile(nffile_r);
				DisposeFile(nffile_r);
			}
			return;
		}
		if ( context->do_xstat ) {
			xstat = InitXStat(nffile_w);
			if ( !xstat ) {
				if ( nffile_r ) {
					CloseFile(nffile_r);
					DisposeFile(nffile_r);
				}
				return;
			}
		}
	}

  //when qname and qtype and lpn is set, if lpn is not dns, then return
  /*if (context->proto_name && (context->qname || context->qtype)) {
    if (strcmp(context->proto_name, "dns"))
      return;
  }*/
  

	// setup Filter Engine to point to master_record, as any record read from file
	// is expanded into this record
	// Engine->nfrecord = (uint64_t *)master_record;

	done = 0;
	while ( !done ) {
	int i, ret;

		// get next data block from file
		ret = ReadBlock(nffile_r);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					LogError("Skip corrupt data file '%s'\n",GetCurrentFilename());
				else 
					LogError("Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF: {
				nffile_t *next = GetNextFile(nffile_r, context->twin_start, context->twin_end);
				if ( next == EMPTY_LIST ) {
					done = 1;
				} else if ( next == NULL ) {
					done = 1;
					LogError("Unexpected end of file list\n");
				} else {
					// Update global time span window
					if ( next->stat_record->first_seen < context->t_first_flow )
						context->t_first_flow = next->stat_record->first_seen;
					if ( next->stat_record->last_seen > context->t_last_flow ) 
						context->t_last_flow = next->stat_record->last_seen;
					// continue with next file
// add by lxh begin
    {
      static int kk;
      kk++;
      if (kk == context->sep / 300)
      {
        kk=0;
        OutputAndDestroy(context);
      }
    }
// add by lxh end
				}
				continue;

				} break; // not really needed
			default:
				// successfully read block
				context->total_bytes += ret;
		}


#ifdef COMPAT15
		if ( nffile_r->block_header->id == DATA_BLOCK_TYPE_1 ) {
			common_record_v1_t *v1_record = (common_record_v1_t *)nffile_r->buff_ptr;
			// create an extension map for v1 blocks
			if ( v1_map_done == 0 ) {
				extension_map_t *map = malloc(sizeof(extension_map_t) + 2 * sizeof(uint16_t) );
				if ( ! map ) {
					LogError("malloc() allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
					exit(255);
				}
				map->type 	= ExtensionMapType;
				map->size 	= sizeof(extension_map_t) + 2 * sizeof(uint16_t);
				if (( map->size & 0x3 ) != 0 ) {
					map->size += 4 - ( map->size & 0x3 );
				}

				map->map_id = INIT_ID;

				map->ex_id[0]  = EX_IO_SNMP_2;
				map->ex_id[1]  = EX_AS_2;
				map->ex_id[2]  = 0;
				
				map->extension_size  = 0;
				map->extension_size += extension_descriptor[EX_IO_SNMP_2].size;
				map->extension_size += extension_descriptor[EX_AS_2].size;

				if ( Insert_Extension_Map(&extension_map_list,map) && write_file ) {
					// flush new map
					AppendToBuffer(nffile_w, (void *)map, map->size);
				} // else map already known and flushed

				v1_map_done = 1;
			}

			// convert the records to v2
			for ( i=0; i < nffile_r->block_header->NumRecords; i++ ) {
				common_record_t *v2_record = (common_record_t *)v1_record;
				Convert_v1_to_v2((void *)v1_record);
				// now we have a v2 record -> use size of v2_record->size
				v1_record = (common_record_v1_t *)((pointer_addr_t)v1_record + v2_record->size);
			}
			nffile_r->block_header->id = DATA_BLOCK_TYPE_2;
		}
#endif

		if ( nffile_r->block_header->id == Large_BLOCK_Type ) {
			// skip
			printf("Xstat block skipped ...\n");
			continue;
		}

		if ( nffile_r->block_header->id != DATA_BLOCK_TYPE_2 ) {
			if ( nffile_r->block_header->id == DATA_BLOCK_TYPE_1 ) {
				LogError("Can't process nfdump 1.5.x block type 1. Add --enable-compat15 to compile compatibility code. Skip block.\n");
			} else {
				LogError("Can't process block type %u. Skip block.\n", nffile_r->block_header->id);
			}
			context->skipped_blocks++;
			continue;
		}

// moded by lxh start
		flow_record = (common_record_t*)nffile_r->buff_ptr;
// moded by lxh end
		for ( i=0; i < nffile_r->block_header->NumRecords; i++ ) {

			switch ( flow_record->type ) {
				case CommonRecordType:  {
					int match;
					uint32_t map_id = flow_record->ext_map;
					generic_exporter_t *exp_info = exporter_list[flow_record->exporter_sysid];
					if ( map_id >= MAX_EXTENSION_MAPS ) {
						LogError("Corrupt data file. Extension map id %u too big.\n", flow_record->ext_map);
						exit(255);
					}
					if ( extension_map_list.slot[map_id] == NULL ) {
						LogError("Corrupt data file. Missing extension map %u. Skip record.\n", flow_record->ext_map);
						flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
						continue;
					} 

					context->total_flows++;
					master_record = &(extension_map_list.slot[map_id]->master_record);
					ExpandRecord_v2( flow_record, extension_map_list.slot[map_id], 
						exp_info ? &(exp_info->info) : NULL, master_record);

					// Time based filter
					// if no time filter is given, the result is always true
					match  = context->twin_start && (master_record->first < context->twin_start || master_record->last > context->twin_end) ? 0 : 1;
					match &= limitflows ? stat_record->numflows < limitflows : 1;

					// filter netflow record with user supplied filter
					if ( match ) 
						match = context->compiled_filter->Match(master_record);
	
					if ( match == 0 ) { // record failed to pass all filters
						// increment pointer by number of bytes for netflow record
						flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
						// go to next record
						continue;
					}

					// Records passed filter -> continue record processing
					// Update statistics
					UpdateStat(stat_record, master_record);

					// update number of flows matching a given map
					extension_map_list.slot[map_id]->ref_count++;
	
					if ( flow_stat ) {
						AddFlow(flow_record, master_record);
						if ( context->element_stat ) {
							AddStat(flow_record, master_record);
						} 
					} else if ( context->element_stat ) {
						AddStat(flow_record, master_record);
					} else if ( sort_flows ) {
						InsertFlow(flow_record, master_record);
					} else {
						if ( write_file ) {
							AppendToBuffer(nffile_w, (void *)flow_record, flow_record->size);
							if ( xstat ) 
								UpdateXStat(xstat, master_record);
// modified by lxh start
						//} else if ( print_record ) {
						} else if ( tmp_print_record ) {
							char *string = NULL;
							// if we need to print out this record
//							print_record(master_record, &string, tag);
//							tmp_print_record(master_record, &string, context->do_tag);
// modified by lxh end
							if ( string ) {
								if ( limitflows ) {
									if ( (stat_record->numflows <= limitflows) )
										printf("%s\n", string);
								} else 
									printf("%s\n", string);
							}
						} else { 
							// mutually exclusive conditions should prevent executing this code
							// this is buggy!
							printf("Bug! - this code should never get executed in file %s line %d\n", __FILE__, __LINE__);
						}
					} // sort_flows - else

// added by lxh start
                    if (context->flow_callback) context->flow_callback(master_record);
// added by lxh end
					} break; 
				case ExtensionMapType: {
					extension_map_t *map = (extension_map_t *)flow_record;
	
					if ( Insert_Extension_Map(&extension_map_list, map) && write_file ) {
						// flush new map
						AppendToBuffer(nffile_w, (void *)map, map->size);
					} // else map already known and flushed
					} break;
				case ExporterRecordType:
				case SamplerRecordype:
						// Silently skip exporter records
					break;
				case ExporterInfoRecordType: {
					int ret = AddExporterInfo((exporter_info_record_t *)flow_record);
					if ( ret != 0 ) {
						if ( write_file && ret == 1 ) 
							AppendToBuffer(nffile_w, (void *)flow_record, flow_record->size);
					} else {
						LogError("Failed to add Exporter Record\n");
					}
					} break;
				case ExporterStatRecordType:
					AddExporterStat((exporter_stats_record_t *)flow_record);
					break;
				case SamplerInfoRecordype: {
					int ret = AddSamplerInfo((sampler_info_record_t *)flow_record);
					if ( ret != 0 ) {
						if ( write_file && ret == 1 ) 
							AppendToBuffer(nffile_w, (void *)flow_record, flow_record->size);
					} else {
						LogError("Failed to add Sampler Record\n");
					}
					} break;
				default: {
					LogError("Skip unknown record type %i\n", flow_record->type);
				}
			}

		// Advance pointer by number of bytes for netflow record
		flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	


		} // for all records

		// check if we are done, due to -c option 
		if ( limitflows ) 
			done = stat_record->numflows >= limitflows;

	} // while

	CloseFile(nffile_r);

	// flush output file
	if ( write_file ) {
		// flush current buffer to disc
		if ( nffile_w->block_header->NumRecords ) {
			if ( WriteBlock(nffile_w) <= 0 ) {
				LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
			} 
		}

		if ( xstat ) {
			if ( WriteExtraBlock(nffile_w, xstat->block_header ) <= 0 ) {
				LogError("Failed to write xstat buffer to disk: '%s'" , strerror(errno));
			} 
		}

		/* Stat info */
		if ( write_file ) {
			/* Copy stat info and close file */
			memcpy((void *)nffile_w->stat_record, (void *)&stat_record, sizeof(stat_record_t));
			CloseUpdateFile(nffile_w, nffile_r->file_header->ident );
			nffile_w = DisposeFile(nffile_w);
		} // else stdout
	}	 

	PackExtensionMapList(&extension_map_list);

	DisposeFile(nffile_r);
// deled by lxh start
//	return stat_record;
// deled by lxh end
} // End of process_data


void process_flow( int argc, char **argv, flow_callback_t flow_callback ) {
//void * process_flow( int argc, char **argv, flow_callback_t flow_callback ) {
struct stat stat_buff;
char 		*rfile, *Rfile, *Mdirs, *ffile, *filter, *tstring, *stat_type;
char		*byte_limit_string, *packet_limit_string, *print_format;
char		*query_file, *UnCompress_file, *nameserver, *aggr_fmt;
int 		c, ffd, ret, fdump;
int 		i, user_format, aggregate_mask;
int 		print_stat, syntax_only;
uint16_t	Aggregate_Bits;
uint64_t	AggregateMasks[AGGR_SIZE];

    Context* context = (Context*)malloc(sizeof(Context));
    memset(context, 0, sizeof(Context));
    if (flow_callback) context->flow_callback = (void (*)(master_record_t*))flow_callback;
	rfile = Rfile = Mdirs = context->wfile = ffile = filter = tstring = stat_type = NULL;
	byte_limit_string = packet_limit_string = NULL;
	fdump = context->aggregate = 0;
	aggregate_mask	= 0;
	context->bidir		= 0;
	context->twin_start = context->twin_end = 0;
	syntax_only	    = 0;
	context->topN	= 10;
	context->flow_stat		= 0;
	print_stat    			= 0;
	context->element_stat  	= 0;
	context->do_xstat 		= 0;
	context->limitflows		= 0;
	context->date_sorted	= 0;
	context->total_bytes	= 0;
	context->total_flows	= 0;
	context->skipped_blocks	= 0;
	context->do_tag			= 0;
	context->quiet			= 0;
	user_format		= 0;
	context->compress		= 0;
	context->plain_numbers	= 0;
	context->pipe_output	= 0;
	context->csv_output		= 0;
	context->is_anonymized	= 0;
	context->GuessDir		= 0;
	nameserver		= NULL;

	print_format    = NULL;
	context->print_header 	= NULL;
	context->print_record  	= NULL;
	context->print_order  	= NULL;
	query_file		= NULL;
	UnCompress_file	= NULL;
	aggr_fmt		= NULL;
	context->record_header 	= NULL;
	Aggregate_Bits	= 0xFFFF;	// set all bits

  context->proto_name = NULL;
  context->qname = NULL;
  context->qtype = 0;

	context->newIdent[0] = '\0';
    hash_hit = 0;
    hash_miss = 0;
    hash_skip = 0;
    context->sep = 0;

	for ( i=0; i<AGGR_SIZE; AggregateMasks[i++] = 0 ) ;

	while ((c = getopt(argc, argv, "6aA:p:Bbc:D:E:s:hHn:i:j:f:qzr:v:w:K:M:NImO:R:XZt:TVv:x:l:L:o:P:Q:C:")) != EOF) {
		switch (c) {
      case 'p':
        context->sep = atoi(optarg);
        context->sep -= context->sep % 300;
        if (context->sep<0) context->sep=0;
        break;
      //add for l7 proto args
      case 'P':
        context->proto_name = optarg;
        break;
      //add for dns qname
      case 'Q':
        context->qname = optarg;
        break;
      //add for dns qtype
      case 'C':
        context->qtype = atoi(optarg);
        break;
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'a':
				context->aggregate = 1;
				break;
			case 'A':
				if ( !ParseAggregateMask(optarg, &aggr_fmt ) ) {
					exit(255);
				}
				aggregate_mask = 1;
				break;
			case 'B':
				context->GuessDir = 1;
			case 'b':
				if ( !SetBidirAggregation() ) {
					exit(255);
				}
				context->bidir	  = 1;
				// implies
				context->aggregate = 1;
				break;
			case 'D':
				nameserver = optarg;
				if ( !set_nameserver(nameserver) ) {
					exit(255);
				}
				break;
			case 'E':
				query_file = optarg;
				if ( !InitExporterList() ) {
					exit(255);
				}
				PrintExporters(query_file);
				exit(0);
				break;
			case 'X':
				fdump = 1;
				break;
			case 'Z':
				syntax_only = 1;
				break;
			case 'q':
				context->quiet = 1;
				break;
			case 'z':
				context->compress = 1;
				break;
			case 'c':	
				context->limitflows = atoi(optarg);
				if ( !context->limitflows ) {
					LogError("Option -c needs a number > 0\n");
					exit(255);
				}
				break;
			case 's':
				stat_type = optarg;
                if ( !SetStat(stat_type, &context->element_stat, &context->flow_stat) ) {
                    exit(255);
                } 
				break;
			case 'V':
				printf("%s: Version: %s\n",argv[0], nfdump_version);
				exit(0);
				break;
			case 'l':
				packet_limit_string = optarg;
				break;
			case 'K':
				LogError("*** Anonymisation moved! Use nfanon to anonymise flows!\n");
				exit(255);
				break;
			case 'H':
				context->do_xstat = 1;
				break;
			case 'L':
				byte_limit_string = optarg;
				break;
			case 'N':
				context->plain_numbers = 1;
				break;
			case 'f':
				ffile = optarg;
				break;
			case 't':
				tstring = optarg;
				break;
			case 'r':
				rfile = optarg;
				if ( strcmp(rfile, "-") == 0 )
					rfile = NULL;
				break;
			case 'm':
				context->print_order = "tstart";
				Parse_PrintOrder(context->print_order);
				context->date_sorted = 1;
				LogError("Option -m depricated. Use '-O tstart' instead\n");
				break;
			case 'M':
				Mdirs = optarg;
				break;
			case 'I':
				print_stat++;
				break;
			case 'o':	// output mode
				print_format = optarg;
				break;
			case 'O': {	// stat order by
				int ret;
				context->print_order = optarg;
				ret = Parse_PrintOrder(context->print_order);
				if ( ret < 0 ) {
					LogError("Unknown print order '%s'\n", context->print_order);
					exit(255);
				}
				context->date_sorted = ret == 6;		// index into order_mode
				} break;
			case 'R':
				Rfile = optarg;
				break;
			case 'w':
				context->wfile = optarg;
				break;
			case 'n':
				context->topN = atoi(optarg);
				if ( context->topN < 0 ) {
					LogError("TopnN number %i out of range\n", context->topN);
					exit(255);
				}
				break;
			case 'T':
				context->do_tag = 1;
				break;
			case 'i':
				strncpy(context->newIdent, optarg, IDENT_SIZE);
				context->newIdent[IDENT_SIZE - 1] = 0;
				if ( strchr(context->newIdent, ' ') ) {
					LogError("Ident must not contain spaces\n");
					exit(255);
				}
				break;
			case 'j':
				UnCompress_file = optarg;
				UnCompressFile(UnCompress_file);
				exit(0);
				break;
			case 'x':
				query_file = optarg;
				InitExtensionMaps(NULL);
				DumpExMaps(query_file);
				exit(0);
				break;
			case 'v':
				query_file = optarg;
				QueryFile(query_file);
				exit(0);
				break;
			case '6':	// print long IPv6 addr
				Setv6Mode(1);
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}
	if (argc - optind > 1) {
		usage(argv[0]);
		exit(255);
	} else {
		/* user specified a pcap filter */
		filter = argv[optind];
		FilterFilename = NULL;
	}
	
	// Change Ident only
	if ( rfile && strlen(context->newIdent) > 0 ) {
		ChangeIdent(rfile, context->newIdent);
		exit(0);
	}

	if ( (context->element_stat && !context->flow_stat) && aggregate_mask ) {
		LogError("Warning: Aggregation ignored for element statistics\n");
		aggregate_mask = 0;
	}

	if ( !context->flow_stat && aggregate_mask ) {
		context->aggregate = 1;
	}

	if ( rfile && Rfile ) {
		LogError("-r and -R are mutually exclusive. Plase specify either -r or -R\n");
		exit(255);
	}
	if ( Mdirs && !(rfile || Rfile) ) {
		LogError("-M needs either -r or -R to specify the file or file list. Add '-R .' for all files in the directories.\n");
		exit(255);
	}

	InitExtensionMaps(&extension_map_list);
	if ( !InitExporterList() ) {
		exit(255);
	}

	SetupInputFileSequence(Mdirs, rfile, Rfile);

	if ( print_stat ) {
		nffile_t *nffile;
		if ( !rfile && !Rfile && !Mdirs) {
			LogError("Expect data file(s).\n");
			exit(255);
		}

		memset(&context->sum_stat, 0, sizeof(stat_record_t));
		context->sum_stat.first_seen = 0x7fffffff;
		context->sum_stat.msec_first = 999;
		nffile = GetNextFile(NULL, 0, 0);
		if ( !nffile ) {
			LogError("Error open file: %s\n", strerror(errno));
			exit(250);
		}
		while ( nffile && nffile != EMPTY_LIST ) {
			SumStatRecords(&context->sum_stat, nffile->stat_record);
			nffile = GetNextFile(nffile, 0, 0);
		}
		PrintStat(&context->sum_stat);
		exit(0);
	}

	// handle print mode
	if ( !print_format ) {
		// automatically select an appropriate output format for custom aggregation
		// aggr_fmt is compiled by ParseAggregateMask
		if ( aggr_fmt ) {
			int len = strlen(AggrPrependFmt) + strlen(aggr_fmt) + strlen(AggrAppendFmt) + 7;	// +7 for 'fmt:', 2 spaces and '\0'
			print_format = (char*)malloc(len);
			if ( !print_format ) {
				LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
				exit(255);
			}
			snprintf(print_format, len, "fmt:%s %s %s",AggrPrependFmt, aggr_fmt, AggrAppendFmt );
			print_format[len-1] = '\0';
		} else if ( context->bidir ) {
			print_format = "biline";
		} else
			print_format = DefaultMode;
	}

	if ( strncasecmp(print_format, "fmt:", 4) == 0 ) {
		// special user defined output format
		char *format = &print_format[4];
		if ( strlen(format) ) {
			if ( !ParseOutputFormat(format, context->plain_numbers, printmap) )
				exit(255);
			context->print_record  = format_special;
			context->record_header = get_record_header();
			user_format	  = 1;
		} else {
			LogError("Missing format description for user defined output format!\n");
			exit(255);
		}
	} else {
		// predefined output format

		// Check for long_v6 mode
		i = strlen(print_format);
		if ( i > 2 ) {
			if ( print_format[i-1] == '6' ) {
				Setv6Mode(1);
				print_format[i-1] = '\0';
			} else 
				Setv6Mode(0);
		}

		i = 0;
		while ( printmap[i].printmode ) {
			if ( strncasecmp(print_format, printmap[i].printmode, MAXMODELEN) == 0 ) {
				if ( printmap[i].Format ) {
					if ( !ParseOutputFormat(printmap[i].Format, context->plain_numbers, printmap) )
						exit(255);
					// predefined custom format
					context->print_record  = printmap[i].func;
					context->record_header = get_record_header();
					user_format	  = 1;
				} else {
					// To support the pipe output format for element stats - check for pipe, and remember this
					if ( strncasecmp(print_format, "pipe", MAXMODELEN) == 0 ) {
						context->pipe_output = 1;
					}
					if ( strncasecmp(print_format, "csv", MAXMODELEN) == 0 ) {
						context->csv_output = 1;
						set_record_header();
						context->record_header = get_record_header();
					}
					// predefined static format
					context->print_record  = printmap[i].func;
					user_format	  = 0;
				}
				break;
			}
			i++;
		}
	}

	if ( !context->print_record ) {
		LogError("Unknown output mode '%s'\n", print_format);
		exit(255);
	}

	// this is the only case, where headers are printed.
	if ( strncasecmp(print_format, "raw", 16) == 0 )
		context->print_header = format_file_block_header;
	
	if ( context->aggregate && (context->flow_stat || context->element_stat) ) {
		context->aggregate = 0;
		LogError("Command line switch -s overwrites -a\n");
	}

	if ( !filter && ffile ) {
		if ( stat(ffile, &stat_buff) ) {
			LogError("Can't stat filter file '%s': %s\n", ffile, strerror(errno));
			exit(255);
		}
		filter = (char *)malloc(stat_buff.st_size+1);
		if ( !filter ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
		ffd = open(ffile, O_RDONLY);
		if ( ffd < 0 ) {
			LogError("Can't open filter file '%s': %s\n", ffile, strerror(errno));
			exit(255);
		}
		ret = read(ffd, (void *)filter, stat_buff.st_size);
		if ( ret < 0   ) {
			perror("Error reading filter file");
			close(ffd);
			exit(255);
		}
		context->total_bytes += ret;
		filter[stat_buff.st_size] = 0;
		close(ffd);

		FilterFilename = ffile;
	}

	// if no filter is given, set the default ip filter which passes through every flow
	if ( !filter  || strlen(filter) == 0 ) 
		filter = "any";

  context->compiled_filter = CompiledFilter::Compile(filter);
	if (!context->compiled_filter)
		exit(254);

	if ( fdump ) {
		context->compiled_filter->DumpList();
		exit(0);
	}

	if ( syntax_only )
		exit(0);

	if ( context->print_order && context->flow_stat ) {
		printf("-s record and -m are mutually exclusive options\n");
		exit(255);
	}

	if ((context->aggregate || context->flow_stat || context->print_order)  && !Init_FlowTable() )
			exit(250);

	if (context->element_stat && !Init_StatTable(HashBits, NumPrealloc) )
			exit(250);

	SetLimits(context->element_stat || context->aggregate || context->flow_stat, packet_limit_string, byte_limit_string);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &context->twin_start, &context->twin_end) )
			exit(255);
	}


	if ( !(context->flow_stat || context->element_stat || context->wfile || context->quiet ) && context->record_header ) {
		if ( user_format ) {
//			printf("%s\n", context->record_header);
		} else {
			// static format - no static format with header any more, but keep code anyway
			if ( Getv6Mode() ) {
//				printf("%s\n", context->record_header);
			} else {
//				printf("%s\n", context->record_header);
            }
		}
	}

	nfprof_start(&context->profile_data);
	process_data(context);
	nfprof_end(&context->profile_data, context->total_flows);

	if ( context->total_bytes == 0 ) {
		printf("No matched flows\n");
		exit(0);
	}
    OutputAndDestroy(context);

	FreeExtensionMaps(&extension_map_list);
#ifdef DEVEL
//	if ( hash_hit || hash_miss )
//		printf("Hash hit: %i, miss: %i, skip: %i, ratio: %5.3f\n", hash_hit, hash_miss, hash_skip, (float)hash_hit/((float)(hash_hit+hash_miss)));
#endif

  free(context);
    //return context;
}

// moded by lxh start
static void OutputAndDestroy(Context* context) {
  
    nfprof_end(&context->profile_data, context->total_flows);

	if (context->aggregate || context->print_order) {
		if ( context->wfile ) {
			nffile_t *nffile = OpenNewFile(context->wfile, NULL, context->compress, context->is_anonymized, NULL);
			if ( !nffile ) 
				exit(255);
			if ( ExportFlowTable(nffile, context->aggregate, context->bidir, context->date_sorted) ) {
				CloseUpdateFile(nffile, context->newIdent );	
			} else {
				CloseFile(nffile);
				unlink(context->wfile);
			}
			DisposeFile(nffile);
		} else {
//			PrintFlowTable(context->print_record, context->limitflows, context->do_tag, context->GuessDir);
		}
	}

	if (context->flow_stat) {
//		PrintFlowStat(context->record_header, context->print_record, context->topN, context->do_tag, context->quiet, context->csv_output);
#ifdef DEVEL
//		printf("Loopcnt: %u\n", loopcnt);
#endif
	} 

	if (context->element_stat) {
//		PrintElementStat(&context->sum_stat, context->record_header, context->print_record, context->topN, context->do_tag, context->quiet, context->pipe_output, context->csv_output);
	} 

	if ( !context->quiet ) {
		if ( context->csv_output ) {
//			PrintSummary(&context->sum_stat, context->plain_numbers, context->csv_output);
		} else if ( !context->wfile ) {
			if (context->is_anonymized) {
//				printf("IP addresses anonymised\n");
            }
//			PrintSummary(&context->sum_stat, context->plain_numbers, context->csv_output);
			if ( context->t_last_flow == 0 ) {
				// in case of a pre 1.6.6 collected and empty flow file
//				printf("Time window: <unknown>\n");
			} else {
// 				printf("Time window: %s\n", TimeString(context->t_first_flow, context->t_last_flow));
			}
//			printf("Total flows processed: %u, Blocks skipped: %u, Bytes read: %llu\n", 
//				context->total_flows, context->skipped_blocks, (unsigned long long)context->total_bytes);
//            printf("\n");
//			nfprof_print(&context->profile_data, stdout);
		}
	}

	Dispose_FlowTable();
	Dispose_StatTable();
  context->skipped_blocks = 0;
  context->total_flows = 0;
  context->total_bytes = 0;
  context->t_first_flow = 0x7fffffff;
  context->t_last_flow = 0;
	memset((void *)&context->sum_stat, 0, sizeof(stat_record_t));
	context->sum_stat.first_seen = 0x7fffffff;
	context->sum_stat.msec_first = 999;
    
	if ((context->aggregate || context->flow_stat || context->print_order)  && !Init_FlowTable() )
			exit(250);

	if (context->element_stat && !Init_StatTable(HashBits, NumPrealloc) )
			exit(250);

    nfprof_start(&context->profile_data);
}
// moded by lxh end
