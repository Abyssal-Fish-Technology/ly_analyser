/*
 *  nfreplay :  Reads netflow data from files saved by nfcapd
 *  			and sends them to another host.
 *
 *  Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *	 this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *	 this list of conditions and the following disclaimer in the documentation 
 *	 and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *	 used to endorse or promote products derived from this software without 
 *	 specific prior written permission.
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
 *  $Id: nftrack.c 8 2009-05-07 08:13:13Z haag $
 *
 *  $LastChangedRevision: 8 $
 *	
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nf_common.h"
#include "nffile.h"
#include "flist.h"
#include "rbtree.h"
#include "nftree.h"
#include "nfdump.h"
#include "nfx.h"
#include "util.h"
#include "grammar.h"

#include "nftrack_stat.h"
#include "nftrack_rrd.h"

// We have 288 slot ( 1 day ) for stat record
#define AVG_STAT 1

/* Externals */
extern int yydebug;

/* Global Variables */
FilterEngine_data_t	*Engine;
int 		byte_mode, packet_mode;
uint32_t	byte_limit, packet_limit;	// needed for linking purpose only

extension_map_list_t extension_map_list;

/* Local Variables */
static const char *nfdump_version = VERSION;

/* Function Prototypes */
static void usage(char *name);

static data_row *process(char *filter);

/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
		printf("usage %s [options] [\"filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-l\t\tLast update of Ports DB\n"
					"-V\t\tPrint version and exit.\n"
					"-I\t\tInitialize Ports DB files.\n"
					"-d <db_dir>\tPorts DB directory.\n"
					"-r <input>\tread from file. default: stdin\n"
					"-p\t\tOnline output mode.\n"
					"-s\t\tCreate port statistics for timeslot -t\n"
					"-t <time>\tTimeslot for statistics\n"
					"-S\t\tCreate port statistics for last day\n"
					"-w <file>\twrite output to file\n"
					"-f <filter>\tfilter syntaxfile\n"
					, name);
} /* usage */

static data_row *process(char *filter) {
master_record_t		master_record;
common_record_t		*flow_record;
nffile_t	*nffile;
int i, done, ret;
data_row * 	port_table;
uint64_t total_bytes; 

	nffile = GetNextFile(NULL, 0, 0);
	if ( !nffile ) {
		LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return NULL;
	}
	if ( nffile == EMPTY_LIST ) {
		LogError("Empty file list. No files to process\n");
		return NULL;
	}

	port_table    = (data_row *)calloc(65536, sizeof(data_row));
    if ( !port_table) {
		LogError("malloc() allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
        return NULL;
    }

    memset((void *)port_table, 0, 65536 * sizeof(data_row));

	// setup Filter Engine to point to master_record, as any record read from file
	// is expanded into this record
	Engine->nfrecord = (uint64_t *)&master_record;

	done	 	= 0;
	while ( !done ) {

		// get next data block from file
		ret = ReadBlock(nffile);

        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if ( ret == NF_CORRUPT ) 
                    fprintf(stderr, "Skip corrupt data file '%s'\n",GetCurrentFilename());
                else 
                    fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
                // fall through - get next file in chain
            case NF_EOF: {
				nffile_t *next = GetNextFile(nffile, 0, 0);
				if ( next == EMPTY_LIST ) {
					done = 1;
				}
				if ( next == NULL ) {
					done = 1;
					LogError("Unexpected end of file list\n");
				}
				// else continue with next file
				continue;

                } break; // not really needed
            default:
                // successfully read block
                total_bytes += ret;
        }

		if ( nffile->block_header->id == Large_BLOCK_Type ) {
			// skip
			continue;
		}

		if ( nffile->block_header->id != DATA_BLOCK_TYPE_2 ) {
			fprintf(stderr, "Can't process block type %u\n", nffile->block_header->id);
			continue;
		}

		flow_record = nffile->buff_ptr;

		for ( i=0; i < nffile->block_header->NumRecords; i++ ) {
			int			ret;

            if ( flow_record->type == CommonRecordType ) {
                if ( extension_map_list.slot[flow_record->ext_map] == NULL ) {
                    LogError("Corrupt data file! No such extension map id: %u. Skip record", flow_record->ext_map );
                } else {
                    ExpandRecord_v2( flow_record, extension_map_list.slot[flow_record->ext_map], NULL, &master_record);
            
   					ret = (*Engine->FilterEngine)(Engine);

					if ( ret == 0 ) { // record failed to pass the filter
						// increment pointer by number of bytes for netflow record
						flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
						// go to next record
						continue;
					}


					// Add to stat record
					if ( master_record.prot == 6 ) {
						port_table[master_record.dstport].proto[tcp].type[flows]++;
						port_table[master_record.dstport].proto[tcp].type[packets]	+= master_record.dPkts;
						port_table[master_record.dstport].proto[tcp].type[bytes]	+= master_record.dOctets;
					} else if ( master_record.prot == 17 ) {
						port_table[master_record.dstport].proto[udp].type[flows]++;
						port_table[master_record.dstport].proto[udp].type[packets]	+= master_record.dPkts;
						port_table[master_record.dstport].proto[udp].type[bytes]	+= master_record.dOctets;
					}
             	}

            } else if ( flow_record->type == ExtensionMapType ) {
                extension_map_t *map = (extension_map_t *)flow_record;

                if ( Insert_Extension_Map(&extension_map_list, map) ) {
                     // flush new map
                } // else map already known and flushed

            } else {
                fprintf(stderr, "Skip unknown record type %i\n", flow_record->type);
            }

			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
		}
	} // while

	CloseFile(nffile);
	DisposeFile(nffile);

	return port_table;

} // End of process


int main( int argc, char **argv ) {
struct stat stat_buff;
char c, *wfile, *rfile, *Rfile, *Mdirs, *ffile, *filter, *timeslot, *DBdir;
char datestr[64];
int ffd, ret, DBinit, AddDB, GenStat, AvStat, output_mode;
unsigned int lastupdate, topN;
data_row *port_table;
time_t	when;
struct tm * t1;

	wfile = rfile = Rfile = Mdirs = ffile = filter = DBdir = timeslot = NULL;
	DBinit = AddDB = GenStat = AvStat = 0;
	lastupdate = output_mode = 0;
	topN = 10;
	while ((c = getopt(argc, argv, "d:hln:pr:st:w:AIM:L:R:SV")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'I':
				DBinit = 1;
				break;
			case 'M':
				Mdirs = strdup(optarg);
				break;
			case 'R':
				Rfile = strdup(optarg);
				break;
			case 'd':
				DBdir = strdup(optarg);
				ret  = stat(DBdir, &stat_buff);
				if ( !(stat_buff.st_mode & S_IFDIR) ) {
					fprintf(stderr, "No such directory: %s\n", DBdir);
					exit(255);
				}
				break;
			case 'l':
				lastupdate = 1;
				break;
			case 'n':
				topN = atoi(optarg);
				if ( topN < 0 ) {
					fprintf(stderr, "TopnN number %i out of range\n", topN);
					exit(255);
				}
				break;
			case 'p':
				output_mode = 1;
				break;
			case 'r':
				rfile = strdup(optarg);
				break;
			case 'w':
				wfile = strdup(optarg);
				break;
			case 's':
				GenStat = 1;
				break;
			case 't':
				timeslot = optarg;
				if ( !ISO2UNIX(timeslot) ) {
					exit(255);
				}
				break;
			case 'A':
				AddDB = 1;
				break;
			case 'L':
				if ( !InitLog("nftrack", optarg) )
					exit(255);
				break;
			case 'S':
				AvStat = 1;
				break;
			case 'V':
				printf("%s: Version: %s\n",argv[0], nfdump_version);
				exit(0);
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
	}

	if ( !filter && ffile ) {
		if ( stat(ffile, &stat_buff) ) {
			perror("Can't stat file");
			exit(255);
		}
		filter = (char *)malloc(stat_buff.st_size);
		if ( !filter ) {
			perror("Memory error");
			exit(255);
		}
		ffd = open(ffile, O_RDONLY);
		if ( ffd < 0 ) {
			perror("Can't open file");
			exit(255);
		}
		ret = read(ffd, (void *)filter, stat_buff.st_size);
		if ( ret < 0   ) {
			perror("Error reading file");
			close(ffd);
			exit(255);
		}
		close(ffd);
	}

	if ( !DBdir ) {
		fprintf(stderr, "DB directory required\n");
		exit(255);
	}

	InitStat(DBdir);

	if ( !filter )
		filter = "any";

	Engine = CompileFilter(filter);
	if ( !Engine ) 
		exit(254);
	
	if ( DBinit ) {
		when = time(NULL);
		when -= ((when % 300) + 300);
		InitStatFile();
		if ( !CreateRRDBs(DBdir, when) ) {
			fprintf(stderr, "Init DBs failed\n");
			exit(255);
		}
		fprintf(stderr, "Port DBs initialized.\n");
		exit(0);
	}

	if ( lastupdate ) {
		when = RRD_LastUpdate(DBdir);
		if ( !when )
			exit(255);
		t1 = localtime(&when);
		strftime(datestr, 63, "%b %d %Y %T", t1);
		printf("Last Update: %i, %s\n", (int)when, datestr);
		exit(0);
	}

	port_table = NULL;
	if ( Mdirs || Rfile || rfile ) {
		SetupInputFileSequence(Mdirs, rfile, Rfile);
		port_table = process(filter);
//		Lister(port_table);
		if ( !port_table ) {
			exit(255);
		}
		if ( AddDB ) {
			if ( !timeslot ) {
				fprintf(stderr, "Timeslot required!\n");
				exit(255);
			}
			UpdateStat(port_table, ISO2UNIX(timeslot));
			RRD_StoreDataRow(DBdir, timeslot, port_table);
		}
	}

	if ( AvStat ) {
		port_table = GetStat();
		if ( !port_table ) {
			fprintf(stderr, "Unable to get port table!\n");
			exit(255);
		}
		// DoStat
		Generate_TopN(port_table, topN, AVG_STAT, 0, output_mode, wfile);

	} 


	if ( GenStat ) {
		when = ISO2UNIX(timeslot);
		if ( !port_table ) {
			if ( !timeslot ) {
				fprintf(stderr, "Timeslot required!\n");
				exit(255);
			}
			port_table = RRD_GetDataRow(DBdir, when);
		}
		if ( !port_table ) {
			fprintf(stderr, "Unable to get port table!\n");
			exit(255);
		}
		// DoStat
		Generate_TopN(port_table, topN, 0, when, output_mode, wfile);
	}

	CloseStat();

	return 0;
}
