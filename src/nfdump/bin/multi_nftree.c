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
 *  $Id: nftree.c 39 2009-11-25 08:11:15Z haag $
 *
 *  $LastChangedRevision: 39 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nf_common.h"
#include "ipconv.h"

#include "grammar.h"
#include "multi_nftree.h"

/*
 * netflow filter engine
 *
 */

extern char 	*CurrentIdent;

#define MAXBLOCKS 1024
#define IdentNumBlockSize 32

// added by lxh start
extern int lineno;
CompiledFilterImpl* CompiledFilterImpl::current_ = NULL;
// added by lxh end

/* 
 * flow processing function table:
 * order of entries must correspond with filter functions enum in nftree.h 
 */
struct flow_procs_map_s {
  const char *name;
  flow_proc_t function;
};

/* flow processing functions */
static inline uint64_t pps_function(uint64_t *data);
static inline uint64_t bps_function(uint64_t *data);
static inline uint64_t bpp_function(uint64_t *data);
static inline uint64_t duration_function(uint64_t *data);
static inline uint64_t mpls_eos_function(uint64_t *data);
static inline uint64_t mpls_any_function(uint64_t *data);

static struct flow_procs_map_s flow_procs_map[] = { 
    {"none",    NULL},
    {"pps",     pps_function},
    {"bps",     bps_function},
    {"bpp",     bpp_function},
    {"duration",  duration_function},
    {"mpls eos",  mpls_eos_function},
    {"mpls any",  mpls_any_function},
    {NULL,      NULL}
  };

// 128bit compare for IPv6 
static int IPNodeCMP(struct IPListNode *e1, struct IPListNode *e2) {
  uint64_t	ip_e1[2], ip_e2[2];
	
	ip_e1[0] = e1->ip[0] & e2->mask[0];
	ip_e1[1] = e1->ip[1] & e2->mask[1];

	ip_e2[0] = e2->ip[0] & e1->mask[0];
	ip_e2[1] = e2->ip[1] & e1->mask[1];

	if ( ip_e1[0] == ip_e2[0] ) {
		if ( ip_e1[1] == ip_e2[1] )
			return 0;
		else
			return (ip_e1[1] < ip_e2[1] ? -1 : 1);
	} else {
		return (ip_e1[0] < ip_e2[0] ? -1 : 1);
	}

} // End of IPNodeCMP

// 64bit uint64 compare
static int ULNodeCMP(struct ULongListNode *e1, struct ULongListNode *e2) {
	if ( e1->value == e2->value ) 
		return 0;
	else 
		return (e1->value < e2->value ? -1 : 1);

} // End of ULNodeCMP

// Insert the IP RB tree code here
RB_GENERATE(IPtree, IPListNode, entry, IPNodeCMP);

// Insert the Ulong RB tree code here
RB_GENERATE(ULongtree, ULongListNode, entry, ULNodeCMP);

CompiledFilter* CompiledFilter::Compile(const char* FilterSyntax) {
  CompiledFilterImpl* filter = new CompiledFilterImpl();
  if (!filter->CompileFilter(FilterSyntax)) {
    delete filter;
    filter = NULL;
  }
  return filter;
}

CompiledFilterImpl::CompiledFilterImpl()
    : filter_tree_(NULL),
      mem_blocks_(0),
      num_blocks_(1), /* index 0 reserved */
      max_idents_(0),
      num_idents_(0),
      ident_list_(NULL),
      start_node_(0),
      extended_(0),
      ip_stack_(NULL)
  {current_ = this;}

CompiledFilterImpl::~CompiledFilterImpl() {
  if (filter_tree_) {
    for (uint32_t i = 1; i < num_blocks_; ++i) {
      if (filter_tree_[i].blocklist) free(filter_tree_[i].blocklist);
    }
    free(filter_tree_);
  }
  if (ident_list_) free(ident_list_);
  if (ip_stack_) free(ip_stack_);
}

void CompiledFilterImpl::InitTree(void) {
	mem_blocks_ = 1;
	filter_tree_ = (FilterBlock_t *)malloc(MAXBLOCKS * sizeof(FilterBlock_t));
	if ( !filter_tree_ ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	this->ClearFilter();
} // End of InitTree

/*
 * Clear Filter
 */
void CompiledFilterImpl::ClearFilter(void) {
	num_blocks_ = 1;
	extended_  = 0;
	max_idents_ = 0;
	num_idents_ = 0;
	ident_list_ = NULL;
	memset((void *)filter_tree_, 0, MAXBLOCKS * sizeof(FilterBlock_t));

} /* End of ClearFilter */

bool CompiledFilterImpl::CompileFilter(const char *FilterSyntax) {
  int	ret;
	if ( !FilterSyntax ) return false;

  ip_stack_ = (uint64_t *)malloc(16 * MAXHOSTS);
	if ( !ip_stack_ ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	if ( !InitSymbols() )
		exit(255);
	this->InitTree();
  // added by lxh start
  lineno = 1;
  // added by lxh end
	lex_init(FilterSyntax);
	ret = yyparse();
	if ( ret != 0 ) {
    free(ip_stack_);
    ip_stack_ = NULL;
		return false;
	}
	lex_cleanup();
	free(ip_stack_);
  ip_stack_ = NULL;
  return true;
} // End of GetTree

bool CompiledFilterImpl::Match(void* record) {
  return extended_ ? this->RunExtendedFilter(record) : this->RunFilter(record);
}
/* 
 * Returns next free slot in blocklist
 */
uint32_t CompiledFilterImpl::NewBlock(uint32_t offset, uint64_t mask, uint64_t value, uint16_t comp, uint32_t  function, void *data) {
	uint32_t	n = num_blocks_;

	if ( n >= ( mem_blocks_ * MAXBLOCKS ) ) {
		mem_blocks_++;
// moded by lxh start
		filter_tree_ = (FilterBlock_t*)realloc(filter_tree_, mem_blocks_ * MAXBLOCKS * sizeof(FilterBlock_t));
// moded by lxh end
		if ( !filter_tree_) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
	}

	filter_tree_[n].offset	= offset;
	filter_tree_[n].mask		= mask;
	filter_tree_[n].value		= value;
	filter_tree_[n].invert	= 0;
	filter_tree_[n].OnTrue	= 0;
	filter_tree_[n].OnFalse	= 0;
	filter_tree_[n].comp 		= comp;
	filter_tree_[n].function 	= flow_procs_map[function].function;
	filter_tree_[n].fname 	= flow_procs_map[function].name;
	filter_tree_[n].data 		= data;
	if ( comp > 0 || function > 0 )
		extended_ = 1;

	filter_tree_[n].numblocks = 1;
	filter_tree_[n].blocklist = (uint32_t *)malloc(sizeof(uint32_t));
	filter_tree_[n].superblock = n;
	filter_tree_[n].blocklist[0] = n;
	num_blocks_++;
	return n;

} /* End of NewBlock */

/* 
 * Connects the two blocks b1 and b2 ( AND ) and returns index of superblock
 */
uint32_t	CompiledFilterImpl::Connect_AND(uint32_t b1, uint32_t b2) {

	uint32_t	a, b, i, j;

	if ( filter_tree_[b1].numblocks <= filter_tree_[b2].numblocks ) {
		a = b1;
		b = b2;
	} else {
		a = b2;
		b = b1;
	}
	/* a points to block with less children and becomes the superblock 
	 * connect b to a
	 */
	for ( i=0; i < filter_tree_[a].numblocks; i++ ) {
		j = filter_tree_[a].blocklist[i];
		if ( filter_tree_[j].invert ) {
			if ( filter_tree_[j].OnFalse == 0 ) {
				filter_tree_[j].OnFalse = b;
			}
		} else {
			if ( filter_tree_[j].OnTrue == 0 ) {
				filter_tree_[j].OnTrue = b;
			}
		}
	}
	this->UpdateList(a,b);
	return a;

} /* End of Connect_AND */

/* 
 * Connects the two blocks b1 and b2 ( OR ) and returns index of superblock
 */
uint32_t	CompiledFilterImpl::Connect_OR(uint32_t b1, uint32_t b2) {

	uint32_t	a, b, i, j;

	if ( filter_tree_[b1].numblocks <= filter_tree_[b2].numblocks ) {
		a = b1;
		b = b2;
	} else {
		a = b2;
		b = b1;
	}
	/* a points to block with less children and becomes the superblock 
	 * connect b to a
	 */
	for ( i=0; i < filter_tree_[a].numblocks; i++ ) {
		j = filter_tree_[a].blocklist[i];
		if ( filter_tree_[j].invert ) {
			if ( filter_tree_[j].OnTrue == 0 ) {
				filter_tree_[j].OnTrue = b;
			}
		} else {
			if ( filter_tree_[j].OnFalse == 0 ) {
				filter_tree_[j].OnFalse = b;
			}
		}
	}
	this->UpdateList(a,b);
	return a;

} /* End of Connect_OR */

/* 
 * Inverts OnTrue and OnFalse
 */
uint32_t	CompiledFilterImpl::Invert(uint32_t a) {
	uint32_t	i, j;

	for ( i=0; i< filter_tree_[a].numblocks; i++ ) {
		j = filter_tree_[a].blocklist[i];
		filter_tree_[j].invert = filter_tree_[j].invert ? 0 : 1 ;
	}
	return a;

} /* End of Invert */

/*
 * Update supernode infos:
 * node 'b' was connected to 'a'. update node 'a' supernode data
 */
void CompiledFilterImpl::UpdateList(uint32_t a, uint32_t b) {
	size_t s;
	uint32_t	i,j;

	/* numblocks contains the number of blocks in the superblock */
	s = filter_tree_[a].numblocks + filter_tree_[b].numblocks;
	filter_tree_[a].blocklist = (uint32_t *)realloc(filter_tree_[a].blocklist, s * sizeof(uint32_t));
	if ( !filter_tree_[a].blocklist ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(250);
	}

	/* connect list of node 'b' after list of node 'a' */
	j = filter_tree_[a].numblocks;
	for ( i=0; i< filter_tree_[b].numblocks; i++ ) {
		filter_tree_[a].blocklist[j+i] = filter_tree_[b].blocklist[i];
	}
	filter_tree_[a].numblocks = s;

	/* set superblock info of all children to new superblock */
	for ( i=0; i< filter_tree_[a].numblocks; i++ ) {
		j = filter_tree_[a].blocklist[i];
		filter_tree_[j].superblock = a;
	}

	/* cleanup old node 'b' */
	filter_tree_[b].numblocks = 0;
	if ( filter_tree_[b].blocklist ) {
		free(filter_tree_[b].blocklist);
    filter_tree_[b].blocklist=NULL;
  }

} /* End of UpdateList */

/*
 * Dump Filterlist 
 */
void CompiledFilterImpl::DumpList() {
  printf("StartNode: %i Engine: %s\n", start_node_, extended_ ? "Extended" : "Fast");

	uint32_t i, j;
	for (i=1; i<num_blocks_; i++ ) {
    FilterBlock_t& block = filter_tree_[i];
		if (block.invert)
			printf("Index: %u, Offset: %u, Mask: %.16llx, Value: %.16llx, Superblock: %u, Numblocks: %u, !OnTrue: %u, !OnFalse: %u Comp: %u Function: %s\n",
				i, block.offset, (unsigned long long)block.mask, 
				(unsigned long long)block.value, block.superblock, 
				block.numblocks, block.OnTrue, block.OnFalse, block.comp, block.fname);
		else 
			printf("Index: %u, Offset: %u, Mask: %.16llx, Value: %.16llx, Superblock: %u, Numblocks: %u, OnTrue: %u, OnFalse: %u Comp: %u Function: %s\n",
				i, block.offset, (unsigned long long)block.mask, 
				(unsigned long long)block.value, block.superblock, 
				block.numblocks, block.OnTrue, block.OnFalse, block.comp, block.fname);
		if ( block.OnTrue > (mem_blocks_ * MAXBLOCKS) || block.OnFalse > (mem_blocks_ * MAXBLOCKS) ) {
			fprintf(stderr, "Tree pointer out of range for index %u. *** ABORT ***\n", i);
			exit(255);
		}
		if ( block.data ) {
			if ( block.comp == CMP_IPLIST ) {
				struct IPListNode *node;
				RB_FOREACH(node, IPtree, (IPtree*)block.data) {
					printf("value: %.16llx %.16llx mask: %.16llx %.16llx\n", 
						(unsigned long long)node->ip[0], (unsigned long long)node->ip[1], 
						(unsigned long long)node->mask[0], (unsigned long long)node->mask[1]);
				} 
			} else if ( block.comp == CMP_ULLIST ) {
				struct ULongListNode *node;
				RB_FOREACH(node, ULongtree, (ULongtree*)block.data) {
					printf("%.16llx \n", (unsigned long long)node->value);
				}
			} else 
				printf("Error comp: %i\n", block.comp);
		}
		printf("\tBlocks: ");
		for ( j=0; j<block.numblocks; j++ ) 
			printf("%i ", block.blocklist[j]);
		printf("\n");
	}
	printf("NumBlocks: %i\n", num_blocks_ - 1);
	for ( i=0; i<num_idents_; i++ ) {
		printf("Ident %i: %s\n", i, ident_list_[i]);
	}
} /* End of DumpList */

/* fast filter engine */
int CompiledFilterImpl::RunFilter(void* record) {
  uint64_t* nfrecord = (uint64_t*)record;
  uint32_t	index, offset;
  int	evaluate, invert;
	index = start_node_;
	evaluate = 0;
	invert = 0;
	while ( index ) {
    FilterBlock_t& block = filter_tree_[index];
		offset   = block.offset;
		invert   = block.invert;
		evaluate = (nfrecord[offset] & block.mask ) == block.value;
		index    = evaluate ?  block.OnTrue : block.OnFalse;
	}
	return invert ? !evaluate : evaluate;

} /* End of RunFilter */

/* extended filter engine */
int CompiledFilterImpl::RunExtendedFilter(void* record) {
  uint64_t* nfrecord = (uint64_t*)record;
  uint32_t	index, offset; 
  uint64_t	value;
  int	evaluate, invert;

	index = start_node_; 
	evaluate = 0;
	invert = 0;
	while ( index ) {
    FilterBlock_t& block = filter_tree_[index];
		offset   = block.offset;
		invert   = block.invert;

		if (block.function == NULL)
			value = nfrecord[offset] & block.mask;
		else
			value = block.function(nfrecord);

		switch (block.comp) {
			case CMP_EQ:
				evaluate = value == block.value;
				break;
			case CMP_GT:
				evaluate = value > block.value;
				break;
			case CMP_LT:
				evaluate = value < block.value;
				break;
			case CMP_IDENT:
				value = block.value;
				evaluate = strncmp(CurrentIdent, ident_list_[value], IDENTLEN) == 0 ;
				break;
			case CMP_FLAGS:
				if ( invert )
					evaluate = value > 0;
				else
					evaluate = value == block.value;
				break;
			case CMP_IPLIST: {
				struct IPListNode find;
				find.ip[0] = nfrecord[offset];
				find.ip[1] = nfrecord[offset+1];
				find.mask[0] = 0xffffffffffffffffLL;
				find.mask[1] = 0xffffffffffffffffLL;
// moded by lxh start
				evaluate = RB_FIND(IPtree, (IPtree*)block.data, &find) != NULL; }
// moded by lxh end
				break;
			case CMP_ULLIST: {
				struct ULongListNode find;
				find.value = value;
// moded by lxh start
				evaluate = RB_FIND(ULongtree, (ULongtree*)block.data, &find ) != NULL; }
// moded by lxh end
				break;
		}

		index = evaluate ? block.OnTrue : block.OnFalse;
	}
	return invert ? !evaluate : evaluate;

} /* End of RunExtendedFilter */

uint32_t CompiledFilterImpl::AddIdent(char *Ident) {
uint32_t	num;

	if ( max_idents_ == 0 ) {
		// allocate first array block
		max_idents_ = IdentNumBlockSize;
		ident_list_ = (char **)malloc( max_idents_ * sizeof(char *));
		if ( !ident_list_ ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(254);
		}
		memset((void *)ident_list_, 0, max_idents_ * sizeof(char *));
		num_idents_ = 0;
	} else if ( num_idents_ == max_idents_ ) {
		// extend array block
		max_idents_ += IdentNumBlockSize;
// moded by lxh start
		ident_list_ = (char**)realloc((void *)ident_list_, max_idents_ * sizeof(char *));
// moded by lxh end
		if ( !ident_list_ ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(254);
		}
	}

	num = num_idents_++;
	ident_list_[num] = strdup(Ident);
	if ( !ident_list_[num] ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(254);
	}

	return num;

} // End of AddIdent

/* record processing functions */

uint64_t duration_function(uint64_t *data) {
master_record_t *record;
uint64_t		duration;

	record = (master_record_t *)data;
	/* duration in msec */
	duration = 1000*(record->last - record->first) + record->msec_last - record->msec_first;

	return duration;

} // End of duration_function

uint64_t pps_function(uint64_t *data) {
master_record_t *record;
uint64_t		duration;

	record = (master_record_t *)data;
	/* duration in msec */
	duration = 1000*(record->last - record->first) + record->msec_last - record->msec_first;
	if ( duration == 0 )
		return 0;
	else 
		return ( 1000LL * record->dPkts ) / duration;

} // End of pps_function

uint64_t bps_function(uint64_t *data) {
master_record_t *record;
uint64_t		duration;

	record = (master_record_t *)data;
	/* duration in msec */
	duration = 1000*(record->last - record->first) + record->msec_last - record->msec_first;
	if ( duration == 0 )
		return 0;
	else 
		return ( 8000LL * record->dOctets ) / duration;	/* 8 bits per Octet - x 1000 for msec */

} // End of bps_function

uint64_t bpp_function(uint64_t *data) {
master_record_t 	*record;

	record = (master_record_t *)data;
	return record->dPkts ? record->dOctets / record->dPkts : 0;

} // End of bpp_function

uint64_t mpls_eos_function(uint64_t *data) {
master_record_t 	*record;
int i;

	record = (master_record_t *)data;

	// search for end of MPLS stack label
	for (i=0; i<10; i++ ) {
		if ( record->mpls_label[i] & 1 ) {
			// End of stack found -> mask exp and eos bits
			return record->mpls_label[i] & 0x00FFFFF0;
		}
	}

	// trick filter to fail with an invalid mpls label value
	return 0xFF000000;

} // End of mpls_eos_function

uint64_t mpls_any_function(uint64_t *data) {
master_record_t *record;
int i;

	record = (master_record_t *)data;

	// search for end of MPLS stack label
	for (i=0; i<10; i++ ) {
		if ( (record->mpls_label[i] & 1) == 1 ) {
			// End of stack found -> mask exp and eos bits
			return record->mpls_label[i] & 0x00FFFFF0;
		}
	}

	// trick filter to fail with an invalid mpls label value
	return 0xFF000000;

} // End of mpls_eos_function


