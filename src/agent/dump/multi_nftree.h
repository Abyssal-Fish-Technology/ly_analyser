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
 */

#ifndef _MULTI_NFTREE_H
#define _MULTI_NFTREE_H 1

/*
 * type definitions for nf tree
 */

typedef uint64_t (*flow_proc_t)(uint64_t *);

typedef struct FilterBlock {
	/* Filter specific data */
	uint32_t	offset;
	uint64_t	mask;
	uint64_t	value;

	/* Internal block info for tree setup */
	uint32_t	superblock;			/* Index of superblock */
	uint32_t	*blocklist;			/* index array of blocks, belonging to
								   	   this superblock */
	uint32_t	numblocks;			/* number of blocks in blocklist */
	uint32_t	OnTrue, OnFalse;	/* Jump Index for tree */
	int16_t		invert;				/* Invert result of test */
	uint16_t	comp;				/* comperator */
	flow_proc_t	function;			/* function for flow processing */
	const char* fname;				/* ascii function name */
	void		*data;				/* any additional data for this block */
} FilterBlock_t;

/* 
 * Definitions
 */
enum { CMP_EQ = 0, CMP_GT, CMP_LT, CMP_IDENT, CMP_FLAGS, CMP_IPLIST, CMP_ULLIST };

/*
 * filter functions:
 * For some filter functions, netflow records need to be processed first in order to filter them
 * This involves all data not directly available in the netflow record, such as packets per second etc. 
 * Filter speed is a bit slower due to extra netflow processsing
 * The sequence of the enum values must correspond with the entries in the flow_procs array
 */

enum { 	FUNC_NONE = 0,	/* no function - just plain filtering - just to be complete here */
		FUNC_PPS,		/* function code for pps ( packet per second ) filter function */
		FUNC_BPS,		/* function code for bps ( bits per second ) filter function */
		FUNC_BPP,		/* function code for bpp ( bytes per packet ) filter function */
		FUNC_DURATION,	/* function code for duration ( in miliseconds ) filter function */
		FUNC_MPLS_EOS,	/* function code for matching End of MPLS Stack label */
		FUNC_MPLS_ANY	/* function code for matching any MPLS label */ 
};

/* 
 * Tree type defs
 */

/* Definition of the IP list node */
struct IPListNode {
	RB_ENTRY(IPListNode) entry;
	uint64_t	ip[2];
	uint64_t	mask[2];
};

/* Definition of the port/AS list node */
struct ULongListNode {
	RB_ENTRY(ULongListNode) entry;
	uint64_t	value;
};


class CompiledFilter {
 public:
  static CompiledFilter* Compile(const char *FilterSyntax);
  virtual ~CompiledFilter() {}
  virtual void DumpList() {}
  virtual bool Match(void* record) {return 0;}
 protected:
  CompiledFilter() {}
};

class CompiledFilterImpl : public CompiledFilter {
 public:
  CompiledFilterImpl();
  virtual ~CompiledFilterImpl();
  virtual void DumpList();
  virtual bool Match(void* record);

  static CompiledFilterImpl* current() {return current_;}
  uint32_t NewBlock(uint32_t offset, uint64_t mask, uint64_t value, uint16_t comp, uint32_t  function, void *data);
  uint32_t Connect_AND(uint32_t b1, uint32_t b2);
  uint32_t Connect_OR(uint32_t b1, uint32_t b2);
  uint32_t Invert(uint32_t a); 
  uint32_t AddIdent(char *Ident);
  uint64_t* IPstack() { return ip_stack_;}
  void setStartNode(uint32_t start_node) {start_node_ = start_node; }

 private:
  bool CompileFilter(const char* FilterSyntax);
  void InitTree();
  void UpdateList(uint32_t a, uint32_t b); 
  void ClearFilter();
  /*
   * For testing purpose only
   */
  int nblocks(void) {
    return num_blocks_ - 1;
  } /* End of nblocks */
  int RunFilter(void* record);
  int RunExtendedFilter(void* record);

  static CompiledFilterImpl* current_;
  FilterBlock_t* filter_tree_;
  uint32_t mem_blocks_; // memblocks
  uint32_t num_blocks_; // NumBlocks index 0 reserved 
  uint16_t max_idents_; // MaxIdents
  uint16_t num_idents_; //NumIdents
  char** ident_list_; // IdentList
  uint32_t start_node_; // StartNode
  uint16_t extended_;  // Extended
  uint64_t* ip_stack_;  // IPstack

  friend class CompiledFilter;
};

#endif //_MULTI_NFTREE_H
