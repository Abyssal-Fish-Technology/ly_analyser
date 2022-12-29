#ifndef _LIBNFDUMP_H
#define _LIBNFDUMP_H 1

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#include "nffile.h"

typedef void (*flow_callback_t)(master_record_t*);
void* process_flow(int argc, char** argv, flow_callback_t flow_callback);

class CompiledFilter {
 public:
  static CompiledFilter* Compile(const char *FilterSyntax);
  virtual ~CompiledFilter() {}
  virtual void DumpList() {}
  virtual bool Match(void* record) {return 0;}
 protected:
  CompiledFilter() {}
};

#endif //_LIBNFDUMP_H
