#include <cstdlib>
#include <memory>
#include "../../common/common.h"
#include "../../common/config.h"
#include "../../common/config.pb.h"
#include "../dump/libnfdump.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../config/cached_config.h"
#include "../define.h"
#include "cache_generator.h"
#include "flow_indexer.h"

using namespace std;

//static std::unique_ptr<FlowIndexer> flow_indexer;
static FlowIndexer* flow_indexer = nullptr;
static std::unique_ptr<CacheGenerator> cache_generator;

////////////////////////////////////////////////////////////////////////////
void flow_callback(master_record_t* r) {
  flow_indexer->flowset_.push_back(*r);
}

////////////////////////////////////////////////////////////////////////////
bool parse_ul(const char* str, u32* ul) {
  if (!str) return false;
  char *end;
  *ul = std::strtoul(str, &end, 10);
  if (errno == ERANGE || *ul == ULONG_MAX) return false;
  return true;
}

////////////////////////////////////////////////////////////////////////////
int main(int argc, char** argv) {
  if (DEBUG) log_info("DEBUG mode is on.\n");

  const char* devid_str = getenv("DEVID");
  const char* start_time_str = getenv("STARTTIME");
  const char* end_time_str = getenv("ENDTIME");

  u32 devid = 0;
  u32 start_time = 0;
  u32 end_time = 0;

  if (!parse_ul(devid_str, &devid)) {
    log_err("Empty or wrong devid %s\n", devid_str);
    return -1;
  }

  if (!parse_ul(start_time_str, &start_time)) {
    log_err("Empty or wrong start_time %s\n", start_time_str);
    return -1;
  }  

  if (!parse_ul(end_time_str, &end_time)) {
    log_err("Empty or wrong end_time %s\n", end_time_str);
    return -1;
  }

  end_time += 300;
  if (end_time <= start_time) {
    log_err("end time %u is less than start time %u\n", end_time, start_time);
    return -1;
  }

  log_info("devid:%u, time:%u - %u\n", devid, start_time, end_time);
  unique_ptr<CachedConfig> cfg(CachedConfig::Create());
	unique_ptr<CMyINI> myini(new CMyINI());
  {
    flow_indexer = new FlowIndexer(devid, start_time, end_time, cfg.get());
    //flow_indexer.reset(new FlowIndexer(devid, start_time, end_time, cfg.get()));
    process_flow(argc, argv, flow_callback);
    delete flow_indexer;    
  }
  {
    cache_generator.reset(new CacheGenerator(devid, start_time, cfg.get(), myini.get()));
  }
  
  return 0;
}
