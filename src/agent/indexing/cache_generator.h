#ifndef AGENT_CACHE_GENERATOR_H
#define AGENT_CACHE_GENERATOR_H

#include <string>
#include "../../common/common.h"
#include "../../common/CMyINI.h"
#include "../../common/cache.pb.h"
#include "../../common/topn.pb.h"
#include "../../common/topn_req.h"
#include "../../common/config.h"
#include "../../common/config.pb.h"
#include "../../common/threadpool.hpp"
#include "../config/cached_config.h"
#include "../data/dbctx.h"
#include "../data/web_cache.h"
#include "../flow/nf_scanner.h"

using config::Config;
using namespace topn;

class CacheGenerator {
 public:
  CacheGenerator(u32 devid, u32 time, CachedConfig* cfg, CMyINI* myini);
  
  void GenerateCacheEntries();

 private:
  bool LoadCacheConfigFromFile(const std::string& file_name);
  //static struct cache_pair GenerateCacheEntry(TopnReq& req, CacheGenerator* ptr);
  void GenerateCacheEntry(const TopnReq& req);
//	bool ReadConfig(Config* cfg);

  u32 devid_;
  u32 time_;
  config::Cache cache_;
  CachedConfig* config_;
	CMyINI* myini_;
};

#endif  // AGENT_CACHE_GENERATOR_H
