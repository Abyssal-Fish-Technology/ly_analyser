#ifndef __AGENT_REDIS_CACHE_H__
#define __AGENT_REDIS_CACHE_H__

#include "../common/common.h"
#include "../common/topn.pb.h"

namespace topn {
bool init_redis_cache();
bool save_to_redis_cache(const TopnReq& req, const std::string& rsp, u64 ttl=0);
bool load_from_redis_cache(const TopnReq& req, std::string* rsp, u64 ttl=0);
}

#endif // __AGENT_REDIS_CACHE_H__
