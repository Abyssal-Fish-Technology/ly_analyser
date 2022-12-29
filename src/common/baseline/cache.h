#ifndef __AGENT_CACHE_H__
#define __AGENT_CACHE_H__

#include "../common.h"

namespace baseline {
bool save_to_file_cache(const topn::TopnReq& req, const std::string& rsp);
bool load_from_file_cache(const topn::TopnReq& req, std::string* rsp, 
    std::string* cache_file_name = NULL);
bool init_redis_cache();
bool save_to_redis_cache(const TopnReq& req, const std::string& rsp, u64 ttl=0);
bool load_from_redis_cache(const TopnReq& req, std::string* rsp, u64 ttl=0);
}

#endif // __AGENT_CACHE_H__
