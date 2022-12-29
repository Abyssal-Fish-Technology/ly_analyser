#include "../common/common.h"
#include "../common/datetime.h"
#include "../common/file.h"
#include "../common/log.h"
#include "../common/sha256.h"
#include "define.h"
#include "cache.h"
#include <hiredis/hiredis.h>

using namespace std;
using namespace datetime;

namespace topn {
static redisContext *redis;

////////////////////////////////////////////////////////////////////////////
string cache_key(const TopnReq& req) {
  string req_key;
  req.SerializeToString(&req_key);
  req_key = sha256(req_key);
  return req_key;
}

////////////////////////////////////////////////////////////////////////////
string build_cache_file(const string& cache_key) {
  string first_level = AGENT_CACHE_DIR"/" + cache_key.substr(0, 1);
  mkdir(first_level.c_str(), 0700);
  string second_level = first_level + "/" + cache_key.substr(1, 2);
  mkdir(second_level.c_str(), 0700);
  return second_level + "/" + cache_key;
}

////////////////////////////////////////////////////////////////////////////
bool save_to_file_cache(const TopnReq& req, const string& rsp) {
  return write_file_contents(build_cache_file(cache_key(req)), rsp, true, false);
}

////////////////////////////////////////////////////////////////////////////
bool load_from_file_cache(const TopnReq& req, string* rsp,
  string* cache_file_name) {
  if (rsp == NULL) return false;
  string file_name = build_cache_file(cache_key(req));
  if (cache_file_name) *cache_file_name = file_name;
  return file_exists(file_name) && read_file_contents(file_name,rsp, true);
}

////////////////////////////////////////////////////////////////////////////
bool init_redis_cache() {
  return NULL != (redis = redisConnect(REDIS_HOST, REDIS_PORT));
}

////////////////////////////////////////////////////////////////////////////
bool load_from_redis_cache(const TopnReq& req, string* rsp, u64 ttl) {
  if (!redis || !rsp) return false;
  if (redis->err) {
    std::cerr << "Redis Connect Error: " << redis->errstr << std::endl;
    return false;
  }

  string key = cache_key(req);
  redisReply* reply;
  reply = (redisReply*)redisCommand(redis, "GET %b", key.c_str(), key.size());
  if (reply == NULL) {
    std::cerr << "Redis Error: "  << redis->errstr << std::endl;
    return false;
  }
  *rsp = reply->str;
  freeReplyObject(reply);
  if (ttl) {
    reply = (redisReply*)redisCommand(redis, "EXPIRE %b %u", key.c_str(), key.size(), ttl);
    if (reply == NULL) {
      std::cerr << "Redis Error: "  << redis->errstr << std::endl;
    } else {
      freeReplyObject(reply);
    }
  }
  return true;
}

////////////////////////////////////////////////////////////////////////////
bool save_to_redis_cache(const TopnReq& req, const string& rsp, u64 ttl) {
  if (!redis) return false;
  if (redis->err) {
    std::cerr << "Redis Connect Error: " << redis->errstr << std::endl;
    return false;
  }

  string key = cache_key(req);
  redisReply* reply;
  if (ttl) {
    reply = (redisReply*)redisCommand(
        redis, "SET %b %b %d", key.c_str(), key.size(),
                               rsp.c_str(), rsp.size(), ttl*1000);
  } else {
    reply = (redisReply*)redisCommand(
        redis, "SET %b %b", key.c_str(), key.size(),
                            rsp.c_str(), rsp.size());
  }
  if (reply == NULL) {
    std::cerr << "Redis Error: "  << redis->errstr << std::endl;
    return false;
  }
  freeReplyObject(reply);
  return true;
}

} // namespace topn
