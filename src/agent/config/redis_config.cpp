#include "redis_config.h"
#include "../../common/common.h"
#include "../../common/strings.h"
#include "../../common/config.pb.h"
#include "../../common/config.h"
#include "../../common/log.h"
#include "../define.h"
#include <hiredis/hiredis.h>
#include <string>

using namespace std;

#define CONFIG_TTL (24*3600)

RedisConfig* RedisConfig::Create(const string& host, const u32 port) {
  struct timeval timeout = { 1, 500000 }; // 1.5 seconds
  auto ctx = redisConnectWithTimeout(host.c_str(), port, timeout);
  if (!ctx) {
    log_err("Could not connect to redis %s:%d\n", host.c_str(), port);
    return NULL;
  }
  return new RedisConfig(ctx);
}

RedisConfig::RedisConfig(redisContext* ctx)
   : CachedConfig(), pending_cmd_(0), ctx_(ctx) {}

RedisConfig::~RedisConfig() {
  redisFree(ctx_);
}

bool RedisConfig::Update(const config::Config& config) {
  config_ = config;
  AppendRedisCommand("MULTI");
  AppendRedisCommand("DEL devids");
  u32 ttl = CONFIG_TTL;
  for (s32 i = 0; i < config.dev_size(); ++i) {
    auto& dev = config.dev(i);
    AppendRedisCommand("SADD devids %u", dev.id());
    AppendRedisCommand("SET dev:%u:ip %s %u", dev.id(), dev.ip().c_str(), ttl);
  }
  AppendRedisCommand("DEL moids");
  for (s32 i = 0; i < config.mo_size(); ++i) {
    auto& mo = config.mo(i);
    AppendRedisCommand("SADD moids %u", mo.id());
    AppendRedisCommand("SET mo:%u:filter \"%s\" %u", mo.id(), mo.filter().c_str(), ttl);
  }
  AppendRedisCommand("EXEC");
  FlushRedisCommands();
  return true;
}

bool RedisConfig::AppendRedisCommand(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  redisAppendCommand(ctx_, format, ap);
  va_end(ap);
  ++pending_cmd_;
  return true;
}

bool RedisConfig::AppendRedisCommand(const string& cmd) {
  redisAppendFormattedCommand(ctx_, cmd.c_str(), cmd.length());
  ++pending_cmd_;
  return true;
}

const RedisConfig::RedisReplies& RedisConfig::FlushRedisCommands() {
  redis_replies_.clear();
  for (; pending_cmd_ > 0; --pending_cmd_) {
    redisReply* reply = NULL;
    redisGetReply(ctx_, (void **)&reply);
    if (reply == NULL) {
      log_err("Redis Error: %s\n", ctx_->errstr);
      pending_cmd_ = 0;
      return redis_replies_;
    }
    redis_replies_.push_back(reply->str);
    freeReplyObject(reply);
  }
  return redis_replies_;
}

const RedisConfig::MOFilters& RedisConfig::FetchMOFilters(
    const RedisConfig::MOIds& mo_ids) {
  returned_mo_filters_.clear();
  AppendRedisCommand("MULTI");
  stringstream s;
  s << "MGET";
  for (auto it = mo_ids.begin(); it != mo_ids.end(); ++it) {
    s << " mo:" << *it << "filter";
  }
  AppendRedisCommand(s.str());
  AppendRedisCommand("EXEC");
  
  const vector<string>& replies = FlushRedisCommands();
  for (u32 i = 0; i < replies.size(); ++i) {
    returned_mo_filters_.push_back(replies[i] == "(nil)" ? "any" : replies[i]);
  }
  redis_replies_.clear();
  return returned_mo_filters_;
}
