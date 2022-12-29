#ifndef __AGENT_CONFIG_REDIS_CONFIG__
#define __AGENT_CONFIG_REDIS_CONFIG__

#include <string>
#include <vector>
#include "../../common/config.h"
#include "cached_config.h"

class redisContext;
namespace config {
class Config;
}  // namespace config

class RedisConfig : public CachedConfig {
 public:
  static RedisConfig* Create(const std::string& host, const uint32_t port);
  ~RedisConfig() override;

  bool Update(const config::Config& config) override;

  // Do not use this method. TODO: fix it.
  const config::Config& config() override { return config_; } 
  // Do not use this method. TODO: fix it.
  config::Config* mutable_config() override { return &config_; }

  const MOFilters& FetchMOFilters(const MOIds& mo_ids) override;

 private:
  RedisConfig(redisContext* ctx);
  bool AppendRedisCommand(const std::string& cmd);
  bool AppendRedisCommand(const char* format, ...);

  typedef std::vector<std::string> RedisReplies; 
  const RedisReplies& FlushRedisCommands();

  uint32_t pending_cmd_;
  redisContext *ctx_;
  RedisReplies redis_replies_;
  MOFilters returned_mo_filters_;
  config::Config config_;
};

#endif // __AGENT_CONFIG_REDIS_CONFIG__
