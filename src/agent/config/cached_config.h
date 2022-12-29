#ifndef __AGENT_CONFIG_CACHED_CONFIG__
#define __AGENT_CONFIG_CACHED_CONFIG__

#include <string>
#include <vector>

namespace config {
class Config;
} // namespace config

class CachedConfig {
 public:
  static CachedConfig* Create();
  virtual ~CachedConfig() {}

  typedef std::vector<uint32_t> MOIds;
  typedef std::vector<std::string> MOFilters;

  virtual bool Update(const config::Config& config) = 0;
  virtual const config::Config& config() = 0;
  virtual config::Config* mutable_config() = 0;
  virtual const MOFilters& FetchMOFilters(const MOIds& mo_ids) = 0;

 protected:
  CachedConfig() {}
};

#endif // __AGENT_CONFIG_CACHED_CONFIG__
