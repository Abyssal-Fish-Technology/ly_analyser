#ifndef __AGENT_LOCAL_DISK_CONFIG__
#define __AGENT_LOCAL_DISK_CONFIG__

#include <string>
#include <memory>
#include "cached_config.h"

namespace config {
class Config;
}  // namespace config
class ConfigReader;

class LocalDiskConfig : public CachedConfig {
 public:
  static LocalDiskConfig* Create(const std::string& config_file);
  ~LocalDiskConfig() override;

  // Do not use method. TODO:fix it
  bool Update(const config::Config& config) override {return false;}
  const config::Config& config() override;
  config::Config* mutable_config() override;
  const MOFilters& FetchMOFilters(const MOIds& mo_ids) override;

 private:
  LocalDiskConfig(std::unique_ptr<ConfigReader> reader);

  std::unique_ptr<ConfigReader> reader_;
  MOFilters returned_mo_filters_;
};

#endif // __AGENT_LOCAL_DISK_CONFIG__
