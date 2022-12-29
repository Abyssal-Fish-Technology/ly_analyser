#include "local_disk_config.h"

#include <memory>
#include "../common/config.h"

using namespace std;

LocalDiskConfig* LocalDiskConfig::Create(const string& config_file) {
  unique_ptr<ConfigReader> reader(new ConfigReader());
  if (reader->LoadFromFile(config_file)) {
    return new LocalDiskConfig(std::move(reader));
  }
  return NULL; 
}

LocalDiskConfig::LocalDiskConfig(unique_ptr<ConfigReader> reader)
  : reader_(std::move(reader)) {}

LocalDiskConfig::~LocalDiskConfig() {}

const config::Config& LocalDiskConfig::config() {
  return reader_->config();
}

config::Config* LocalDiskConfig::mutable_config() {
  return reader_->mutable_config();
}

const CachedConfig::MOFilters& LocalDiskConfig::FetchMOFilters(
    const CachedConfig::MOIds& mo_ids) {
  returned_mo_filters_.clear();
  for (auto it1 = mo_ids.begin(); it1!= mo_ids.end(); ++it1) {
    for (auto it2 = config().mo().begin();
         it2 != config().mo().end(); ++it2){
      if (*it1 == it2->id()) {
        returned_mo_filters_.push_back(it2->filter());
        break;
      }   
    }   
  }
  return returned_mo_filters_;
}
