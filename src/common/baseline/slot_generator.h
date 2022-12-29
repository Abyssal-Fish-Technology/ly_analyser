#ifndef __COMMON_BASELINE_GENERATOR_H__
#define __COMMON_BASELINE_GENERATOR_H__

#include "../common.h"
#include "../config.pb.h"

class SlotManager;

class SlotGenerator {
 public:
  // Load slot
  SlotGenerator() {}
  explicit SlotGenerator(const std::string& config_file)
    : config_file_(config_file) {}

  bool LoadConfigFromFile(const std::string& filename);
  bool GenerateSlots(SlotManager* manager);

 private:
  bool GenerateDeviceSlots(SlotManager* manager);
  bool GenerateInterfaceSlots(SlotManager* manager);
  bool GenerateTopIpSlots(SlotManager* manager);
  bool GenerateMOSlots(SlotManager* manager);

  std::string config_file_;
  config::Config config_;
};

#endif // __COMMON_BASELINE_GENERATOR_H__
