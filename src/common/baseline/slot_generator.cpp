#include "slot_generator.h"
#include "../common.h"
#include "../file.h"
#include "../config.h"
#include "../strings.h"
#include "slot_manager.h"

using namespace std;
using namespace config;

bool SlotGenerator::LoadConfigFromFile(const string& config_file) {
  ConfigReader cfg_reader(config_file);
  if (!cfg_reader.LoadFromFile()) return false;
  config_.Swap(cfg_reader.mutable_config());
  return true;
}

bool SlotGenerator::GenerateSlots(SlotManager* manager) {
  return GenerateDeviceSlots(manager) && 
         GenerateInterfaceSlots(manager) &&
         GenerateTopIpSlots(manager) &&
         GenerateMOSlots(manager);
}

bool SlotGenerator::GenerateDeviceSlots(SlotManager* manager) {
  for (int i = 0; i < config_.dev_size(); ++i) {
    auto& dev = config_.dev(i);
    string slot_name = "dev:" + to_string(dev.id());
    auto slot = manager->Find(slot_name);
    if (!slot) slot = manager->Reserve(slot_name);
    if (!slot) return false;
    slot->set_devid(dev.id());
    slot->set_filter("any");
  }
  return true;
}

bool SlotGenerator::GenerateInterfaceSlots(SlotManager* manager) {
  for (int i = 0; i < config_.dev_size(); ++i) {
    auto& dev = config_.dev(i);
    string dev_name = "dev:" + to_string(dev.id());
    for (int j = 0; j < dev.interfaces_size(); ++j) {
      auto interface = dev.interfaces(j);
      string slot_name = dev_name + "|if:" + to_string(interface.no()) + " in";
      auto slot = manager->Find(slot_name);
      if (!slot) slot = manager->Reserve(slot_name);
      if (!slot) return false;
      slot->set_devid(dev.id());
      slot->set_interface_no(interface.no());
      slot->set_interface_direction(BaselineSlot::IN);
      slot->set_filter("in if " + to_string(interface.no()));

      slot_name = dev_name + "|if:" + to_string(interface.no()) + " out";
      slot = manager->Find(slot_name);
      if (!slot) slot = manager->Reserve(slot_name);
      if (!slot) return false;
      slot->set_devid(dev.id());
      slot->set_interface_no(interface.no());
      slot->set_interface_direction(BaselineSlot::OUT);
      slot->set_filter("out if " + to_string(interface.no()));
    }
  }
  return true;
}

bool SlotGenerator::GenerateTopIpSlots(SlotManager* manager) {
  return true;
}

bool SlotGenerator::GenerateMOSlots(SlotManager* manager) {
  return true;
}

