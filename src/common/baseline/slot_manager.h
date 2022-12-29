#ifndef __COMMON_BASELINE_SLOT_MANAGER_H__
#define __COMMON_BASELINE_SLOT_MANAGER_H__

#include "../common.h"
#include "baseline.pb.h"

class SlotManager {
 public:
  // Load slot
  SlotManager()
    : dirty_(false), next_available_id_(1), next_available_baseline_id_(1) {}
  explicit SlotManager(const std::string& filename)
    : dirty_(false), next_available_id_(1), next_available_baseline_id_(1),
      filename_(filename) {}
  ~SlotManager();

  bool LoadFromFile() {return LoadFromFile(filename_); }
  bool SaveToFile() { return SaveToFile(filename_); }
  bool LoadFromFile(const std::string& filename);
  bool SaveToFile(const std::string& filename);

  BaselineSlot* Find(const std::string& slot_name);
  BaselineSlot* Reserve(const std::string& slot_name);

 private:
  void UpdateNextIds(const BaselineSlot& slot);
  bool AllocBatch(u32 size);
  void Recycle();

  bool dirty_;
  u32 next_available_id_;
  u32 next_available_baseline_id_;
  std::string filename_;
  std::map<std::string, BaselineSlot*> active_;
  std::map<std::string, BaselineSlot*> unactive_;
};

#endif // __COMMON_BASELINE_SLOT_MANAGER_H__
