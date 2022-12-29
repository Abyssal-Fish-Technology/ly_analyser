#include "slot_manager.h"
#include "../common.h"
#include "../file.h"
#include "../log.h"
#include "../strings.h"
#include <iostream>
#include <sstream>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

using namespace std;
using google::protobuf::io::IstreamInputStream;
using google::protobuf::io::OstreamOutputStream;

const static u32 kMaxSlots = 1000000;
const static u32 kAllocBatchSize = 256;

SlotManager::~SlotManager() {
  for (auto it = active_.begin(); it != active_.end(); ++it) {
    delete it->second;
  }
  active_.clear();
  for (auto it = active_.begin(); it != active_.end(); ++it) {
    delete it->second;
  }
  unactive_.clear();
}

void SlotManager::UpdateNextIds(const BaselineSlot& slot) {
  if (slot.has_id()) next_available_id_ = MAX(next_available_id_, slot.id() + 1);
  for (int i = 0 ; i < slot.baselines_size(); ++i) {
    auto baseline = slot.baselines(i);
    if (!baseline.has_id()) continue;
    next_available_baseline_id_ = MAX(next_available_baseline_id_, baseline.id() + 1);
  }
}

bool SlotManager::LoadFromFile(const string& filename) {
  if (filename.empty()) return false;
  ifstream ins(filename, ios_base::in);
  
  auto is = new IstreamInputStream(&ins);
  BaselineSlots all;
  if (!google::protobuf::TextFormat::Parse(is, &all)) {
    log_err("Error parsing baseline file %s\n", filename.c_str());
    return false;
  }

  for (int i = 0; i < all.slots_size(); ++i) {
    auto slot = all.mutable_slots(i);
    auto that = Find(slot->name());
    if (that) {
      UpdateNextIds(*that);
      if (slot->DebugString() != that->DebugString()) that->Swap(slot);
      continue;
    }
    that = Reserve(slot->name());
    if (that) {
      UpdateNextIds(*that);
      if (slot->DebugString() != that->DebugString()) that->Swap(slot);
      continue;
    }
    log_info("Error reservsing baseline %u from file %s\n",
             i, filename.c_str());
    return false;
  }
  log_info("Successfully parsed %u baselines from file %s\n",
           all.slots_size(), filename.c_str());
  return true;
}

bool SlotManager::SaveToFile(const string& filename) {
  if (filename.empty()) return false;
  if (!dirty_) return true;
  ofstream outs(filename, ios_base::out);
  auto os = new OstreamOutputStream(&outs);

  BaselineSlots all;
  for (auto it = active_.begin(); it != active_.end(); ++it) {
    auto slot = all.add_slots();
    slot->CopyFrom(*it->second);
  }
  for (auto it = unactive_.begin(); it != unactive_.end(); ++it) {
    auto slot = all.add_slots();
    slot->CopyFrom(*it->second);
  }
 
  if (!google::protobuf::TextFormat::Print(all, os)) {
    log_err("Error printing baseline file %s\n", filename.c_str());
    return false;
  }
  log_info("Successfully printed %u baselines to file %s\n",
           all.slots_size(), filename.c_str());
  dirty_ = false;
  return true;
}

BaselineSlot* SlotManager::Find(const string& slot_name) {
  auto it = active_.find(slot_name);
  if (it == active_.end()) return NULL;
  return it->second;
}

BaselineSlot* SlotManager::Reserve(const string& slot_name) {
  if (unactive_.empty()) AllocBatch(kAllocBatchSize);
  if (unactive_.empty()) return NULL;
  auto it = unactive_.find(slot_name);
  if (it == unactive_.end()) it = unactive_.begin();
  auto slot = it->second;
  unactive_.erase(it);
  slot->set_active(true);
  slot->set_name(slot_name);
  active_[slot_name] = slot;
  dirty_ = true; 
  return slot;
}

void SlotManager::Recycle() {
}

bool SlotManager::AllocBatch(u32 size) {
  size = MIN(size, kMaxSlots - active_.size());
  if (size <= 0) return false;
  for (u32 i = 0; i < size; ++i) {
    auto slot = new BaselineSlot();
    auto slot_id = next_available_id_;
    ++next_available_id_;
    auto slot_name = to_string(slot_id);
    slot->set_id(slot_id);
    slot->set_name(slot_name);
    slot->set_active(false);
    unactive_[slot_name] = slot;

    Baseline* baseline;
    u64 baseline_id;

    // bps 300s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(300);
    baseline->set_unit(Baseline::BPS);
    // pps 300s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(300);
    baseline->set_unit(Baseline::PPS);
    // fps 300s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(300);
    baseline->set_unit(Baseline::FPS);

    // bps 3600s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(3600);
    baseline->set_unit(Baseline::BPS);
    // pps 3600s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(3600);
    baseline->set_unit(Baseline::PPS);
    // fps 3600s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(3600);
    baseline->set_unit(Baseline::FPS);

    // bps 86400s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(86400);
    baseline->set_unit(Baseline::BPS);
    // pps 86400s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(86400);
    baseline->set_unit(Baseline::PPS);
    // fps 86400s
    baseline = slot->add_baselines();
    baseline_id = next_available_baseline_id_;
    ++next_available_baseline_id_;
    baseline->set_id(baseline_id);
    baseline->set_interval(86400);
    baseline->set_unit(Baseline::FPS);
  }
  return true;
}

