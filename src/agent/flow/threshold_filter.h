#ifndef __AGENT_THRESHOLD_FILTER_H__
#define __AGENT_THRESHOLD_FILTER_H__

#include <memory>
#include <string>
#include <vector>
#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/event.pb.h"
#include "../../common/event_feature.pb.h"
#include "../config/cached_config.h"
#include "flow_filter.h"
#include "mo_filter.h"

using namespace std;
using config::Event;
using event::GenEventRecord;
using namespace eventfeature;

class ThresholdFilter : public FlowFilter {
 public:
  static ThresholdFilter* Create(
      CachedConfig* config, const config::Event& event_config, u32 dev_id, const string& model,
      u32 start_time, u32 end_time, DBBuilder* event_builder);

  ~ThresholdFilter() override {}

  bool CheckFlow(FlowPtr flow) override {return false;}

  // Generate an event if exceeds threshold.
  static event::GenEventRes CheckThreshold(std::vector<master_record_t>* flowset, unique_ptr<ThresholdFilter>& ptr, const string& model);
  void FilterMoEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);
  
 private:
  struct TiKey {
    u32 lip[4];
    u32 tip[4];
    u16 tport;
    u16 proto;
    bool operator<(const TiKey& k) const {
      return memcmp(this, &k, sizeof(k)) < 0;
    }
    bool operator==(const TiKey& s) const {
     return lip[0] == s.lip[0] && lip[1] == s.lip[1] && lip[2] == s.lip[2] && lip[3] == s.lip[3] && 
            tip[0] == s.tip[0] && tip[1] == s.tip[1] && tip[2] == s.tip[2] && tip[3] == s.tip[3] &&
            proto == s.proto && tport == s.tport;
    }
  };

  struct TiStat {
    u32 first;
    u32 last;
    u64 pkts;
    u64 bytes;
    u64 flows;
  };

  struct EventKey {
    u32 sip[4];
    u16 sport;
    u32 dip[4];
    u16 dport;
    u16 proto;
    u32 time;
    u32 type;
    u32 model;
    char obj[120];
    bool operator<(const EventKey& k) const {
      return memcmp(this, &k, sizeof(k)) < 0;
    }
  };

  struct EventValue{
    u32 first;
    u32 last;
    u64 flows;
    u64 bytes;
    u64 pkts;
  };

  ThresholdFilter(const config::Event& event_config, u32 dev_id, const string& model,
                       u32 start_time, u32 end_time,
                       std::unique_ptr<MOFilter> mo_filter);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateThreshold(FlowPtr flow);
  bool UpdateThresholdV6(FlowPtr flow);
  bool ExceedThreshold(double value, double* thres_value);
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const TiKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckMoEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);

  config::Event event_config_;
  u32 dev_id_;
  std::unique_ptr<TSDB> event_tsdb_;
  string model_;
  u32 start_time_;
  u32 end_time_;
  u64 bytes_;
  u64 pkts_;
  u64 flows_;
  std::unique_ptr<MOFilter> mo_filter_;
  string direction_;
  std::map<TiKey, TiStat> tis_;
  std::map<TiKey, std::map<EventKey, EventValue> >event_details_;
};

#endif // __AGENT_THRESHOLD_FILTER_H__

