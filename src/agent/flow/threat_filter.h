#ifndef __AGENT_THREAT_FILTER_H__
#define __AGENT_THREAT_FILTER_H__

#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/event.pb.h"
#include "../../common/feature.pb.h"
#include "../../common/event_feature.pb.h"
#include "../../common/slice.h"
#include "../data/dbctx.h"
#include "../data/tsdb.h"
#include "../model/feature_key.h"
#include "../dump/libnfdump.h"
#include "flow_filter.h"
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace std;
using namespace feature;
using namespace eventfeature;
using namespace event;

class ThreatFilter : public FlowFilter {

 public:
  struct EventGenerator {
    EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
    config::Event event_config;
    u32 dev_id;
    u32 start_time;
    u32 end_time;
  };
  typedef std::vector<EventGenerator> EventGenerators;
  // static ThreatFilter* Create(u32 dev_id, const string& model, DBBuilder* builder);
  static ThreatFilter* Create(u32 dev_id, const string& model, DBBuilder* builder, DBBuilder* event_builder);

  ~ThreatFilter() override {}
  bool CheckFlow(FlowPtr flow) override {return true;};
  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<ThreatFilter>& ptr, const string& model);
  void FilterThreat(const feature::FeatureReq& req, feature::FeatureResponse* resp);
  EventGenerators* event_generators() { return &event_generators_; }
  void FilterThreatEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);

 private:

  struct ThreatStat {
    u32 first;
    u32 last;
    u64 flows;
    u64 pkts;
    u64 bytes;
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
    char captype[32];
    char capname[32];
    char capvers[16];
    u64 capusec;
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

  ThreatFilter(u32 dev_id, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);

  void UpdateThreats(u32 first, u32 last, u32 sip[], u16 sport, u8 proto, u32 dip[], u16 dport, char* url, char* host, char* threat_type, char* threat_name, char* threat_vers, u64 threat_time, u64 pkts, u64 bytes);
  void InsertThreatToTSDB(const ThreatKey&, const ThreatStat&);
  void CheckThreat(const Slice& key, const Slice& val, const feature::FeatureReq& req);
  void AddRecord(const ThreatKey& key, const feature::FeatureRecord& new_rec);
  void GenerateEvents(const ThreatKey& s, const ThreatStat& p, GenEventRes* events, EventGenerator& gen);

  void AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp);
  void CheckThreatEvent(const Slice& key, const Slice& value, const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);
  void GenEventFeature(const ThreatKey& s, const event::GenEventRecord* e);
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);


  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::unique_ptr<TSDB> event_tsdb_;
  std::map<ThreatKey, ThreatStat> threats_;
  std::map<ThreatKey, feature::FeatureResponse> res_threat_;
  std::map<u32, std::set<ThreatKey>> caches_;
  EventGenerators event_generators_;
  std::vector<event::GenEventRecord*> events_;
  std::map<ThreatKey, std::map<EventKey, EventValue> >event_details_;

};

#endif // __AGENT_THREAT_FILTER_H__
