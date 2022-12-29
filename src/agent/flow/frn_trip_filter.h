#ifndef __AGENT_FRN_TRIP_FILTER_H__
#define __AGENT_FRN_TRIP_FILTER_H__

#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/event.pb.h"
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
using namespace event;
using namespace eventfeature;

class FrnTripFilter : public FlowFilter {

 public:

  struct EventGenerator {
    EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
    config::Event event_config;
    u32 dev_id;
    u32 start_time;
    u32 end_time;
  };
  typedef std::vector<EventGenerator> EventGenerators;

  static FrnTripFilter* Create(u32 dev_id, const string& model, DBBuilder* event_builder);

  ~FrnTripFilter() override {}

  bool CheckFlow(FlowPtr flow) override {return true;}

  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<FrnTripFilter>& ptr, const string& model, std::set<string>& asset_ips);

  EventGenerators* event_generators() { return &event_generators_; }
  void FilterFrnTripEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);


  //tcpinit key
  struct FrnTripKey {
    u32 sip[4], dip[4];
    u16 dport;
    bool operator<(const FrnTripKey& k) const {
      return memcmp(this, &k, sizeof(k)) < 0;
    }
    bool operator==(const FrnTripKey& s) const {
       return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
              dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] &&
              dport == s.dport;
    }
  };

 private:

  struct FrnTripStat {
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

  FrnTripFilter(u32 dev_id, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);
  void UpdateFrnTrip(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dstport, u16 proto, u64 pkts, u64 bytes);
  void GenerateEvents(const FrnTripKey&, const FrnTripStat&, event::GenEventRes* events, EventGenerator& gen);
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const FrnTripKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckFrnTripEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);

  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> event_tsdb_;
  std::map<FrnTripKey, FrnTripStat> frntrips_;
  EventGenerators event_generators_;
  std::map<u32, std::set<FrnTripKey>> caches_;
  config::Config cfg_;
  std::map<FrnTripKey, std::map<EventKey, EventValue> >event_details_;
};

#endif // __AGENT_FRN_TRIP_FILTER_H__
