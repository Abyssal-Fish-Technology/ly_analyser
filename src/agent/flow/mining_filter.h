#ifndef __AGENT_MINING_FILTER_H__
#define __AGENT_MINING_FILTER_H__

#include "../../common/common.h"
#include "../../common/csv.hpp"
#include "../../common/config.pb.h"
#include "../../common/feature.pb.h"
#include "../../common/event_feature.pb.h"
#include "../../common/slice.h"
#include "../../common/feature.pb.h"
#include "../../common/event.pb.h"
#include "../../common/config.pb.h"
#include "../data/dbctx.h"
#include "../data/tsdb.h"
#include "../model/feature_key.h"
#include "../dump/libnfdump.h"
#include "../define.h"
#include "flow_filter.h"
#include "boost/regex.hpp"
#include <boost/algorithm/string.hpp>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <unordered_set>

#define COIN_NAME_LEN 32

using namespace feature;
using namespace eventfeature;
using namespace config;
using namespace event;
using namespace std;
using namespace boost;

class MiningFilter : public FlowFilter {

 public:

  struct EventGenerator {
    EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
    config::Event event_config;
    u32 dev_id;
    u32 start_time;
    u32 end_time;
  };
  typedef std::vector<EventGenerator> EventGenerators;

  static MiningFilter* Create(u32 dev_id, const string& model,
                               DBBuilder* builder, DBBuilder* event_builder);

  ~MiningFilter() override {}
  bool CheckFlow(FlowPtr flow) override {return true;}
  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<MiningFilter>& ptr, const string& model);
  void FilterMining(const feature::FeatureReq& req, feature::FeatureResponse* resp);
  EventGenerators* event_generators() { return &event_generators_; }
  void FilterMiningEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);

 private:

  struct MiningKey {
    u32 sip[4];
    u32 dip[4];
    u16 proto;
    u64 model;
    char domain[MAX_DOMAIN_LEN];
    //char fp_type[FP_TYPE_LEN];
    char coin_name[FP_TYPE_LEN];
    bool operator<(const MiningKey& k) const {
      return memcmp(this, &k, sizeof(k)) < 0;
    }
    bool operator==(const MiningKey& s) const {
      return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] && 
            dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] && proto == s.proto &&
            model == s.model && !strcmp(coin_name, s.coin_name) && !strcmp(domain, s.domain);
    }
  };

  struct MiningStat {
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
    char domain[MAX_DOMAIN_LEN]; 
    char coin_name[COIN_NAME_LEN];
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

  MiningFilter(u32 dev_id, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);

  void UpdateMining(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, 
              char *qname, u8 tos, char* threat_type, char* threat_name, u64 threat_time, u64 pkts, u64 bytes);
  void InsertMiningToTSDB(const MiningKey&, const MiningStat&);
  void CheckMining(const Slice& key, const Slice& val, const feature::FeatureReq& req);
  void AddRecord(const MiningKey& key, const feature::FeatureRecord& new_rec);
  void GenerateEvents(const MiningKey&, const MiningStat&, event::GenEventRes* events, EventGenerator& gen);
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const MiningKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckMiningEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);

  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::unique_ptr<TSDB> event_tsdb_;
  std::map<MiningKey, MiningStat> cap_mining_;
  std::map<MiningKey, MiningStat> dns_mining_;
  std::map<MiningKey, MiningStat> ti_mining_;
  std::map<MiningKey, FeatureResponse> res_mining_;
  EventGenerators event_generators_;
  std::map<string, vector<string> > domains_;
  std::map<string, vector<string> > ips_;
  std::map<MiningKey, std::map<EventKey, EventValue> > event_details_;
};

#endif // __AGENT_MINING_FILTER_H__
