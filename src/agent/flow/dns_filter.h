#ifndef __AGENT_DNS_FILTER_H__
#define __AGENT_DNS_FILTER_H__

#include "../../common/common.h"
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
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <unordered_set>

#define MAXBWCLASSLEN 20

using namespace feature;
using namespace eventfeature;
using namespace config;
using namespace event;
using namespace std;
using namespace boost;

class DnsFilter : public FlowFilter {

 public:

  struct EventGenerator {
    EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
    config::Event event_config;
    u32 dev_id;
    u32 start_time;
    u32 end_time;
  };
  typedef std::vector<EventGenerator> EventGenerators;

  static DnsFilter* Create(u32 dev_id, const string& model,
                               DBBuilder* builder, DBBuilder* event_builder);

  ~DnsFilter() override {}
  bool CheckFlow(FlowPtr flow) override {return true;}
  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<DnsFilter>& ptr, const string& model);
  void FilterDns(const feature::FeatureReq& req, feature::FeatureResponse* resp);
  EventGenerators* event_generators() { return &event_generators_; }
  void FilterDnsEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);

 private:

  struct DnsStat {
    u32 first;
    u32 last;
    u64 flows;
    u64 pkts;
    u64 bytes;
    char bwclass[MAXBWCLASSLEN];  
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
    u16 qtype;
    char obj[120];
    char domain[MAX_DOMAIN_LEN]; 
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

  DnsFilter(u32 dev_id, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);

  void UpdateDns(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport,
                 u16 proto, char *qname, u16 qtype, u64 pkts, u64 bytes);
  void InsertDnsToTSDB(const DnsKey&, const DnsStat&);
  void CheckDns(const Slice& key, const Slice& val, const feature::FeatureReq& req);
  void AddRecord(const DnsKey& key, const feature::FeatureRecord& new_rec);
  void GenerateEvents(const DnsKey&, const DnsStat&, event::GenEventRes* events, EventGenerator& gen);
  bool JudgeSpecChar(const string& str);
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const DnsKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckDnsEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);

  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::unique_ptr<TSDB> event_tsdb_;
  std::map<DnsKey, DnsStat> dns_;
  std::map<DnsKey, FeatureResponse> res_dns_;
  std::map<u32, std::set<DnsKey>> caches_;
  EventGenerators event_generators_;
  std::map<string, string> domains_;
  std::map<DnsKey, std::map<EventKey, EventValue> > event_details_;
};

#endif // __AGENT_TCPINIT_FILTER_H__
