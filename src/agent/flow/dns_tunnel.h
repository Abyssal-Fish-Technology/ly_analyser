#ifndef __AGENT_DNS_TUNNEL_H__
#define __AGENT_DNS_TUNNEL_H__

#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/feature.pb.h"
#include "../../common/slice.h"
#include "../../common/feature.pb.h"
#include "../../common/event_feature.pb.h"
#include "../../common/event.pb.h"
#include "../../common/config.pb.h"
#include "../data/dbctx.h"
#include "../data/tsdb.h"
#include "../model/feature_key.h"
#include "../dump/libnfdump.h"
#include "../define.h"
#include "boost/regex.hpp"
#include "flow_filter.h"
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <unordered_set>

using namespace feature;
using namespace eventfeature;
using namespace config;
using namespace event;
using namespace std;
using namespace boost;

class DnstunnelFilter : public FlowFilter {

 public:

  struct EventGenerator {
    EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
    config::Event event_config;
    u32 dev_id;
    u32 start_time;
    u32 end_time;
  };
  typedef std::vector<EventGenerator> EventGenerators;

  static DnstunnelFilter* Create(u32 dev_id, const string& model, 
                               DBBuilder* builder, DBBuilder* event_builder);

  ~DnstunnelFilter() override {}
  bool CheckFlow(FlowPtr flow) override {return true;}
  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<DnstunnelFilter>& ptr, const string& model);
  void FilterDnstunnel(const feature::FeatureReq& req, feature::FeatureResponse* resp);
  EventGenerators* event_generators() { return &event_generators_; }
  void FilterDnsTunEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);

 private:

  struct DtStat {
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
    u16 qtype;
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

  DnstunnelFilter(u32 dev_id, const string& model);

  void UpdateDnstunnel(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto,
                       char *qname, u16 qtype, u64 pkts, u64 bytes);
  void InsertDnstunnelToTSDB(const DtKey&, const DtStat&);
  void CheckDnstunnel(const Slice& key, const Slice& val, const feature::FeatureReq& req);
  void AddRecord(const DtKey& key, const feature::FeatureRecord& new_rec);
  void GenerateEvents(const DtKey&, const DtStat&, event::GenEventRes* events, EventGenerator& gen);
  double DomainEntropy(const string& domain);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const DtKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckDnsTunEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);

  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::unique_ptr<TSDB> event_tsdb_;
  EventGenerators event_generators_;
  std::map<DtKey, map<string, DtStat> > all_fp_;
  std::unordered_set<string> white_domains_;
  std::set<string> whole_domain_;
  std::map<DtKey, FeatureResponse> res_dns_;
  std::map<DtKey, std::map<EventKey, EventValue> > event_details_; //记录事件五元组详细信息
};

#endif // __AGENT_TCPINIT_FILTER_H__
