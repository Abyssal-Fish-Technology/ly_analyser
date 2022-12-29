#ifndef __AGENT_DGA_FILTER_H__
#define __AGENT_DGA_FILTER_H__

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
#include "flow_filter.h"
#include "boost/regex.hpp"
#include <tensorflow/cc/client/client_session.h>
#include <tensorflow/cc/ops/standard_ops.h>
#include <tensorflow/core/framework/tensor.h>
#include <tensorflow/core/public/session.h>
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
using namespace tensorflow;

class DgaFilter : public FlowFilter {

 public:

  struct EventGenerator {
    EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
    config::Event event_config;
    u32 dev_id;
    u32 start_time;
    u32 end_time;
  };
  typedef std::vector<EventGenerator> EventGenerators;

  static DgaFilter* Create(u32 dev_id, const string& model, DBBuilder* builder, DBBuilder* event_builder);

  ~DgaFilter() override {}
  bool CheckFlow(FlowPtr flow) override {return true;}
  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<DgaFilter>& ptr, const string& model);
  void FilterDga(const feature::FeatureReq& req, feature::FeatureResponse* resp);
  EventGenerators* event_generators() { return &event_generators_; }
  void FilterDgaEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);

 private:

  struct DgaStat {
    u32 first;
    u32 last;
    u64 flows;
    u64 pkts;
    u64 bytes;
    float score;
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
    float score;
    u64 dga_cnt;
  };

  struct EventSumKey {
    u32 sip[4];
    u32 dip[4];
    u32 index; //记录配置event_generators_中的下标
    bool operator<(const EventSumKey& k) const {
      return memcmp(this, &k, sizeof(k)) < 0;
    }
    bool operator==(const EventSumKey& s) const {
     return sip[0] == s.sip[0] && sip[1] == s.sip[1] && sip[2] == s.sip[2] && sip[3] == s.sip[3] &&
            dip[0] == s.dip[0] && dip[1] == s.dip[1] && dip[2] == s.dip[2] && dip[3] == s.dip[3] && 
            index == s.index;
  }
  };

  DgaFilter(u32 dev_id, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);

  void UpdateDga(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto,
            char *qname, u64 pkts, u64 bytes);
  void InsertDgaToTSDB(const DgaKey&, const DgaStat&);
  void CheckDga(const Slice& key, const Slice& val, const feature::FeatureReq& req);
  void AddRecord(const DgaKey& key, const feature::FeatureRecord& new_rec);
  void GenerateEvents(const EventSumKey&, const EventValue&, event::GenEventRes* events);
  bool JudgeSpecChar(const string& str);
  bool IsDgaDomain();
  tensorflow::Tensor Domain2Tensor(const vector<string>& domains);
  bool CreateSession();
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckDgaEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);
  void GenEventFeature(const EventSumKey& s, const event::GenEventRecord* e);
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);


  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::unique_ptr<TSDB> event_tsdb_;
  std::map<DgaKey, DgaStat> dga_;
  std::map<DgaKey, FeatureResponse> res_dga_;
  std::map<u32, std::set<DgaKey>> caches_;
  EventGenerators event_generators_;
  std::map<string, float> domains_;
  std::unordered_set<string> not_tld_;
  std::unique_ptr<tensorflow::Session> session_;
  std::map<EventSumKey, EventValue> all_events_;
  std::map<DgaKey, std::map<EventKey, EventValue> > event_details_;
};

#endif // __AGENT_DGA_FILTER_H__
