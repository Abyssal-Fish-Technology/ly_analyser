#ifndef __AGENT_ICMP_TUNNEL_H__
#define __AGENT_ICMP_TUNNEL_H__

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
#include "boost/regex.hpp"
#include "flow_filter.h"
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <unordered_set>

#define INTERVAL 3600

using namespace feature;
using namespace config;
using namespace event;
using namespace std;
using namespace boost;
using namespace eventfeature;

class IcmpTunnelFilter : public FlowFilter {

 public:

  struct EventGenerator {
    EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
    config::Event event_config;
    u32 dev_id;
    u32 start_time;
    u32 end_time;
  };
  typedef std::vector<EventGenerator> EventGenerators;

  static IcmpTunnelFilter* Create(u32 dev_id, const string& model, 
                               DBBuilder* builder, DBBuilder* event_builder);

  ~IcmpTunnelFilter() override {}
  bool CheckFlow(FlowPtr flow) override {return true;}
  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<IcmpTunnelFilter>& ptr, const string& model);
  void FilterIcmpTunnel(const feature::FeatureReq& req, feature::FeatureResponse* resp);
  EventGenerators* event_generators() { return &event_generators_; }
  void FilterIcmptunEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);

 private:

  struct IcmpTunStat {
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
    u8 icmp_type;
    char obj[120];
    char icmp_data[128];
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

  IcmpTunnelFilter(u32 dev_id, const string& model);

  void UpdateIcmpTunnel(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, char* payload,
                        u8 tos, u16 seq, u32 payload_len, u64 pkts, u64 bytes);
  void InsertIcmpTunToTSDB(const IcmpTunKey&, const IcmpTunStat&);
  void CheckIcmpTunnel(const Slice& key, const Slice& val, const feature::FeatureReq& req);
  void AddRecord(const IcmpTunKey& key, const feature::FeatureRecord& new_rec);
  void GenerateEvents(const IcmpTunKey&, const IcmpTunStat&, event::GenEventRes* events, EventGenerator& gen);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const IcmpTunKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckIcmptunEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);

  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::unique_ptr<TSDB> event_tsdb_;
  std::map<IcmpTunKey, FeatureResponse> res_icmp_;
  std::map<IcmpTunKey, std::set<string> > icmp_cons_; //统计payload去重个数
  std::map<IcmpTunKey, std::set<u32> > payload_len_; //统计payload长度去重个数
  std::map<IcmpTunKey, IcmpTunStat> icmp_;
  std::map<IcmpTunKey, set<u8> > abnormal_type_;  //统计异常type
  std::map<IcmpTunKey, set<string> > abnormal_type_payload_; //异常type对应的payload
  std::map<IcmpTunKey, map<u16, std::pair<u32, u32> > > req_reply_; //统计同一sequence num下请求和响应的个数
  std::map<IcmpTunKey, map<u16, set<string> > > seq_payload_;   //统计同一sequence num下请求和响应的payload
  EventGenerators event_generators_;
  std::map<IcmpTunKey, std::map<EventKey, EventValue> > event_details_;
};

#endif // __AGENT_ICMP_TUNNEL_H__
