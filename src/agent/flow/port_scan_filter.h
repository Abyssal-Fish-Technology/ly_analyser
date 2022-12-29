#ifndef __AGENT_PORT_SCAN_FILTER_H__
#define __AGENT_PORT_SCAN_FILTER_H__

#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/event.pb.h"
#include "../../common/feature.pb.h"
#include "../../common/event_feature.pb.h"
#include "../../common/slice.h"
#include "../data/dbctx.h"
#include "../data/tsdb.h"
#include "../model/feature_key.h"
#include "../model/model.h"
#include "../dump/libnfdump.h"
#include "flow_filter.h"
#include <map>
#include <memory>
#include <set>
#include <unordered_set>
#include <string>
#include <vector>

#define INTERVAL 3600

using namespace std;
using namespace feature;
using namespace eventfeature;
using event::GenEventRes;
using event::GenEventRecord;

class PortScanFilter : public FlowFilter {

 public:
  struct EventGenerator {
    EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
    config::Event event_config;
    u32 dev_id;
    u32 start_time;
    u32 end_time;
  };
  typedef std::vector<EventGenerator> EventGenerators;

  static PortScanFilter* Create(u32 dev_id, const string& model,
                               DBBuilder* builder, DBBuilder* event_builder);

  ~PortScanFilter() override {}
  bool CheckFlow(FlowPtr flow) override;
  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<PortScanFilter>& ptr, const string& model);
  void FilterScan(const feature::FeatureReq& req, feature::FeatureResponse* resp);
  void FilterScanEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);
  EventGenerators* event_generators() { return &event_generators_; }

 private:
  struct Conv {
    u32 ip[4];
    u16 proto;
    u16 peerport;
    u32 peerip[4];
    bool operator<(const Conv& c) const {
      return memcmp(this, &c, sizeof(Conv)) < 0;
    }
  };
  struct ScanStat {
    u32 first;
    u32 last;
    u64 peerip_count;
    u64 flows;
    u64 pkts;
    u64 bytes;
    char app_proto[APP_PROTO_LEN];
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

  PortScanFilter(u32 dev_id, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);

  void UpdateScans(u32 first, u32 last, u16 proto, u32 ip[], u16 port, u32 peerip[],
                   u16 peerport, char* pname, u64 pkts, u64 bytes);
  void InsertScanToTSDB(const PortScanKey&, const ScanStat&);
  void CheckScan(const Slice& key, const Slice& val, const feature::FeatureReq& req);
  void AddRecord(const PortScanKey& key, const feature::FeatureRecord& new_rec);
  void GenerateEvents(const PortScanKey&, const ScanStat&, event::GenEventRes* events);
	void DividePatterns(Pattern& pat, vector<string>& res);
  void Generate(const PortScanKey& s, const ScanStat& p, event::GenEventRes* events, Pattern& pat);
	void DivideMode();
	void GenerateFeature(const PortScanKey& s, const ScanStat& p);
	Match_res* Pickout(const PortScanKey& s, const ScanStat& p,
                     struct Match_res& result, vector<set<Pattern>>& models);
	bool LoadPatternFromFile();
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const PortScanKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckScanEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);

  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::unique_ptr<TSDB> event_tsdb_;
  std::set<Conv> convs_;
  std::map<PortScanKey, ScanStat> scans_;
  std::map<PortScanKey, feature::FeatureResponse> res_scan_;
  EventGenerators event_generators_;
  std::vector<event::GenEventRecord*> events_;
  std::map<u32, std::set<PortScanKey>> caches_;
  std::map<PortScanKey, std::map<EventKey, EventValue> >event_details_;

	std::set<Pattern> ip_port_proto_;
  std::set<Pattern> ip_port_;
  std::set<Pattern> ip_proto_;
  std::set<Pattern> port_proto_;
  std::set<Pattern> ip_;
  std::set<Pattern> port_;
  std::set<Pattern> proto_;
  std::set<Pattern> flows_;
};

#endif // __AGENT_PORT_SCAN_FILTER_H__
