#ifndef __AGENT_BW_FILTER_H__
#define __AGENT_BW_FILTER_H__

#include "flow_filter.h"
#include "../../common/common.h"
#include "../../common/policy.pb.h"
#include "../../common/event.pb.h"
#include "../model/model.h"
#include "../../common/feature.pb.h"
#include "../../common/event_feature.pb.h"
#include "../../common/config.pb.h"
#include "../model/feature_key.h"
#include "../data/tsdb.h"
#include "../data/dbctx.pb.h"
#include "../data/dbctx.h"
#include "../dump/libnfdump.h"
#include <unordered_set>
#include <set>
#include <string>
#include <map>
#include <memory>
#include <utility>

#define INTERVAL 3600

using namespace std;
using namespace feature;
using namespace eventfeature;
using namespace config;
using namespace event;
 
class DBs;

class BWFilter : public FlowFilter {
 
 private: 
	struct BWStat;	
 public:
	bool is_black_list_ = false;
	struct EventGenerator {
		EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
	//	event::GenEventRecord* Generate(const BWKey&, const BWFilter::BWStat&);

    config::Event event_config;	
		u32 dev_id;
		u32 start_time;
		u32 end_time;
	};
	typedef std::vector<EventGenerator> EventGenerators;

  //EventGenerator* event_generators_;
  // Work as netflow filter.
  static BWFilter* Create(u32 devid, const policy::PolicyData& policy_data, DBBuilder* builder, 
                          DBBuilder* event_builder, const string& model, const string& label);
  // Update only.
  //static BWFilter* Create() { return NULL; }
	static BWFilter* Create(u32 devid, DBBuilder* builder, DBBuilder* event_builder, const string& model, const string& label);

  ~BWFilter() override {}

  bool CheckFlow(FlowPtr flow) override;
	static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<BWFilter>& ptr, const string& model);
	void FilterBwlist(const feature::FeatureReq& req, feature::FeatureResponse* resp);
	EventGenerators* event_generators() { return &event_generators_; }
  void Merge(const BWFilter& filter);
  void FilterBWEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);

 private:

	struct BWStat {
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

	BWFilter(u32 devid, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);
  bool UpdateBW(u32 first, u32 last, u32 sip, u16 sport, u32 dip, u16 dport, u16 proto, u64 pkts, u64 bytes, u8 tos);
  bool UpdateBW6(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, u64 pkts, u64 bytes, u8 tos);
	void InsertBWToTSDB(const BWKey&, const BWStat&);	
	void AddRecord(const BWKey& key, const FeatureRecord& new_rec);
	void CheckBwlist(const Slice& key, const Slice& value, const feature::FeatureReq& req);
	void GenerateEvents(const BWKey&, const BWStat&, event::GenEventRes* events);
  void DivideMode();
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const BWKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckBWEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);


 // bool is_black_list_ = false;
  u32 devid_;
  string model_;
	std::unique_ptr<TSDB> tsdb_;
	std::unique_ptr<TSDB> event_tsdb_;
	std::map<BWKey, BWStat> bws_;
	std::map<BWKey, FeatureResponse> res_bws_;
	EventGenerators event_generators_;
	std::vector<event::GenEventRecord*> events_;
  std::unordered_set<u32> ips_;
  std::unordered_set<string> ips6_;
 // std::unordered_set<u16> ports_;
 // std::set<std::pair<u32, u32>> ip_pip_pairs_;
//  std::set<std::pair<u32, u16>> ip_port_pairs_;
 // std::set<std::pair<u32, u16>> ip_pport_pairs_;
  std::map<BWKey, std::map<EventKey, EventValue> >event_details_;
};

#endif // __AGENT_BW_FILTER_H__
