#ifndef __AGENT_IP_SET_FILTER_H__
#define __AGENT_IP_SET_FILTER_H__

#include "../../common/common.h"
#include "../data/dbctx.h"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include "../model/feature_key.h"
#include "../model/model.h"
#include "../../common/feature.pb.h"
#include "../../common/event_feature.pb.h"
#include "../../common/event.pb.h"
#include "../../common/config.pb.h"
#include "../dump/libnfdump.h"
#include "flow_filter.h"
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>

#define INTERVAL 3600
#define MAXBWCLASSLEN 20

using namespace feature;
using namespace eventfeature;
using namespace config;
using namespace std;
using namespace event;

class IPSetFilter : public FlowFilter {

 public:
	bool is_popular_service_ = false;
	struct EventGenerator {
		EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);

    config::Event event_config;
		u32 dev_id;
		u32 start_time;
		u32 end_time;
	};
	typedef std::vector<EventGenerator> EventGenerators;

  static IPSetFilter* Create(u32 devid, DBBuilder* builder, DBBuilder* event_builder, const string& model,
                             const std::string& label);
  // Update only.
  static IPSetFilter* Create(u32 devid, DBBuilder* builder, DBBuilder* event_builder, const string& model,
                             const std::string& label, const std::string& unfiltered_ip_csv_file);

  ~IPSetFilter() override {};
  bool CheckFlow(FlowPtr flow) override;
	void FilterIPSets(const feature::FeatureReq& req, feature::FeatureResponse* resp);
	static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<IPSetFilter>& ptr, const string& model);
	EventGenerators* event_generators() { return &event_generators_; }
  void FilterSusEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);

 private:
	struct IPsetStat {
		u32 first;
    u32 last;
		u64 flows;
		u64 pkts;
		u64 bytes;
    char bwclass[MAXBWCLASSLEN];
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

  IPSetFilter(u32 devid, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);
  bool UpdateIpset(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, u8 tos, u64 pkts, u64 bytes, char* pname);
  bool UpdateIpsetV6(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, u8 tos, u64 pkts, u64 bytes, char* pname);
	void InsertIPsetToTSDB(const IPsetKey& s, const IPsetStat& stat);
  void LoadUnfilteredIPs(const std::string& file_name);
	void CheckIPSet(const Slice& key, const Slice& value, const feature::FeatureReq& req);
	void AddRecord(const IPsetKey& key, const feature::FeatureRecord& new_rec);
	void GenerateEvents(const IPsetKey&, const IPsetStat&, event::GenEventRes* events);	
  void DivideMode();
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const IPsetKey& s, const event::GenEventRecord* e);
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckSusEvent(const Slice& key, const Slice& value,
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);

  u32 devid_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::unique_ptr<TSDB> event_tsdb_;
  std::map<u32, string> unfiltered_ips_;
  std::map<string, string> unfiltered_ips6_;
  // packed with time, ip
	std::map<IPsetKey, IPsetStat> ipset_;
	std::map<IPsetKey, FeatureResponse> res_ips_;
  std::map<u32, std::set<string>> caches_;
	EventGenerators event_generators_;
	std::vector<event::GenEventRecord*> events_;
  std::map<IPsetKey, std::map<EventKey, EventValue> >event_details_;
};

#endif // __AGENT_IP_SET_FILTER_H__
