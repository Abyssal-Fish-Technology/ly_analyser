#ifndef __AGENT_ASSET_SRV_FILTER_H__
#define __AGENT_ASSET_SRV_FILTER_H__

#include <set>
#include <map>
#include <memory>
#include <string>
#include <boost/algorithm/string.hpp>
#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/feature.pb.h"
#include "../../common/event_feature.pb.h"
#include "../../common/event.pb.h"
#include "../../common/strings.h"
#include "../../common/ip.h"
#include "../config/cached_config.h"
#include "../data/tsdb.h"
#include "../model/feature_key.h"
#include "../model/model.h"
#include "../data/dbctx.h"
#include "../../common/slice.h"
#include "flow_filter.h"
#include "mo_filter.h"

#define INTERVAL 3600

using namespace feature;
using namespace eventfeature;
using namespace std;
using namespace config;
using namespace boost;

class AssetsrvFilter : public FlowFilter {
 private:struct PortStat;

 public:

	struct EventGenerator {
		EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
		config::Event event_config;
		u32 dev_id;
		u32 start_time;
		u32 end_time;
	};
	
	typedef std::vector<EventGenerator> EventGenerators;

  static AssetsrvFilter* Create( u32 dev_id, const string& model,
      														DBBuilder* builder, DBBuilder* event_builder);

  ~AssetsrvFilter() override {}

  bool CheckFlow(FlowPtr flow) override;
  static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<AssetsrvFilter>& ptr, 
                                           const string& model, std::set<string>& asset_ips);
	void FilterService(const feature::FeatureReq& req, feature::FeatureResponse* resp);
	void FilterServiceEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp);
	EventGenerators* event_generators() { return &event_generators_; }
  
 private:
  struct PortStat {
    u32 first;
		u32 last;
		u64 flow_count;
		u64 pkts;
		u64 bytes;
    u64 srv_time;
    u64 os_time;
    u64 dev_time;
    u64 midware_time;
    char app_proto[APP_PROTO_LEN];
    char srv_type[32];
    char srv_name[32];
    char srv_version[16];
    char dev_type[32];
    char dev_name[32];
    char dev_vendor[32];
    char dev_model[16];
    char os_type[32];
    char os_name[32];
    char os_version[16];
    char midware_type[32];
    char midware_name[32];
    char midware_version[16];
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
  

  AssetsrvFilter(u32 dev_id, const string& model);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);
  void UpdateService(u32 first, u32 last, u32 sip[], u16 sport, u16 proto, u32 dip[],
                     u16 dport, u8 tos, char* pname, u64 pkts, u64 bytes, char* service_type,
                     char* service_name, char* service_version, char* dev_type, char* dev_name,
                     char* dev_vendor, char* dev_model, char* os_type, char* os_name, char* os_version,
                     char* midware_type, char* midware_name, char* midware_version,
                     u64 srv_time, u64 dev_time, u64 os_time, u64 midware_time);
	void InsertSrvToTSDB(const PvcKey&, const PortStat&);
	void GenerateEvents(const PvcKey&, const PortStat&, event::GenEventRes* events);
  void GenerateFeature(const PvcKey& s, const PortStat& p);
  void CheckService(const Slice& key, const Slice& value, const feature::FeatureReq& req);
	void AddRecord(const PvcKey& key, const FeatureRecord& new_rec);	
	void DividePatterns(Pattern& pat, vector<string>& res);	
  void Generate(const PvcKey& s, const PortStat& p, event::GenEventRes* events, Pattern& pat);
	void DivideMode();
  Match_res* Pickout(const PvcKey& s, const PortStat& p, struct Match_res& result, vector<set<Pattern>>& models);
	bool LoadPatternFromFile();
  void InsertEventToTSDB(const EventKey& s, const EventValue& p);
  void GenEventFeature(const PvcKey& s, const event::GenEventRecord* e); 
  void AddEventRecord(const eventfeature::EventFeatureRecord& new_rec, eventfeature::EventFeatureResponse* resp);
  void CheckServiceEvent(const Slice& key, const Slice& value, 
                         const eventfeature::EventFeatureReq& req,
                         eventfeature::EventFeatureResponse* resp);


	u32 dev_id_;
  string model_;	
	std::unique_ptr<TSDB> tsdb_;
	std::unique_ptr<TSDB> event_tsdb_;
	EventGenerators event_generators_;
	std::vector<event::GenEventRecord*> events_;
  std::set<PvcKey> srvtos_;
  std::map<PvcKey, PortStat> srvreq_;
  std::map<PvcKey, PortStat> srvres_;
	std::map<u32, std::set<PvcKey>> caches_;
  std::map<PvcKey, FeatureResponse> res_srvs_;
  std::map<PvcKey, std::map<EventKey, EventValue> >event_details_; 

	std::set<Pattern> ip_port_proto_;
  std::set<Pattern> ip_port_;
  std::set<Pattern> ip_proto_;
  std::set<Pattern> port_proto_;
  std::set<Pattern> ip_;
  std::set<Pattern> port_;
  std::set<Pattern> proto_;
  std::set<Pattern> flows_;
  std::vector<string> type_ = {"SCAN", "SRV", "FORCE", "TUUNEL"};
};

#endif // __AGENT_SERVICE_FILTER_H__
