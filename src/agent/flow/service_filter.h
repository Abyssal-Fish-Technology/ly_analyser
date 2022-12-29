#ifndef __AGENT_SERVICE_FILTER_H__
#define __AGENT_SERVICE_FILTER_H__

#include <set>
#include <map>
#include <memory>
#include <string>
#include <boost/algorithm/string.hpp>
#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/feature.pb.h"
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
using namespace std;
using namespace config;

class ServiceFilter : public FlowFilter {

 public:

  static ServiceFilter* Create(u32 dev_id, const string& model, DBBuilder* builder);

  ~ServiceFilter() override {}

  bool CheckFlow(FlowPtr flow) override;
  static void UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<ServiceFilter>& ptr, const string& model);
	void FilterService(const feature::FeatureReq& req, feature::FeatureResponse* resp);
	bool LoadPatternFromFile();
  
 private:
  struct PortStat {
    u32 first;
		u32 last;
		u64 flow_count;
		u64 pkts;
		u64 bytes;
    char app_proto[APP_PROTO_LEN];
  };

  ServiceFilter(u32 dev_id, const string& model, std::unique_ptr<TSDB> tsdb);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);
	void UpdateService(u32 first, u32 last, u32 sip[], u16 sport, u16 proto, u32 dip[], 
									 u16 dport, u8 tos, char* pname, u64 pkts, u64 bytes);
	void InsertSrvToTSDB(const PvcKey&, const PortStat&);
	void GenerateFeature(const PvcKey& s, const PortStat& p);
  void CheckService(const Slice& key, const Slice& value, const feature::FeatureReq& req);
	void AddRecord(const PvcKey& key, const feature::FeatureRecord& new_rec);
	void DividePatterns(Pattern& pat, vector<string>& res);	
  Match_res* Pickout(const PvcKey& s, const PortStat& p, struct Match_res& result);

	u32 dev_id_;
  string model_;	
	std::unique_ptr<TSDB> tsdb_;
  std::set<PvcKey> srvtos_;
  std::map<PvcKey, PortStat> srvres_;
  std::map<PvcKey, PortStat> srvreq_;
  std::map<PvcKey, feature::FeatureResponse> res_srv_;
	std::map<u32, std::set<PvcKey>> caches_;
  std::vector<string> type_ = {"SCAN", "SRV", "FORCE", "TUUNEL"};
};

#endif // __AGENT_SERVICE_FILTER_H__
