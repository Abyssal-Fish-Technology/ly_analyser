#ifndef __AGENT_MO_FILTER_H__
#define __AGENT_MO_FILTER_H__

#include <memory>
#include <string>
#include <vector>
#include <map>
#include "../../common/common.h"
#include "../dump/libnfdump.h"
#include "../../common/feature.pb.h"
#include "../../common/mo.pb.h"
#include "../../common/slice.h"
#include "../data/dbctx.h"
#include "../data/tsdb.h"
#include "../define.h"
#include "../config/cached_config.h"
#include "../model/feature_key.h"
#include "flow_filter.h"
#include <set>

#define INTERVAL 3600

using namespace std;
using namespace feature;
using namespace mo;

class MOFilter : public FlowFilter {
 public:
  
  CachedConfig* config_; // Do not own.
  // Work as flow filter.
  static MOFilter* Create(CachedConfig* config,
                          u32 devid,
                          const std::string& mo_id_list,
                          const std::string& additional_filter);
  static MOFilter* Create(CachedConfig* config, u32 devid, DBBuilder* builder);
  ~MOFilter() override;
  bool CheckFlow(FlowPtr flow) override;
  bool UpdateByFlow(std::vector<master_record_t>* flowset_);
  static void UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<MOFilter>& ptr);
  void FilterMO(const feature::FeatureReq& req, feature::FeatureResponse* resp);
  
  
 private:
  struct MOStat {
    u32 first;
    u32 last;
    u64 flows;
    u64 bytes;
    u64 pkts;
    u64 peak_flows;
    u64 peak_bytes;
    u64 peak_pkts;
  };

  MOFilter(CachedConfig* config, u32 devid, std::unique_ptr<TSDB> tsdb);
  MOFilter(CachedConfig* config, u32 devid);
  void InsertMOToTSDB(const MOKey& s, const MOStat& p);
  bool UpdateMo(FlowPtr flow);
  bool InitInternal(const std::string& mo_id_list);
  bool AddFilter(const std::string& filter);
  void CheckMO(const Slice& key, const Slice& val, const feature::FeatureReq& req);
  void AddRecord(const MOKey& key, const feature::FeatureRecord& new_rec);
  void GetAllMoIds(std::vector<u32>* ids);
  void GetMoIdsOfGroupid(std::vector<u32>* ids, u32 groupid);

  typedef std::vector<CompiledFilter*> CompiledFilters;

  //CachedConfig* config_; // Do not own.
  u32 devid_;
  std::unique_ptr<TSDB> tsdb_;
  std::map<MOKey, MOStat> mo_;
  std::map<MOKey, FeatureResponse> res_mo_;
  CompiledFilters filters_;
  std::map<u32, unique_ptr<CompiledFilter> > compilers_;
  //std::map<u32, CompiledFilter*> compilers_;
};

#endif // __AGENT_MO_FILTER_H__

