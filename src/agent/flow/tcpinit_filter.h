#ifndef __AGENT_TCPINIT_FILTER_H__
#define __AGENT_TCPINIT_FILTER_H__

#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/feature.pb.h"
#include "../../common/slice.h"
#include "../data/dbctx.h"
#include "../data/tsdb.h"
#include "../model/feature_key.h"
#include "../dump/libnfdump.h"
#include "flow_filter.h"
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace std;
using namespace feature;

class TcpinitFilter : public FlowFilter {

 public:

  static TcpinitFilter* Create(u32 dev_id, const string& model,
                               DBBuilder* builder);

  ~TcpinitFilter() override {}
  bool CheckFlow(FlowPtr flow) override {return true;};
  static void UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<TcpinitFilter>& ptr, const string& model);
  void FilterTcpinit(const feature::FeatureReq& req, feature::FeatureResponse* resp);

 private:

  struct TcpinitStat {
    u32 first;
    u32 last;
    u64 flows;
    u64 pkts;
    u64 bytes;
  };

  TcpinitFilter(u32 dev_id, const string& model, std::unique_ptr<TSDB> tsdb);
  bool UpdateByFlow(std::vector<master_record_t>* flowset);
  bool UpdateByFlowV6(std::vector<master_record_t>* flowset);

  void UpdateTcpinits(u32 first, u32 last, u32 sip[], u32 dip[],
                   u16 dport, u64 pkts, u64 bytes);
  void InsertTcpinitToTSDB(const TvcKey&, const TcpinitStat&);
  void CheckTcpinit(const Slice& key, const Slice& val,
                    const feature::FeatureReq& req,
                    feature::FeatureResponse* resp);
  void AddRecord(const feature::FeatureReq& req,
                 const feature::FeatureRecord& new_rec,
                 feature::FeatureResponse* resp) const;

  u32 dev_id_;
  string model_;
  std::unique_ptr<TSDB> tsdb_;
  std::map<TvcKey, TcpinitStat> tcpinits_;
  std::map<u32, std::set<TvcKey>> caches_;
};

#endif // __AGENT_TCPINIT_FILTER_H__
