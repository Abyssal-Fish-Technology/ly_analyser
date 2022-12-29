#ifndef __AGENT_URL_CONTENT_FILTER_H__
#define __AGENT_URL_CONTENT_FILTER_H__

#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/feature.pb.h"
#include "../../common/slice.h"
#include "../../common/csv.hpp"
#include "../../common/ip.h"
#include "../../common/log.h"
#include "../../common/asset.h"
#include "../../common/strings.h"
#include "../../common/datetime.h"
#include "../../common/common_filter.hpp"
#include "../../common/feature.pb.h"
#include "../../common/event.pb.h"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include "../data/dbctx.h"
#include "../data/tsdb.h"
#include "../define.h"
#include "../model/feature_key.h"
#include "../dump/libnfdump.h"
#include "boost/regex.hpp"
#include "flow_filter.h"
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <unordered_set>

using namespace std;
using namespace feature;
using namespace config;
using namespace event;
using namespace boost;

class UrlContentFilter : public FlowFilter {
  public:
    struct EventGenerator {
      EventGenerator(){}
      EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et);
      //EventGenerator(const EventGenerator& obj);
      config::Event event_config;
      u32 dev_id;
      u32 start_time;
      u32 end_time;
    };
    typedef std::vector<EventGenerator> EventGenerators;
    static UrlContentFilter* Create(u32 dev_id, const string& model, DBBuilder* builder);
    ~UrlContentFilter() {}
    bool CheckFlow(FlowPtr flow) override {return true;}
    static event::GenEventRes UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<UrlContentFilter>& ptr,
                               const string& model, set<string>& asset_ips);
    void FilterUrlCon(const feature::FeatureReq& req, feature::FeatureResponse* resp);
    EventGenerators* event_generators() { return &event_generators_; } 
 
  private:
    struct UrlConStat {
      u32 first;
      u32 last;
      u64 flows;
      u64 pkts;
      u64 bytes;
      config::Event_Ctype type;
      u32 config_id;
    };

    UrlContentFilter(u32 dev_id, const string& model, std::unique_ptr<TSDB> tsdb);
    bool UpdateByFlow(std::vector<master_record_t>* flowset);
    bool UpdateByFlowV6(std::vector<master_record_t>* flowset);
    void UpdateUrlCon(u32 first, u32 last, u32 sip[], u32 dip[], u16 sport, u16 dport,
                       u8 tos, char* url, u16 retcode, u64 pkts, u64 bytes);
    //void InsertUrlConToTSDB(const UrlConKey&, const UrlConStat&);
    //void CheckUrlCon(const Slice& key, const Slice& val, const feature::FeatureReq& req);
    //void AddRecord(const UrlConKey& key, const feature::FeatureRecord& new_rec);
    //void GenerateFeature();
    void GenerateEvents(const UrlConKey&, const UrlConStat&, event::GenEventRes* events);
    bool MatchPattern(const string& str, const string& reg);
    void DivideType();

    u32 dev_id_;
    string model_;
    std::unique_ptr<TSDB> tsdb_;
    std::map<UrlConKey, UrlConStat> url_con_;
    std::map<UrlConKey, feature::FeatureResponse> res_urlcon_;
    EventGenerators event_generators_;
    std::map<u32, EventGenerator> event_conf_;
    std::map<UrlConKey, UrlConStat> flow_rec_;
};


#endif
