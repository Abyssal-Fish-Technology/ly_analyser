#include "flow_filter.h"

#include <memory>
#include <string>
#include <unordered_set>

#include "../../common/log.h"
#include "../../common/ip.h"
#include "../../common/strings.h"
#include "../../common/stringutil.h"
#include "../config/cached_config.h"
#include "../data/tsdb.h"
#include "../define.h"
#include "../model/policy.h"
#include "ip_set_filter.h"
#include "mo_filter.h"
#include "port_scan_filter.h"
#include "service_filter.h"
#include "bw_filter.h"
//#include "xdayypercent_filter.h"

using config::Config;

string kDefaultPopularServicePolicyLabel = "pop_service";
string kDefaultSuspectPolicyLabel = "sus_threat";

namespace {
bool ParseDevidFromEnv(u32* devid) {
  char* devid_cstr = getenv("DEVID");
  if (!devid_cstr || !strlen(devid_cstr)) return false;
  *devid = strtoul(devid_cstr, NULL, 10);
  return errno != ERANGE && *devid;
}
}

FlowFilters::FlowFilters() {}
FlowFilters::~FlowFilters() {}

class FlowFiltersImpl : public FlowFilters {
 public:
  FlowFiltersImpl();
  ~FlowFiltersImpl() override {}
  bool ParseOptArg(const string& optarg) override;
  bool CheckFlow(FlowFilter::FlowPtr flow) override;

 private:
  typedef unordered_set<unique_ptr<FlowFilter>> Filters;

  //void AddXDayYPercentFilter(u32 devid, const string& optarg);
  void AddFilters(u32 devid, const string& optarg);

  Filters* GetFilters(bool excluded) {
    return excluded ? &exclude_filters_ : &include_filters_;
  }

  unique_ptr<DBBuilder> db_builder_;
  Filters exclude_filters_;
  Filters include_filters_;
  unique_ptr<CachedConfig> config_;
};

FlowFiltersImpl::FlowFiltersImpl()
  : FlowFilters(), config_(CachedConfig::Create()) {
  DBCtxOptions options;
  options.set_read_only(true);
  db_builder_.reset(new DBBuilder(options, AGENT_DB_ROOT));
}
 
bool FlowFiltersImpl::ParseOptArg(const string& optarg) {
  u32 devid = 0;
  if (!ParseDevidFromEnv(&devid)) {
    log_err("Empty or wrong devid %d\n", devid);
    return false;
  }
  string devid_str = to_string(devid);

  if (DEBUG) log_info("DEVID=%u ParseOptArg %s\n", devid, optarg.c_str());

  AddFilters(devid, optarg);
  return true; 
}
/*
void FlowFiltersImpl::AddXDayYPercentFilter(u32 devid, const string& optarg) {
  auto i = optarg.find("=");
  if (i == string::npos) return;
  string key = optarg.substr(0, i);
  if (key != "xdayypercent_only" && key != "exclude_xdayypercent") return;

  bool excluded = key == "exclude_xdayypercent";
  auto& filters = excluded ? exclude_filters_ : include_filters_;
  string config_str = optarg.substr(strlen(
    excluded ? "exclude_xdayypercent=" : "xdayypercent_only="));
  
  auto filter = XDayYPercentFilter::Create(
    db_builder_.get(), to_string(devid) + "_xy", config_str);
  if (filter) filters.emplace(filter);
}
*/
void FlowFiltersImpl::AddFilters(u32 devid, const string& optarg) {
  auto i = optarg.find("=");
  if (i == string::npos) return;
  string key = optarg.substr(0, i);
  if (key != "include" && key != "exclude") return;
 
  bool excluded = key == "exclude";
  Filters* filters = GetFilters(excluded);
  string labels = optarg.substr(i + 1);

  istringstream iss(labels);
  string label;
  string mo_id_list;
  unique_ptr<FlowFilter> filter; 
  unique_ptr<BWFilter> bw_filter; 

  string model;
  const auto& config = config_->config();
  for (const auto& dev : config.dev()) {
    if (dev.id() == devid) {
      model = dev.model();
    }
  }
  
  while (!iss.eof()) {
    getline(iss, label, ',');
    unique_ptr<Policy> policy(Policy::Create(&config_->config(), label));
    if (!policy) {
      log_warning("Could not find policy of %s\n", label.c_str());
      continue;
    }
  
    switch (policy->index().policy()) {
      // Popular Services or Suspects
      case policy::POP: // fall through
        filter.reset(IPSetFilter::Create(devid,
          db_builder_.get(), nullptr, model, policy->label()));
        break;
      case policy::SUS:
        filter.reset(IPSetFilter::Create(devid,
          db_builder_.get(), nullptr, model, policy->label()));
        break;
      case policy::I_PORT_SCAN:
        filter.reset(PortScanFilter::Create(devid, model, db_builder_.get(), nullptr));
        break;
      //service
      case policy::I_SRV:
        filter.reset(ServiceFilter::Create(devid, model, db_builder_.get()));
        break;
      // MO
      case policy::MO:
        if (!policy->data()) {
          log_warning("Could not find policy data of %s\n", label.c_str());
        } else {
          string mo_id = to_string(policy->data()->mo().id());
          if (mo_id_list.empty()) 
            mo_id_list = mo_id;
          else
            mo_id_list += ',' + mo_id;
        }
        break;
      // bw
      case policy::WHITE:
      case policy::BLACK:
        if (!policy->data()) {
          log_warning("Could not find policy data of %s\n", label.c_str());
        } else{
          unique_ptr<BWFilter> tmp_filter(BWFilter::Create(devid,
            *policy->data(), db_builder_.get(), nullptr, model, (*policy->data()).label()));
          if (!bw_filter) {
            bw_filter.reset(tmp_filter.release());
          } else if (tmp_filter) {
            bw_filter->Merge(*tmp_filter);
            tmp_filter.reset();
          }
        }
        break;
      default:
        log_warning("Policy %s is not supported\n", label.c_str());
        break;
    }
    
    // Add pop/sus/scanner/service filter.
    if (filter) filters->emplace(filter.release());

  }

  // Add mo filter
  if (!mo_id_list.empty()) {
    auto mo_filter = MOFilter::Create(config_.get(), devid, mo_id_list, string());
    if (mo_filter) filters->emplace(mo_filter);
  }

  // Add bw filter
  if (bw_filter) {
    filters->emplace(bw_filter.release());
  }
}

void LogFlow(FlowFilter::FlowPtr flow, bool excluded, bool included, bool accepted) {
  if (!DEBUG) return;
  if (!excluded && !included && !accepted) return;

  static set<string> exclude_logs;
  static set<string> include_logs;
  static set<string> accept_logs;
  static set<string> reject_logs;
  auto& logs = excluded ? exclude_logs :
    (included ? include_logs : (accepted ? accept_logs : reject_logs));
  if (logs.size() > 100) return;

  auto r = (master_record_t*)flow;
  string log = StringPrintf("%s->%s %s\n",
    ipnum_to_ipstr(r->v4.srcaddr).c_str(),
    ipnum_to_ipstr(r->v4.dstaddr).c_str(),
    excluded ? "excluded"
             : (included ? "included"
                         : (accepted ? "accepted" : "rejected")));
  if (logs.find(log) != logs.end()) return;

  logs.insert(log);
  log_info(log.c_str());
}

bool FlowFiltersImpl::CheckFlow(FlowFilter::FlowPtr flow) {

  for (auto& filter : exclude_filters_) {
    if (filter->CheckFlow(flow)) {
      LogFlow(flow, true, false, false);
      return false;
    }
  }

  if (include_filters_.empty()) {
    LogFlow(flow, false, false, true);
    return true;
  }

  for (auto& filter : include_filters_) {
    if (filter->CheckFlow(flow)) {
      LogFlow(flow, false, true, true);
      return true;
    }
  }

  LogFlow(flow, false, false, false);
  return false;
}

FlowFilters* FlowFilters::Create() {
  return new FlowFiltersImpl();
}
