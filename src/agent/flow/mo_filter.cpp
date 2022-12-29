#include "mo_filter.h"
#include "../../common/common.h"
#include "../../common/config.pb.h"
#include "../../common/log.h"
#include "../../common/ip.h"
#include "../config/cached_config.h"
#include <iostream>

#define MAX_LOG_FLOW 10

void MOFilter::GetAllMoIds(std::vector<u32>* ids) {
  for (s32 i = 0; i < config_->config().mo_size(); ++i) {
    auto mo = config_->config().mo(i);
    if (mo.devid() == devid_)
      ids->push_back(mo.id());
  }
}

void MOFilter::GetMoIdsOfGroupid(std::vector<u32>* ids, u32 groupid) {
  for (s32 i = 0; i < config_->config().mo_size(); ++i) {
    auto mo = config_->config().mo(i);
    if (mo.devid() != devid_) continue;
    if (mo.mogroupid() == groupid) {
      ids->push_back(mo.id());
    }
  }
}

MOFilter::MOFilter(CachedConfig* config, u32 devid)
  : FlowFilter(), config_(config), devid_(devid) {}

MOFilter::MOFilter(CachedConfig* config, u32 devid, std::unique_ptr<TSDB> tsdb)
  : FlowFilter(), config_(config), devid_(devid), tsdb_(std::move(tsdb)) {}

MOFilter::~MOFilter() {
  for (u32 i = 0; i < filters_.size(); ++i) {
    delete filters_[i];
  }
}


MOFilter* MOFilter::Create(CachedConfig* config, u32 devid, DBBuilder* builder) {
  auto* filter = new MOFilter(
    config, devid, unique_ptr<TSDB>(new TSDB(builder, to_string(devid) + "_feature_mo")));
  
  for (s32 i = 0; i < config->config().mo_size(); ++i) {
    auto mo = config->config().mo(i);
    if (mo.devid() != devid) continue;
    //filter->compilers_[mo.id()] = CompiledFilter::Compile(mo.filter().c_str());
    filter->compilers_[mo.id()].reset(CompiledFilter::Compile(mo.filter().c_str()));
  }
  if (DEBUG) log_info("mo filter initialized for update.\n");
  return filter;
}

MOFilter* MOFilter::Create(
    CachedConfig* config, u32 devid, const string& mo_id_list,
    const string& additional_filter) {
  if (DEBUG) log_info("Begin to create mo filter of %s\n", mo_id_list.c_str());
  unique_ptr<MOFilter> filter(new MOFilter(config, devid));
  if (!filter->InitInternal(mo_id_list)) {
     if (!additional_filter.empty()) {
       log_info("Add filter of additional filter %s\n", additional_filter.c_str());
       if (!filter->AddFilter(additional_filter)) {
         log_err("Failed to init additional filter of mo filter:%s\n", mo_id_list.c_str());
         return nullptr;
       }
     } else {
       log_err("Failed to init mo filter:%s\n", mo_id_list.c_str());
       return nullptr;
     }
  }
  if (DEBUG) {
    log_info("Init mo filter:%s grep:%s\n", mo_id_list.c_str(),
             additional_filter.c_str());
  }
  return filter.release();
}

bool MOFilter::InitInternal(const string& mo_id_list) {
  istringstream iss(mo_id_list);
  string idstr;
  vector<u32> ids_to_fetch;
  if (mo_id_list.empty()) {
    if (DEBUG) log_info("mo_id_list is empty. fetch all mo instead.\n");
    GetAllMoIds(&ids_to_fetch);
  } else {
    while (std::getline(iss, idstr, ',')) {
      if (idstr.empty()) continue;
      u32 mo_id = std::stoi(idstr);
      for (s32 i = 0; i < config_->config().mo_size(); ++i) {
        const auto& mo = config_->config().mo(i);
        if (mo.id() == mo_id) {
          if (mo.devid() == devid_) {
          //if (!mo.has_devid() || mo.devid() == devid_) {
            ids_to_fetch.push_back(mo_id);
          }
          break;
        }
      }
    }  
  }
  if (DEBUG) {
    ostringstream oss;
    std::copy(ids_to_fetch.begin(), ids_to_fetch.end(),
              ostream_iterator<u32>(oss, ","));
    log_info("%d effective ids to fetch  %s\n", ids_to_fetch.size(), oss.str().c_str());
  }

  auto filters = config_->FetchMOFilters(ids_to_fetch);
  string filter;
  for (auto it = filters.begin(); it != filters.end(); ++it) {
    if (it->empty()) continue;
    if (filter.empty()) filter = *it;
    else filter = "(" + filter + ") or (" + *it + ")";
  }
  return AddFilter(filter);
}

bool MOFilter::AddFilter(const string& filter_str) {
  if (DEBUG) log_info("Complie filter %s\n", filter_str.c_str());
  auto filter = CompiledFilter::Compile(filter_str.c_str());
  if (!filter) {
    log_err("can't add filter:%s\n", filter_str.c_str());
    return false;
  }
  if (DEBUG) log_info("add filter:%s\n", filter_str.c_str());
  filters_.push_back(filter);
  return true;
}


bool MOFilter::CheckFlow(FlowPtr flow) {
  static u64 index;
  ++index;
  bool matched = false;  
  for (auto it = filters_.begin(); it != filters_.end(); ++it) {
    if ((*it)->Match(flow)) {
      matched = true;
      break;
    }
  }

  static int log_matched;
  static int log_unmatched;
  bool should_log = DEBUG && ((matched && log_matched++ < MAX_LOG_FLOW) ||
                              (!matched && log_unmatched++ < MAX_LOG_FLOW));
  if (!should_log) return matched;

  //master_record_t *r = (master_record_t *)flow;
  /*auto srcip = r->v4.srcaddr;
  auto dstip = r->v4.dstaddr;
 
  stringstream oss;
  oss << "flow #" << index << ' ' << ipnum_to_ipstr(srcip) << ':' << r->srcport << ':'
      << " -> " << ipnum_to_ipstr(dstip) << ':' << r->dstport << ' '
      << proto_to_string(r->prot) << ' '
      << (matched ? "matches" : "NOT matches") << " mo filters:";
  for (u32 i = 0; i < filters_.size(); ++i) {
    if (filters_[i]->Match(flow)) {
      oss << i << ' ';
    }
  }
  log_info("%s\n", oss.str().c_str());*/
  return matched;
}


bool MOFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for (auto it = flowset->begin(); it != flowset->end(); it++) {
    UpdateMo(&*it);
  }
  return true;  
}

bool MOFilter::UpdateMo(FlowPtr flow) {
  auto r = (master_record_t*)flow;
  u32 first = r->first;
  u32 last = r->last;
  u64 pkts = r->dPkts;
  u64 bytes = r->dOctets;

  for (auto it = compilers_.begin(); it != compilers_.end(); it++) {
    auto id = it->first;
    MOKey s{id};
    bool match = it->second->Match(flow);
    if (match) {
      auto t = mo_.find(s);
      if (t == mo_.end()) {
        MOStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        mo_[s] = p;
      } else {
        auto& p = t->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;
      }
    }
  }
  return true;
}

void MOFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<MOFilter>& ptr) {
  ptr->UpdateByFlow(flowset);
  for (auto it = ptr->mo_.begin(); it != ptr->mo_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;
    p.peak_flows = p.flows;
    p.peak_pkts = p.pkts;
    p.peak_bytes = p.bytes;
    ptr->InsertMOToTSDB(s, p);
  }
}

void MOFilter::InsertMOToTSDB(const MOKey& s, const MOStat& p) {
  Slice old_value;
  MOStat new_stat;
  if (tsdb_->Get(p.first, Slice(&s, sizeof(s)), &old_value) &&
                    (old_value.size() >= sizeof(MOStat))) {
    auto* old_stat = (MOStat*)old_value.data();
    new_stat.first = std::min(p.first, old_stat->first);
    new_stat.last = std::max(p.last, old_stat->last);
    new_stat.flows = p.flows + old_stat->flows;
    new_stat.pkts = p.pkts + old_stat->pkts;
    new_stat.bytes = p.bytes + old_stat->bytes;
    new_stat.peak_flows = std::max(p.peak_flows, old_stat->peak_flows);
    new_stat.peak_pkts = std::max(p.peak_pkts, old_stat->peak_pkts);
    new_stat.peak_bytes = std::max(p.peak_bytes, old_stat->peak_bytes);
  } else {
    new_stat = p;
  }
  tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}

void MOFilter::FilterMO(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckMO(key, value, req);
    });
  
  for (auto it = res_mo_.begin(); it != res_mo_.end(); ++it)
    resp->MergeFrom(it->second);
}

void MOFilter::CheckMO(const Slice& key, const Slice& val,
                        const feature::FeatureReq& req) {
  const MOKey& mokey = *(const MOKey*)key.data();
  const MOStat& stat = *(const MOStat*)val.data();
  if (stat.last < req.starttime() || stat.first > req.endtime()) return;
  vector<u32> ids;
  if (req.has_moid() && req.moid() != mokey.moid ) return;
  if (req.has_groupid()) {
    GetMoIdsOfGroupid(&ids, req.groupid());
    auto it = find(ids.begin(), ids.end(), mokey.moid);
    if (it == ids.end()) return;
  }
  if (req.has_moid() && req.has_groupid()) return;
  
  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_duration(stat.last - stat.first);
  rec.set_moid(mokey.moid);
  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);
  rec.set_peak_flows(stat.peak_flows);
  rec.set_peak_pkts(stat.peak_pkts);
  rec.set_peak_bytes(stat.peak_bytes);
  
  if (DEBUG) log_info("Got mo Record: %s\n", rec.DebugString().c_str());
  AddRecord(mokey, rec);
}

void MOFilter::AddRecord(const MOKey& key, const FeatureRecord& new_rec) {
  auto it = res_mo_.find(key);
  if (it == res_mo_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_mo_[key] = resp;
  } else {
    auto& resp = res_mo_[key];
    for (s32 i = 0; i < resp.records_size(); i++) {
      auto rec = resp.mutable_records(i);

      u32 s1 = rec->time();
      u32 e1 = s1 + rec->duration();
      u32 s2 = new_rec.time();
      u32 e2 = s2 + new_rec.duration();
      if (e1 + INTERVAL < s2) continue;
      if (e2 + INTERVAL < s1) continue;
      u32 mins = std::min(s1, s2);
      u32 maxe = std::max(e1, e2);

      rec->set_time(mins);
      rec->set_duration(maxe - mins);
      rec->set_flows(rec->flows() + new_rec.flows());
      rec->set_pkts(rec->pkts() + new_rec.pkts());
      rec->set_bytes(rec->bytes() + new_rec.bytes());
      rec->set_peak_flows(std::max(rec->peak_flows(), new_rec.peak_flows()));
      rec->set_peak_bytes(std::max(rec->peak_bytes(), new_rec.peak_bytes()));
      rec->set_peak_pkts(std::max(rec->peak_pkts(), new_rec.peak_pkts()));
      return;
    }
    
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}
