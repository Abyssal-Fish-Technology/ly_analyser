#include "ip_set_filter.h"
#include "common_model_filter.hpp"
#include "../../common/common.h"
#include "../../common/strings.h"
#include "../../common/log.h"
#include "../../common/ip.h"
#include "../data/tsdb.h"
#include "../define.h"
#include <iostream>
#include <sstream>

static set<Pattern> pats_;
static char kBPS[] = "bps";
static char kPPS[] = "pps";
static char kFPS[] = "sps";

namespace {
void LoadIPsFromFile(const string& file_name, std::map<u32, string>& ips) {
  try {
    ifstream ifs(file_name);
    string line;
    size_t pos;
    string ip, type;
    while (getline(ifs, line)) {
      trim(line);
      if (line.empty() || line[0] == '#') continue;
      pos = line.find(",");
      if (pos != std::string::npos) {
        ip = line.substr(0, pos);
        type = line.substr(pos + 1);
        ips[ipstr_to_ipnum(ip)] = type;
      } else {
        ips[ipstr_to_ipnum(line)] = "";
      }
    }
  } catch (...) {
    log_warning("Could not load ip set from file %s\n", file_name.c_str());
  }
}


void LoadIPsFromFileV6(const string& file_name, std::map<string, string>& ips6) {
  try {
    ifstream ifs(file_name);
    string line;
    size_t pos;
    string ip, type;
    while (getline(ifs, line)) {
      trim(line);
      if (line.empty() || line[0] == '#') continue;
      pos = line.find(",");
      if (pos != std::string::npos) {
        ip = line.substr(0, pos);
        type = line.substr(pos + 1);
        ips6[ip] = type;
      } else {
        ips6[line] = "";
      }
    }
  } catch (...) {
    log_warning("Could not load ip set from file %s\n", file_name.c_str());
  }
}

} // namespace 

IPSetFilter::IPSetFilter(u32 devid, const string& model) 
		: FlowFilter(), devid_(devid), model_(model) {}

////////////////////////////////////////////////////////////////////////////
IPSetFilter* IPSetFilter::Create(u32 devid, DBBuilder* builder, DBBuilder* event_builder, const string& model, 
                                 const string& label, const string& unfiltered_ip_csv_file) {
  unique_ptr<IPSetFilter> filter(new IPSetFilter(devid, model));
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(devid) + "_feature_" + label));
  if (event_builder && label == "sus")
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(devid) + "_event_" + label));

  if (model == "V6")
    LoadIPsFromFileV6(unfiltered_ip_csv_file + "_v6", filter->unfiltered_ips6_);
  else
    LoadIPsFromFile(unfiltered_ip_csv_file, filter->unfiltered_ips_);

	if (label == "pop")
		filter->is_popular_service_ = true; 

  if (filter->unfiltered_ips_.empty() && filter->unfiltered_ips6_.empty() ) {
    log_err("no entry loaded from %s into unfiltered ip map %s.\n",
            unfiltered_ip_csv_file.c_str(),
            filter->tsdb_->name().c_str());
    return nullptr;
  }

  if (DEBUG) {
    log_info("%u entries loaded from %s into unfiltered ip map %s.\n",
             filter->unfiltered_ips_.size(),
             unfiltered_ip_csv_file.c_str(),
             filter->tsdb_->name().c_str());
  }
  return filter.release();
}

////////////////////////////////////////////////////////////////////////////
IPSetFilter* IPSetFilter::Create(u32 devid, DBBuilder* builder, DBBuilder* event_builder, const string& model,
                                 const string& label) {
  auto* filter = new IPSetFilter(devid, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(devid) + "_feature_" + label));
  if (event_builder && label == "sus")
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(devid) + "_event_" + label));

  filter->is_popular_service_ = label == "pop" ? true : false;
  
  if (DEBUG) {
    log_info("Init %s filter.\n",
             filter->is_popular_service_ ? "popular_service" : "ip set");
  }
  return filter;
}

void IPSetFilter::InsertIPsetToTSDB(const IPsetKey& s, const IPsetStat& p) {
	Slice old_value;
	IPsetStat new_stat;
	if (tsdb_->Get(p.first, Slice(&s, sizeof(s)), &old_value) && 
					(old_value.size() >= sizeof(IPsetStat))) {
		auto* old_stat = (IPsetStat*)old_value.data();
		new_stat.first = std::min(p.first, old_stat->first);
		new_stat.last = std::max(p.last, old_stat->last);
		new_stat.flows = p.flows + old_stat->flows;
		new_stat.pkts = p.pkts + old_stat->pkts;
		new_stat.bytes = p.bytes + old_stat->bytes;
    strcpy(new_stat.bwclass,old_stat->bwclass);
    strcpy(new_stat.app_proto, old_stat->app_proto);
	} else {
		new_stat = p;
	}
	tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}

////////////////////////////////////////////////////////////////////////////
bool IPSetFilter::CheckFlow(FlowPtr flow) {
  auto r = (master_record_t*)flow;
  string sip, dip;
  if (model_ == "V6") {
    uint32_t s[4], d[4];
    memset(s, 0, sizeof(uint)*4);
    memset(d, 0, sizeof(uint)*4);
    s[0] = ( r->v6.srcaddr[0] >> 32 ) & 0xffffffffLL;
    s[1] = r->v6.srcaddr[0] & 0xffffffffLL;
    s[2] = ( r->v6.srcaddr[1] >> 32 ) & 0xffffffffLL;
    s[3] = r->v6.srcaddr[1] & 0xffffffffLL;
    d[0] = ( r->v6.dstaddr[0] >> 32 ) & 0xffffffffLL;
    d[1] = r->v6.dstaddr[0] & 0xffffffffLL;
    d[2] = ( r->v6.dstaddr[1] >> 32 ) & 0xffffffffLL;
    d[3] = r->v6.dstaddr[1] & 0xffffffffLL;
    struct in6_addr s6, d6;
    std::copy(s, s+4, s6.s6_addr32);
    std::copy(d, d+4, d6.s6_addr32);
    sip = ipnum_to_ipstr_v6(s6); 
    dip = ipnum_to_ipstr_v6(d6);
  } else {
    sip = ipnum_to_ipstr(r->v4.srcaddr);
    dip = ipnum_to_ipstr(r->v4.dstaddr);
  }

  auto timestamp = r->first - r->first % tsdb_->time_unit();
  auto it = caches_.find(timestamp);
  if (it == caches_.end()) {
    auto& cache = caches_[timestamp];
    tsdb_->Scan(
      timestamp, timestamp,
      [this, &cache](const Slice& key, const Slice&) {
        if (this->model_ == "V6") {
          struct in6_addr ip6;
          auto k = *(const IPsetKey*)key.data();
          std::copy(k.sip, k.sip+4, ip6.s6_addr32);
          cache.insert(ipnum_to_ipstr_v6(ip6));
        } else
          cache.insert(ipnum_to_ipstr((*(const IPsetKey*)key.data()).sip[0]));
      });
    if (DEBUG) log_info("%u ips loaded into ip set cache\n", cache.size());
	
    it = caches_.find(timestamp);
  }
	
  int match_bits = (it->second.count(sip) ? 1 : 0) | (it->second.count(dip) ? 2 : 0);
  if (is_popular_service_) r->popular_service = match_bits; 
  return match_bits;
}


bool IPSetFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for (auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;
    UpdateIpset(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.tos, r.dPkts, r.dOctets, r.pname); 
  }
  return true;
}

bool IPSetFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for (auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = ( r.v6.srcaddr[0] >> 32 ) & 0xffffffffLL;
    sip[1] = r.v6.srcaddr[0] & 0xffffffffLL;
    sip[2] = ( r.v6.srcaddr[1] >> 32 ) & 0xffffffffLL;
    sip[3] = r.v6.srcaddr[1] & 0xffffffffLL;
    dip[0] = ( r.v6.dstaddr[0] >> 32 ) & 0xffffffffLL;
    dip[1] = r.v6.dstaddr[0] & 0xffffffffLL;
    dip[2] = ( r.v6.dstaddr[1] >> 32 ) & 0xffffffffLL;
    dip[3] = r.v6.dstaddr[1] & 0xffffffffLL;

    UpdateIpsetV6(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.tos, r.dPkts, r.dOctets, r.pname);
  }
  return true;
}

bool IPSetFilter::UpdateIpset(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, 
                              u16 proto, u8 tos, u64 pkts, u64 bytes, char* pname) {
	auto& ips = unfiltered_ips_;

  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;
   
  if (proto == 6) {
    if (tos & 0x01 && ips.find(dip[0]) != ips.end()) {
      IPsetKey k;
      std::copy(sip, sip+4, k.dip);
      std::copy(dip, dip+4, k.sip);
      k.proto = proto;
      k.ti_mark = true;
      auto it = ipset_.find(k);
      if (it == ipset_.end()) {
        IPsetStat p;
        memset(&p, 0, sizeof(struct IPsetStat));
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);
        ipset_[k] = p;

        //五元组统计信息
        EventValue ep;
        ep.first = first;
        ep.last = last;
        ep.flows = 1;
        ep.pkts = pkts;
        ep.bytes = bytes;
        map<EventKey, EventValue> event_tmp;
        event_tmp[event] = ep;
        event_details_[k] = event_tmp;
      } else {
        auto& p = it->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);

        //五元组统计信息
        auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.last = last;
          p.flows = 1;
          p.pkts = pkts;
          p.bytes = bytes;
          event_details_[k][event] = p;
        } else {
          auto& p = itr->second;
          p.first = MIN(p.first, first);
          p.last = MAX(p.last, last);
          p.flows++;
          p.pkts += pkts;
          p.bytes += bytes;
        }
      }
    }
  } else {
    if (ips.find(sip[0]) != ips.end()) {
      IPsetKey k;
      std::copy(sip, sip+4, k.sip);
      std::copy(dip, dip+4, k.dip);
      k.proto = proto;
      k.ti_mark = false;
      auto it = ipset_.find(k);
      if (it == ipset_.end()) {
        IPsetStat p;
        memset(&p, 0, sizeof(struct IPsetStat));
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);
        ipset_[k] = p;

        //五元组统计信息
        EventValue ep;
        ep.first = first;
        ep.last = last;
        ep.flows = 1;
        ep.pkts = pkts;
        ep.bytes = bytes;
        map<EventKey, EventValue> event_tmp;
        event_tmp[event] = ep;
        event_details_[k] = event_tmp;
      } else {
        auto& p = it->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);

        //五元组统计信息
        auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.flows = 1;
          p.pkts = pkts;
          p.bytes = bytes;
          event_details_[k][event] = p;
        } else {
          auto& p = itr->second;
          p.first = MIN(p.first, first);
          p.last = MAX(p.last, last);
          p.flows++;
          p.pkts += pkts;
          p.bytes += bytes;
        }
      }
    } else if(ips.find(dip[0]) != ips.end()) {
      IPsetKey k;
      std::copy(sip, sip+4, k.dip);
      std::copy(dip, dip+4, k.sip);
      k.proto = proto;
      k.ti_mark = true;
      auto it = ipset_.find(k);
      if (it == ipset_.end()) {
        IPsetStat p;
        memset(&p, 0, sizeof(struct IPsetStat));
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);
        ipset_[k] = p;

        //五元组统计信息
        EventValue ep;
        ep.first = first;
        ep.last = last;
        ep.flows = 1;
        ep.pkts = pkts;
        ep.bytes = bytes;
        map<EventKey, EventValue> event_tmp;
        event_tmp[event] = ep;
        event_details_[k] = event_tmp;
      } else {
        auto& p = it->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);

        //五元组统计信息
        auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.flows = 1;
          p.pkts = pkts;
          p.bytes = bytes;
          event_details_[k][event] = p;
        } else {
          auto& p = itr->second;
          p.first = MIN(p.first, first);
          p.last = MAX(p.last, last);
          p.flows++;
          p.pkts += pkts;
          p.bytes += bytes;
        }
      }
    }
  }
	return true;
}

bool IPSetFilter::UpdateIpsetV6(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, 
                                u16 proto, u8 tos, u64 pkts, u64 bytes, char* pname) {
	auto& ips = unfiltered_ips6_;
  struct in6_addr sip6, dip6;
  std::copy(sip, sip+4, sip6.s6_addr32);
  std::copy(dip, dip+4, dip6.s6_addr32);

  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;
   
  if (proto == 6) {
    if (tos & 0x01 && ips.find(ipnum_to_ipstr_v6(dip6)) != ips.end()) {
      IPsetKey k;
      std::copy(dip, dip+4, k.sip);
      std::copy(sip, sip+4, k.dip);
      k.proto = proto;
      k.ti_mark = true;
      auto it = ipset_.find(k);
      if (it == ipset_.end()) {
        IPsetStat p;
        memset(&p, 0, sizeof(struct IPsetStat));
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);
        ipset_[k] = p;

        //统计五元组信息
        EventValue ep;
        ep.first = first;
        ep.last = last;
        ep.flows = 1;
        ep.pkts = pkts;
        ep.bytes = bytes;
        map<EventKey, EventValue> event_tmp;
        event_tmp[event] = ep;
        event_details_[k] = event_tmp;
      } else {
        auto& p = it->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);

        //统计五元组信息
        auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.flows = 1;
          p.pkts = pkts;
          p.bytes = bytes;
          event_details_[k][event] = p;
        } else {
          auto& p = itr->second;
          p.first = MIN(p.first, first);
          p.last = MAX(p.last, last);
          p.flows++;
          p.pkts += pkts;
          p.bytes += bytes;
        }
      }
    }
  } else { 
    if (ips.find(ipnum_to_ipstr_v6(sip6)) != ips.end()) {
      IPsetKey k;
      std::copy(sip, sip+4, k.sip);
      std::copy(dip, dip+4, k.dip);
      k.proto = proto;
      k.ti_mark = false;
      auto it = ipset_.find(k);
      if (it == ipset_.end()) {
        IPsetStat p;
        memset(&p, 0, sizeof(struct IPsetStat));
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);
        ipset_[k] = p;

        //统计五元组信息
        EventValue ep;
        ep.first = first;
        ep.last = last;
        ep.flows = 1;
        ep.pkts = pkts;
        ep.bytes = bytes;
        map<EventKey, EventValue> event_tmp;
        event_tmp[event] = ep;
        event_details_[k] = event_tmp;
      } else {
        auto& p = it->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);

       //统计五元组信息
       auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.flows = 1;
          p.pkts = pkts;
          p.bytes = bytes;
          event_details_[k][event] = p;
        } else {
          auto& p = itr->second;
          p.first = MIN(p.first, first);
          p.last = MAX(p.last, last);
          p.flows++;
          p.pkts += pkts;
          p.bytes += bytes;
        } 
      }
    } else if(ips.find(ipnum_to_ipstr_v6(dip6)) != ips.end()) {
      IPsetKey k;
      std::copy(dip, dip+4, k.sip);
      std::copy(sip, sip+4, k.dip);
      k.proto = proto;
      k.ti_mark = true;
      auto it = ipset_.find(k);
      if (it == ipset_.end()) {
        IPsetStat p;
        memset(&p, 0, sizeof(struct IPsetStat));
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);
        ipset_[k] = p;

        //统计五元组信息
        EventValue ep;
        ep.first = first;
        ep.last = last;
        ep.flows = 1;
        ep.pkts = pkts;
        ep.bytes = bytes;
        map<EventKey, EventValue> event_tmp;
        event_tmp[event] = ep;
        event_details_[k] = event_tmp;
      } else {
        auto& p = it->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;
        memcpy(p.app_proto, pname, strlen(pname)+1);

        //统计五元组信息
        auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.flows = 1;
          p.pkts = pkts;
          p.bytes = bytes;
          event_details_[k][event] = p;
        } else {
          auto& p = itr->second;
          p.first = MIN(p.first, first);
          p.last = MAX(p.last, last);
          p.flows++;
          p.pkts += pkts;
          p.bytes += bytes;
        }       
      }
    }
  }
	return true;
}

event::GenEventRes IPSetFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<IPSetFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);

  GenEventRes events;
  ptr->DivideMode();
	for (auto it = ptr->ipset_.begin(); it != ptr->ipset_.end(); ++it) {
		auto& s = it->first;
		auto& p = it->second;
    memset(p.bwclass, 0, MAXBWCLASSLEN);
 
		if (!ptr->is_popular_service_) {
      string str;
      if (model == "V6") {
        struct in6_addr sip6;
        std::copy(s.sip, s.sip+4, sip6.s6_addr32);
        string ipstr = ipnum_to_ipstr_v6(sip6);
        str =  ptr->unfiltered_ips6_[ipstr];
      } else
        str = ptr->unfiltered_ips_[s.sip[0]];
      auto size = str.size();
      if (size >= MAXBWCLASSLEN) { 
        size = MAXBWCLASSLEN; 
        str[MAXBWCLASSLEN - 1] = '\0';
      }
      memcpy(p.bwclass, str.c_str(), size);
      if (s.ti_mark) {
			  ptr->GenerateEvents(s, p, &events);
      } 
      ptr->InsertIPsetToTSDB(s, p);
      continue;
    }
    ptr->InsertIPsetToTSDB(s, p);
	}
  return events;
}

IPSetFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et)
  : event_config(e), dev_id(devid), start_time(st), end_time(et) {

  if (DEBUG) log_info("EventGenerator initialized.\n");
}

//event_config to model struct
void IPSetFilter::DivideMode() {
  Pattern pat;
  for (u32 i = 0; i < event_generators_.size(); ++i) {
    auto event_config = event_generators_[i].event_config;
    pat.type_id = event_config.type_id();
    pat.config_id = event_config.config_id();
    pat.data_type = event_config.data_type();
    pat.min = event_config.min();
    pat.start_time = event_generators_[i].start_time;
    pat.end_time = event_generators_[i].end_time;
    pat.dev_id = event_generators_[i].dev_id;
    for (int i=0;i<event_config.weekday_size(); i++) {
      pat.weekday.push_back(event_config.weekday(i));
    }
    pat.coverrange = event_config.coverrange();
    pat.stime_hour = event_config.stime_hour();
    pat.stime_min = event_config.stime_min();
    pat.stime_sec = event_config.stime_sec();
    pat.etime_hour = event_config.etime_hour();
    pat.etime_min = event_config.etime_min();
    pat.etime_sec = event_config.etime_sec();
    pat.max = event_config.has_max() ? event_config.max() : 0;

    pats_.emplace(pat);
  }
}


void IPSetFilter::GenerateEvents(const IPsetKey& s, const IPsetStat& p, GenEventRes* events) {
  double bps = 0, pps = 0, fps = 0;
  for (auto& pat : pats_) {
    u32 interval = pat.end_time - pat.start_time;
    bps = p.bytes / (double)interval;
    pps = p.pkts / (double)interval;
    fps = p.flows / (double)interval;
    const string& data_type = pat.data_type;
    double value = 0;
    if (data_type == kBPS) {
      value = bps;
    } else if (data_type == kPPS) {
      value = pps;
    } else if (data_type == kFPS) {
      value = fps;
    } else {
      log_err("data_type not supported:%s.\n", pat.data_type.c_str());
      continue;
    }
    if (value >= pat.min && (pat.max==0 || value < pat.max) &&
				common_model_filter::filter_time_range(pat)) {
      auto e = events->add_records();
      e->set_time(pat.start_time);
      e->set_type_id(pat.type_id);
      e->set_config_id(pat.config_id);
      e->set_devid(pat.dev_id);
      if (model_ == "V6") {
        struct in6_addr sip6, dip6;
        std::copy(s.sip, s.sip+4, sip6.s6_addr32);
        std::copy(s.dip, s.dip+4, dip6.s6_addr32);
        e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]: " + proto_to_string(s.proto) + " " + p.bwclass);
      } else
        e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>" + ipnum_to_ipstr(s.dip[0]) + ": " + 
                proto_to_string(s.proto) + " " + p.bwclass);
      e->set_thres_value(pat.min);
      e->set_alarm_value(value);
      e->set_value_type(data_type);
      e->set_model_id(2);
      
      //生成事件特征数据，即事件五元组详细信息
      GenEventFeature(s, e);
    }
  }
}

void IPSetFilter::GenEventFeature(const IPsetKey& s, const event::GenEventRecord* e) {
  for (auto& kv : event_details_[s]) {
    auto k = kv.first;
    auto v = kv.second;

    k.time = e->time();
    k.type = e->type_id();
    k.model = e->model_id();
    memcpy(k.obj, e->obj().c_str(), e->obj().size()+1);
    InsertEventToTSDB(k, v);
  }
}

void IPSetFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}

void IPSetFilter::FilterSusEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckSusEvent(key, value, req, resp);
    });
}

void IPSetFilter::FilterIPSets(const feature::FeatureReq& req, feature::FeatureResponse* resp) {
	tsdb_->Scan(
		req.starttime(), req.endtime(),
		[this, &req, &resp](const Slice& key, const Slice& value) {
			CheckIPSet(key, value, req);
		});

  for (auto it = res_ips_.begin(); it != res_ips_.end(); ++it)
    resp->MergeFrom(it->second);
}

void IPSetFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}


void IPSetFilter::AddRecord(const IPsetKey& key, const FeatureRecord& new_rec) {
  auto it = res_ips_.find(key);
  if (it == res_ips_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_ips_[key] = resp;
  } else {
    auto& resp = res_ips_[key];
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
      rec->set_bwclass(new_rec.bwclass());
      rec->set_app_proto(new_rec.app_proto());
      return;
    }
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void IPSetFilter::CheckIPSet(const Slice& key, const Slice& value, 
						 const FeatureReq& req) {
	const IPsetKey& ipsetkey = *(const IPsetKey*)key.data();
  const IPsetStat& stat = *(const IPsetStat*)value.data();

	if (stat.last < req.starttime() || stat.first > req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(ipsetkey.sip, ipsetkey.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(ipsetkey.dip, ipsetkey.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(ipsetkey.sip[0]);
    dip = ipnum_to_ipstr(ipsetkey.dip[0]);
  }

	if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
	if (req.has_sip() && req.sip() != sip) return;
	if (req.has_dip() && req.dip() != dip) return;
	if (req.has_proto() && req.proto() != ipsetkey.proto)	return;
  if (req.has_ti_mark() && req.ti_mark() != ipsetkey.ti_mark) return;

	FeatureRecord rec;	
	rec.set_time(stat.first);
  rec.set_duration(stat.last - stat.first);
	rec.set_sip(sip);
	rec.set_dip(dip);
	rec.set_protocol(ipsetkey.proto);
	rec.set_flows(stat.flows);
	rec.set_pkts(stat.pkts);
	rec.set_bytes(stat.bytes);
  if (ipsetkey.ti_mark)
    rec.set_ti_mark("res");
  else 
    rec.set_ti_mark("req");
  rec.set_bwclass(stat.bwclass);
  rec.set_app_proto(stat.app_proto);
	
	if (DEBUG) log_info("Got IPs Record: %s\n", rec.DebugString().c_str());
  AddRecord(ipsetkey, rec);
 }

void IPSetFilter::CheckSusEvent(const Slice& key, const Slice& value,
                                  const eventfeature::EventFeatureReq& req,
                                  eventfeature::EventFeatureResponse* resp) {
  const EventKey& pvckey = *(const EventKey*)key.data();
  const EventValue& stat = *(const EventValue*)value.data();

  if (pvckey.time < req.starttime() || pvckey.time > req.endtime()) return;
  if (req.has_obj() && req.obj() != pvckey.obj) return;

  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6 ,dip6;
    std::copy(pvckey.sip, pvckey.sip+4, sip6.s6_addr32);
    std::copy(pvckey.dip, pvckey.dip+4, dip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(pvckey.sip[0]);
    dip = ipnum_to_ipstr(pvckey.dip[0]);
  }

  EventFeatureRecord rec;
  rec.set_time(pvckey.time);
  rec.set_sip(sip);
  rec.set_sport(pvckey.sport);
  rec.set_dip(dip);
  rec.set_dport(pvckey.dport);
  rec.set_protocol(pvckey.proto);
  rec.set_obj(pvckey.obj);
  rec.set_type(pvckey.type);
  rec.set_model(pvckey.model);
  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);

  if (DEBUG) log_info("Got Dos Record: %s\n", rec.DebugString().c_str());
  AddEventRecord(rec, resp);
}
