#include "port_scan_filter.h"
#include "common_model_filter.hpp"
#include "../../common/common.h"
#include "../../common/ip.h"
#include "../../common/asset.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/datetime.h"
#include "../../common/common_filter.hpp"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include "../define.h"
#include <utility>

static std::vector<set<Pattern>> event_models;
static std::vector<set<Pattern>> feature_models;

PortScanFilter::PortScanFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}

PortScanFilter* PortScanFilter::Create(u32 dev_id, const string& model,
                                     DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new PortScanFilter(dev_id, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_portscan"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_portscan"));
  if (DEBUG) log_info("Port Scan filter initialized.\n");
  return filter;
}

bool PortScanFilter::CheckFlow(FlowPtr flow) {
  auto r = (master_record_t*)flow;
  uint32_t sip[4];
  memset(sip, 0, sizeof(uint)*4);
  if (model_ == "V6") {
    sip[0] = ( r->v6.srcaddr[0] >> 32 ) & 0xffffffffLL;
    sip[1] = r->v6.srcaddr[0] & 0xffffffffLL;
    sip[2] = ( r->v6.srcaddr[1] >> 32 ) & 0xffffffffLL;
    sip[3] = r->v6.srcaddr[1] & 0xffffffffLL;
  } else
    sip[0] = r->v4.srcaddr;

  PortScanKey k;
  std::copy(sip, sip+4, k.ip);
  k.proto = r->prot;
  k.port = r->dstport;
  auto timestamp = r->first - r->first % tsdb_->time_unit();
  auto it = caches_.find(timestamp);
  if (it == caches_.end()) {
    auto& cache = caches_[timestamp];
    tsdb_->Scan(timestamp, timestamp, 
               [&cache](const Slice& key, const Slice&) {
                 cache.insert(*(const PortScanKey*)key.data());
               });
    it = caches_.find(timestamp);
  }  
  r->scanner = it->second.count(k) ? 1 : 0;
  return r->scanner;
}

bool PortScanFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.srcport == 0 || r.dstport == 0) continue;
    if (r.prot == 6 && (r.tos & 0x01) != 0x01) continue;

    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;
  
    UpdateScans(r.first, r.last, r.prot, sip, r.srcport, dip, r.dstport, r.pname, r.dPkts, r.dOctets);
    //UpdateScans(r.first, r.last, r.prot, dip, sip, r.srcport, r.pname, r.dPkts, r.dOctets);
  }
  return true;
}

bool PortScanFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.srcport == 0 || r.dstport == 0) continue;
    if (r.prot == 6 && (r.tos & 0x01) != 0x01) continue;

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

    UpdateScans(r.first, r.last, r.prot, sip, r.srcport, dip, r.dstport, r.pname, r.dPkts, r.dOctets);
    //UpdateScans(r.first, r.last, r.prot, dip, sip, r.srcport, r.pname, r.dPkts, r.dOctets);
  }
  return true;
}


void PortScanFilter::UpdateScans(u32 first, u32 last, u16 proto, u32 ip[], u16 port, u32 peerip[],
    u16 peerport, char* pname, u64 pkts, u64 bytes) {

  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(ip, ip+4, event.sip);
  event.sport = port;
  std::copy(peerip, peerip+4, event.dip);
  event.dport = peerport;
  event.proto = proto;

  Conv conv;
  std::copy(ip, ip+4, conv.ip);
  conv.proto = proto;
  conv.peerport = peerport;
  std::copy(peerip, peerip+4, conv.peerip);
  
  auto rv = convs_.insert(conv);
  PortScanKey scan;
  std::copy(ip, ip+4, scan.ip);
  scan.proto = proto;
  scan.port = peerport;
  auto it = scans_.find(scan);
  if (it == scans_.end()) {
    ScanStat p;
    memset(&p, 0, sizeof(struct ScanStat));
    p.first = first;
    p.last = last;
    p.peerip_count = 1;
    p.flows = 1;
    memcpy(p.app_proto, pname, strlen(pname)+1);
    p.pkts = pkts;
    p.bytes = bytes;
    scans_[scan] = p;

    //五元组统计信息
    EventValue ep;
    ep.first = first;
    ep.last = last;
    ep.flows = 1;
    ep.pkts = pkts;
    ep.bytes = bytes;
    map<EventKey, EventValue> event_tmp;
    event_tmp[event] = ep;
    event_details_[scan] = event_tmp;
  } else {
    auto& p = it->second;
    p.first = MIN(p.first, first);
    p.last = MAX(p.last, last);
    if (rv.second) ++p.peerip_count;
    ++p.flows;
    memcpy(p.app_proto, pname, strlen(pname)+1);
    p.pkts += pkts;
    p.bytes += bytes;

    //五元组统计信息
    auto itr = event_details_[scan].find(event);
    if (itr == event_details_[scan].end()) {
      EventValue p;
      p.first = first;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      event_details_[scan][event] = p;
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

bool PortScanFilter::LoadPatternFromFile() {
  ifstream ifs(AGENT_PAT_FILE);
  if (!ifs.is_open()) {
    log_err(__FILE__": failed to load pattern config: %s\n", AGENT_PAT_FILE);
    return false;
  }

  string line;
  Pattern pat;

  while (getline(ifs, line)) {
		trim(line);
    if (line.empty()|| line[0] == '#') continue;
    size_t pos = line.find(",");
    size_t size = line.size();
    vector<string> res;
    while (pos != std::string::npos) {
      string x = line.substr(0,pos);
      res.push_back(trim(x));
      line = line.substr(pos+1, size-pos-1);
      pos = line.find(",");
    }
    res.push_back(line);
    if (res[0] != "PORT_SCAN") continue;
    pat.type = res[0];
    pat.sip = res[1];
    pat.dport = res[4];
    pat.protocol = res[5];
    if (res[6].empty()) continue;
    pat.peers = atol(res[6].c_str());
    pat.flows = res[7].empty() ? 0 : atol(res[7].c_str());
    DividePatterns(pat, res);
  }
	feature_models.push_back(ip_port_proto_);
  feature_models.push_back(ip_port_);
  feature_models.push_back(ip_proto_);
  feature_models.push_back(port_proto_);
  feature_models.push_back(ip_);
  feature_models.push_back(port_);
  feature_models.push_back(proto_);
  feature_models.push_back(flows_);
  return true;
}

void PortScanFilter::DividePatterns(Pattern& pat, vector<string>& res) {
    if (!res[1].empty() && !res[4].empty() && !res[5].empty()) {
      ip_port_proto_.emplace(pat);
    } else if (!res[1].empty() && !res[4].empty() && res[5].empty()) {
      ip_port_.emplace(pat);
    } else if (!res[1].empty() && res[4].empty() && !res[5].empty()) {
      ip_proto_.emplace(pat);
    } else if (res[1].empty() && !res[4].empty() && !res[5].empty()) {
      port_proto_.emplace(pat);
    } else if (!res[1].empty() && res[4].empty() && res[5].empty()) {
      ip_.emplace(pat);
    } else if (res[1].empty() && !res[4].empty() && res[5].empty()) {
      port_.emplace(pat);
    } else if (res[1].empty() && res[4].empty() && !res[5].empty()) {
      proto_.emplace(pat);
    } else {
      flows_.emplace(pat);
    }
}

event::GenEventRes PortScanFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<PortScanFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);
	GenEventRes events;
  Pattern pat;
  if (!ptr->LoadPatternFromFile()) {
    log_err("Can't load config file.\n");
    return events;
  }

	ptr->DivideMode();
  auto it = ptr->scans_.begin();
  while (it != ptr->scans_.end()) {
    auto& s = it->first;
    auto& p = it->second;
		ptr->GenerateEvents(s, p, &events);
    ptr->GenerateFeature(s, p);
    it++;
  }

  return events;
}


void PortScanFilter::InsertScanToTSDB(const PortScanKey& s, const ScanStat& stat) {
  /*if (DEBUG) {
    ostringstream oss;
    oss << "Found scanner: " << datetime::format_timestamp(stat.first) << ' '
        << stat.last - stat.first << "s PROTO:" << proto_to_string(s.proto) << ' '
        << ipnum_to_ipstr(s.ip) << " -> " << stat.peerip_count << " ips port:"
        << s.port << " flows:" << stat.flows << " pkts:" << stat.pkts
        << " bytes" << stat.bytes << '\n';
    log_info("%s\n", oss.str().c_str());
  }*/

  ScanStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(ScanStat))) {
    auto* old_stat = (ScanStat*)old_value.data();
    new_stat.first = std::min(stat.first, old_stat->first);
    new_stat.last = std::max(stat.last, old_stat->last);
    new_stat.peerip_count = stat.peerip_count + old_stat->peerip_count;
    new_stat.flows = stat.flows + old_stat->flows;
    new_stat.pkts = stat.pkts + old_stat->pkts;
    new_stat.bytes = stat.bytes + old_stat->bytes;
    strcpy(new_stat.app_proto, old_stat->app_proto);
  } else {
    new_stat = stat;
  }
  tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}


void PortScanFilter::FilterScan(const feature::FeatureReq& req,
                                   feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckScan(key, value, req);
    });

  for (auto it = res_scan_.begin(); it != res_scan_.end(); ++it)
    resp->MergeFrom(it->second);
}

void PortScanFilter::FilterScanEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckScanEvent(key, value, req, resp);
    });
}

void PortScanFilter::AddRecord(const PortScanKey& key, const FeatureRecord& new_rec) {
  auto it = res_scan_.find(key);
  if (it == res_scan_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_scan_[key] = resp;
  } else {
    auto& resp = res_scan_[key];
    for (s32 i = 0; i < resp.records_size(); ++i) {
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
      rec->set_peers(rec->peers() + new_rec.peers());
      rec->set_bytes(rec->bytes() + new_rec.bytes());
      rec->set_pkts(rec->pkts() + new_rec.pkts());
      rec->set_flows(rec->flows() + new_rec.flows());
      rec->set_app_proto(new_rec.app_proto());
      return;
    }
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void PortScanFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void PortScanFilter::CheckScan(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const PortScanKey& svckey = *(const PortScanKey*)key.data();
  const ScanStat& stat = *(const ScanStat*)value.data();

  if (stat.last < req.starttime() || stat.first > req.endtime()) return;
  string ip;
  if (model_ == "V6") {
    struct in6_addr ip6;
    std::copy(svckey.ip, svckey.ip+4, ip6.s6_addr32);
    ip = ipnum_to_ipstr_v6(ip6);
  } else
    ip = ipnum_to_ipstr(svckey.ip[0]);

  if (req.has_sip() && req.sip() != ip) return;
  if (req.has_ip() && req.ip() != ip) return;
  if (req.has_proto() && req.proto() != svckey.proto) return;
  if (req.has_dport() && req.dport() != svckey.port) return;
  if (req.has_port() && req.port() != svckey.port) return;
  if (req.has_peers() && req.peers() > stat.peerip_count) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_duration(stat.last - stat.first);
  rec.set_sip(ip);
  rec.set_dport(svckey.port);
  rec.set_protocol(svckey.proto);
  rec.set_peers(stat.peerip_count);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);
  rec.set_app_proto(stat.app_proto);  

  if (DEBUG) log_info("Got Scan Record: %s\n", rec.DebugString().c_str());
  AddRecord(svckey, rec);
}

void PortScanFilter::CheckScanEvent(const Slice& key, const Slice& value,
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

///////////////////////////////////////////////////////////////////////////////
// PortScanFilter::EventGenerator
///////////////////////////////////////////////////////////////////////////////

void PortScanFilter::DivideMode() {
  std::set<Pattern> sip_dport_prot_;
  std::set<Pattern> sip_dport_;
  std::set<Pattern> sip_prot_;
  std::set<Pattern> dport_prot_;
  std::set<Pattern> sip_;
  std::set<Pattern> dport_;
  std::set<Pattern> prot_;
  std::set<Pattern> min_;
	Pattern pat;
	for (u32 i = 0; i < event_generators_.size(); ++i) {
		auto event_config = event_generators_[i].event_config;
  	pat.peers = event_config.min();
  	pat.start_time = event_generators_[i].start_time;
  	pat.config_id = event_config.config_id();
  	pat.type_id = event_config.type_id();
  	if (event_config.has_max())
    	pat.max = event_config.max();
  	else
    	pat.max = 0;

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

		if (event_config.has_ip() && event_config.has_port() && event_config.has_protocol()) {
    	pat.dip = event_config.ip();
    	pat.dport = to_string(event_config.port());
    	pat.protocol = event_config.protocol();
    	sip_dport_prot_.emplace(pat);
  	} else if (event_config.has_ip() && event_config.has_port() && !event_config.has_protocol()) {
    	pat.dip = event_config.ip();
    	pat.dport = to_string(event_config.port());
    	sip_dport_.emplace(pat);
  	} else if (event_config.has_ip() && !event_config.has_port() && event_config.has_protocol()) {
    	pat.dip = event_config.ip();
    	pat.protocol = event_config.protocol();
    	sip_prot_.emplace(pat);
  	} else if (!event_config.has_ip() && event_config.has_port() && event_config.has_protocol()) {
    	pat.dport = to_string(event_config.port());
    	pat.protocol = event_config.protocol();
    	dport_prot_.emplace(pat);
  	} else if (event_config.has_ip() && !event_config.has_port() && !event_config.has_protocol()) {
    	pat.dip = event_config.ip();
    	sip_.emplace(pat);
  	} else if (!event_config.has_ip() && event_config.has_port() && !event_config.has_protocol()) {
    	pat.dport = to_string(event_config.port());
    	dport_.emplace(pat);
  	} else if (!event_config.has_ip() && !event_config.has_port() && event_config.has_protocol()) {
    	pat.protocol = event_config.protocol();
    	prot_.emplace(pat);
  	} else {
    	min_.emplace(pat);
  	}
	}
	event_models.push_back(sip_dport_prot_);
  event_models.push_back(sip_dport_);
  event_models.push_back(sip_prot_);
  event_models.push_back(dport_prot_);
  event_models.push_back(sip_);
  event_models.push_back(dport_);
  event_models.push_back(prot_);
  event_models.push_back(min_);
}

PortScanFilter::EventGenerator::EventGenerator(
    const config::Event& e, u32 devid, u32 st, u32 et)
    : event_config(e), dev_id(devid), start_time(st), end_time(et) {
  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void PortScanFilter::Generate(const PortScanKey& s, const ScanStat& p, GenEventRes* events, Pattern& pat) {
	if (common_model_filter::filter_time_range(pat)) {
  	auto e = events->add_records();
  	e->set_time(pat.start_time);
  	e->set_type_id(pat.type_id);
  	e->set_config_id(pat.config_id);
  	e->set_devid(dev_id_);
    if (model_ == "V6") {
      struct in6_addr ip6;
      std::copy(s.ip, s.ip+4, ip6.s6_addr32);
      e->set_obj("[" + ipnum_to_ipstr_v6(ip6) + "]:>:" + to_string(s.port) + " " +
                proto_to_string(s.proto) + " ");
    } else
  	  e->set_obj(ipnum_to_ipstr(s.ip[0]) + ":>:" + to_string(s.port) + " " +
                proto_to_string(s.proto) + " ");
  	e->set_thres_value(pat.peers);
  	e->set_alarm_value(p.peerip_count);
  	e->set_value_type("peerips");
    e->set_model_id(0);
    
    //生成事件特征数据，即事件五元组详细信息 
    GenEventFeature(s, e);
  	if (DEBUG) log_info("Generated dos event: %s\n", e->DebugString().c_str());
	}
}

void PortScanFilter::GenEventFeature(const PortScanKey& s, const event::GenEventRecord* e) {
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

void PortScanFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}

Match_res* PortScanFilter::Pickout(const PortScanKey& s, const ScanStat& p,
                                struct Match_res& result, vector<set<Pattern>>& models) {
  string ipstr;
  if (model_ == "V6") {
    struct in6_addr ip6;
    std::copy(s.ip, s.ip+4, ip6.s6_addr32);
    ipstr = ipnum_to_ipstr_v6(ip6);
  } else
    ipstr = ipnum_to_ipstr(s.ip[0]);

  string port = to_string(s.port);
  string proto = proto_to_string(s.proto);
	for (auto a : models[0]) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, a.sip);
    else
      res = valid_ip(ipstr, a.sip);
    if (res && port == a.dport
        && proto == a.protocol) {
      if (p.peerip_count >= a.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = a;
      return &result;
    }
  }
  for (auto b : models[1]) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, b.sip);
    else
      res = valid_ip(ipstr, b.sip);

    if (res && port == b.dport) {
      if (p.peerip_count >= b.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = b;
      return &result;
    }
  }
	for (auto c : models[2]) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, c.sip);
    else
      res = valid_ip(ipstr, c.sip);

    if (res && proto == c.protocol) {
      if (p.peerip_count >= c.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = c;
      return &result;
    }
  }
  for (auto d : models[3]) {
    if (port == d.dport && proto == d.protocol) {
      if (p.peerip_count >= d.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = d;
      return &result;
    }
  }
  for (auto e : models[4]) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, e.sip);
    else
      res = valid_ip(ipstr, e.sip);

    if (res) {
      if (p.peerip_count >= e.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = e;
      return &result;
    }
  }
	for (auto f : models[5]) {
    if (port == f.dport) {
      if (p.peerip_count >= f.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = f;
      return &result;
    }
  }
  for (auto h : models[6]) {
    if (proto == h.protocol) {
      if (p.peerip_count >= h.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = h;
      return &result;
    }
  }
	for (auto i : models[7]) {
    if (p.peerip_count >= i.peers) {
      result.res = true;
    } else {
      result.res = false;
    }
    result.pat = i;
    return &result;
  }
  return nullptr;
}

void PortScanFilter::GenerateEvents(
    const PortScanKey& s, const ScanStat& p, GenEventRes* events) {
	struct Match_res result;
  auto res = Pickout(s, p, result, event_models);
  if (res && res->res && (res->pat.max == 0 || p.peerip_count < res->pat.max)) {
    Generate(s, p, events, res->pat);
  }
  return;
}

void PortScanFilter::GenerateFeature(const PortScanKey& s, const ScanStat& p) {
  struct Match_res result;
  auto res = Pickout(s, p, result, feature_models);
  if (res && res->res && p.flows >= res->pat.flows) {
    InsertScanToTSDB(s, p);
  }
  return;
}
