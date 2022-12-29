#include "ip_scan_filter.h"
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

IPScanFilter::IPScanFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}

IPScanFilter* IPScanFilter::Create(u32 dev_id, const string& model,
                                     DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new IPScanFilter(dev_id, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_ipscan"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_ipscan"));
  if (DEBUG) log_info("Scanner filter initialized.\n");
  return filter;
}

bool IPScanFilter::CheckFlow(FlowPtr flow) {
  auto r = (master_record_t*)flow;
  uint32_t sip[4];
  uint32_t dip[4];
  memset(sip, 0, sizeof(uint)*4);
  memset(dip, 0, sizeof(uint)*4);
  if (model_ == "V6") {
    sip[0] = ( r->v6.dstaddr[0] >> 32 ) & 0xffffffffLL;
    sip[1] = r->v6.dstaddr[0] & 0xffffffffLL;
    sip[2] = ( r->v6.dstaddr[1] >> 32 ) & 0xffffffffLL;
    sip[3] = r->v6.dstaddr[1] & 0xffffffffLL;
    dip[0] = ( r->v6.dstaddr[0] >> 32 ) & 0xffffffffLL;
    dip[1] = r->v6.dstaddr[0] & 0xffffffffLL;
    dip[2] = ( r->v6.dstaddr[1] >> 32 ) & 0xffffffffLL;
    dip[3] = r->v6.dstaddr[1] & 0xffffffffLL;
  } else {
    sip[0] = r->v4.srcaddr;
    dip[0] = r->v4.dstaddr;
  }

  IPScanKey k;
  std::copy(sip, sip+4, k.sip);
  std::copy(dip, dip+4, k.dip);
  k.proto = r->prot;
  auto timestamp = r->first - r->first % tsdb_->time_unit();
  auto it = caches_.find(timestamp);
  if (it == caches_.end()) {
    auto& cache = caches_[timestamp];
    tsdb_->Scan(timestamp, timestamp, 
               [&cache](const Slice& key, const Slice&) {
                 cache.insert(*(const IPScanKey*)key.data());
               });
    it = caches_.find(timestamp);
  }  
  r->scanner = it->second.count(k) ? 1 : 0;
  return r->scanner;
}

bool IPScanFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot == 17) continue;
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

bool IPScanFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot == 17) continue;
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


void IPScanFilter::UpdateScans(u32 first, u32 last, u16 proto, u32 ip[], u16 port, u32 peerip[],
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
  IPScanKey scan;
  std::copy(ip, ip+4, scan.sip);
  scan.proto = proto;
  std::copy(peerip, peerip+4, scan.dip);
  auto it = scans_.find(scan);
  if (it == scans_.end()) {
    IPScanStat p;
    memset(&p, 0, sizeof(struct IPScanStat));
    p.first = first;
    p.last = last;
    p.peerport_count = 1;
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
    if (rv.second) ++p.peerport_count;
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

bool IPScanFilter::LoadPatternFromFile() {
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
    if (res[0] != "IP_SCAN") continue;
    pat.type = res[0];
    pat.sip = res[1];
    pat.dip = res[3];
    pat.protocol = res[5];
    if (res[6].empty()) continue;
    pat.peers = atol(res[6].c_str());
    pat.flows = res[7].empty() ? 0 : atol(res[7].c_str());
    DividePatterns(pat, res);
  }
	feature_models.push_back(ip_peerip_proto_);
  feature_models.push_back(ip_peerip_);
  feature_models.push_back(ip_proto_);
  feature_models.push_back(peerip_proto_);
  feature_models.push_back(ip_);
  feature_models.push_back(peerip_);
  feature_models.push_back(proto_);
  feature_models.push_back(peers_);
  return true;
}

void IPScanFilter::DividePatterns(Pattern& pat, vector<string>& res) {
  if (!res[1].empty() && !res[3].empty() && !res[5].empty()) {
    ip_peerip_proto_.emplace(pat);
  } else if (!res[1].empty() && !res[3].empty() && res[5].empty()) {
    ip_peerip_.emplace(pat);
  } else if (!res[1].empty() && res[3].empty() && !res[5].empty()) {
    ip_proto_.emplace(pat);
  } else if (res[1].empty() && !res[3].empty() && !res[5].empty()) {
    peerip_proto_.emplace(pat);
  } else if (!res[1].empty() && res[3].empty() && res[5].empty()) {
    ip_.emplace(pat);
  } else if (res[1].empty() && !res[3].empty() && res[5].empty()) {
    peerip_.emplace(pat);
  } else if (res[1].empty() && res[3].empty() && !res[5].empty()) {
    proto_.emplace(pat);
  } else {
    peers_.emplace(pat);
  }
}

event::GenEventRes IPScanFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<IPScanFilter>& ptr, const string& model) {
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


void IPScanFilter::InsertScanToTSDB(const IPScanKey& s, const IPScanStat& stat) {
  /*if (DEBUG) {
    ostringstream oss;
    oss << "Found scanner: " << datetime::format_timestamp(stat.first) << ' '
        << stat.last - stat.first << "s PROTO:" << proto_to_string(s.proto) << ' '
        << ipnum_to_ipstr(s.ip) << " -> " << stat.peerport_count << " ips port:"
        << s.port << " flows:" << stat.flows << " pkts:" << stat.pkts
        << " bytes" << stat.bytes << '\n';
    log_info("%s\n", oss.str().c_str());
  }*/

  IPScanStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(IPScanStat))) {
    auto* old_stat = (IPScanStat*)old_value.data();
    new_stat.first = std::min(stat.first, old_stat->first);
    new_stat.last = std::max(stat.last, old_stat->last);
    new_stat.peerport_count = stat.peerport_count + old_stat->peerport_count;
    new_stat.flows = stat.flows + old_stat->flows;
    new_stat.pkts = stat.pkts + old_stat->pkts;
    new_stat.bytes = stat.bytes + old_stat->bytes;
    strcpy(new_stat.app_proto, old_stat->app_proto);
  } else {
    new_stat = stat;
  }
  tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}


void IPScanFilter::FilterScan(const feature::FeatureReq& req,
                                   feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckScan(key, value, req);
    });

  for (auto it = res_ipscan_.begin(); it != res_ipscan_.end(); ++it) 
    resp->MergeFrom(it->second);
}

void IPScanFilter::FilterScanEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckScanEvent(key, value, req, resp);
    });
}

void IPScanFilter::AddRecord(const IPScanKey& key, const FeatureRecord& new_rec) {
  auto it = res_ipscan_.find(key);
  if (it == res_ipscan_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_ipscan_[key] = resp;
  } else {
    auto& resp = res_ipscan_[key];
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

void IPScanFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void IPScanFilter::CheckScanEvent(const Slice& key, const Slice& value,
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

void IPScanFilter::CheckScan(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const IPScanKey& svckey = *(const IPScanKey*)key.data();
  const IPScanStat& stat = *(const IPScanStat*)value.data();
  if (stat.last < req.starttime() || stat.first > req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(svckey.sip, svckey.sip+4, sip6.s6_addr32);
    std::copy(svckey.dip, svckey.dip+4, dip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(svckey.sip[0]);
    dip = ipnum_to_ipstr(svckey.dip[0]);
  }

  if (req.has_sip() && req.sip() != sip) return;
  if (req.has_proto() && req.proto() != svckey.proto) return;
  if (req.has_dip() && req.dip() != dip) return;
  if (req.has_peers() && req.peers() > stat.peerport_count) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_duration(stat.last - stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_protocol(svckey.proto);
  rec.set_peers(stat.peerport_count);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);
  rec.set_app_proto(stat.app_proto);  

  if (DEBUG) log_info("Got IPScanner Record: %s\n", rec.DebugString().c_str());
  AddRecord(svckey, rec);
}

///////////////////////////////////////////////////////////////////////////////
// IPScanFilter::EventGenerator
///////////////////////////////////////////////////////////////////////////////

void IPScanFilter::DivideMode() {
  std::set<Pattern> sip_dip_prot;
  std::set<Pattern> sip_dip;
  std::set<Pattern> sip_prot;
  std::set<Pattern> dip_prot;
  std::set<Pattern> sip;
  std::set<Pattern> dip;
  std::set<Pattern> prot;
  std::set<Pattern> min;
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

		for (int i=0;i<event_config.weekday_size(); ++i) {
      pat.weekday.push_back(event_config.weekday(i));
    }
    pat.coverrange = event_config.coverrange();
    pat.stime_hour = event_config.stime_hour();
    pat.stime_min = event_config.stime_min();
    pat.stime_sec = event_config.stime_sec();
    pat.etime_hour = event_config.etime_hour();
    pat.etime_min = event_config.etime_min();
    pat.etime_sec = event_config.etime_sec();

		if (event_config.has_sip() && event_config.has_dip() && event_config.has_protocol()) {
    	pat.sip = event_config.sip();
    	pat.dip = event_config.dip();
    	pat.protocol = event_config.protocol();
    	sip_dip_prot.emplace(pat);
  	} else if (event_config.has_sip() && event_config.has_dip() && !event_config.has_protocol()) {
    	pat.sip = event_config.sip();
    	pat.dip = event_config.dip();
    	sip_dip.emplace(pat);
  	} else if (event_config.has_sip() && !event_config.has_dip() && event_config.has_protocol()) {
    	pat.sip = event_config.sip();
    	pat.protocol = event_config.protocol();
    	sip_prot.emplace(pat);
  	} else if (!event_config.has_sip() && event_config.has_dip() && event_config.has_protocol()) {
    	pat.dip = event_config.dip();
    	pat.protocol = event_config.protocol();
    	dip_prot.emplace(pat);
  	} else if (event_config.has_sip() && !event_config.has_dip() && !event_config.has_protocol()) {
    	pat.sip = event_config.sip();
    	sip.emplace(pat);
  	} else if (!event_config.has_sip() && event_config.has_dip() && !event_config.has_protocol()) {
    	pat.dip = event_config.dip();
    	dip.emplace(pat);
  	} else if (!event_config.has_sip() && !event_config.has_dip() && event_config.has_protocol()) {
    	pat.protocol = event_config.protocol();
    	prot.emplace(pat);
  	} else {
    	min.emplace(pat);
  	}
	}
	event_models.push_back(sip_dip_prot);
  event_models.push_back(sip_dip);
  event_models.push_back(sip_prot);
  event_models.push_back(dip_prot);
  event_models.push_back(sip);
  event_models.push_back(dip);
  event_models.push_back(prot);
  event_models.push_back(min);
}

IPScanFilter::EventGenerator::EventGenerator(
    const config::Event& e, u32 devid, u32 st, u32 et)
    : event_config(e), dev_id(devid), start_time(st), end_time(et) {
  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void IPScanFilter::Generate(const IPScanKey& s, const IPScanStat& p, GenEventRes* events, Pattern& pat) {
	if (common_model_filter::filter_time_range(pat)) {
  	auto e = events->add_records();
  	e->set_time(pat.start_time);
  	e->set_type_id(pat.type_id);
  	e->set_config_id(pat.config_id);
  	e->set_devid(dev_id_);
    if (model_ == "V6") {
      struct in6_addr sip6, dip6;
      std::copy(s.sip, s.sip+4, sip6.s6_addr32);
      std::copy(s.dip, s.dip+4, dip6.s6_addr32);
      e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]: " +
                proto_to_string(s.proto) + " ");
    } else
  	  e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>" + ipnum_to_ipstr(s.dip[0]) + ": " +
                proto_to_string(s.proto) + " ");
  	e->set_thres_value(pat.peers);
  	e->set_alarm_value(p.peerport_count);
  	e->set_value_type("peerports");
    e->set_model_id(0);

    //生成事件特征数据，即事件五元组详细信息
    GenEventFeature(s, e);
  	if (DEBUG) log_info("Generated ipscan event: %s\n", e->DebugString().c_str());
	}
}

void IPScanFilter::GenEventFeature(const IPScanKey& s, const event::GenEventRecord* e) {
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

void IPScanFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}

Match_res* IPScanFilter::Pickout(const IPScanKey& s, const IPScanStat& p,
                                struct Match_res& result, vector<set<Pattern>>& models) {
  string sipstr, dipstr;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(s.sip, s.sip+4, sip6.s6_addr32);
    std::copy(s.dip, s.dip+4, dip6.s6_addr32);
    sipstr = ipnum_to_ipstr_v6(sip6);
    dipstr = ipnum_to_ipstr_v6(dip6);
  } else {
    sipstr = ipnum_to_ipstr(s.sip[0]);
    dipstr = ipnum_to_ipstr(s.dip[0]);
  }
  string proto = proto_to_string(s.proto);

	for (auto a : models[0]) {
    bool sres, dres;
    if (model_ == "V6") {
      sres = valid_ip_v6(sipstr, a.sip);
      dres = valid_ip_v6(dipstr, a.dip);
    } else {
      sres = valid_ip(sipstr, a.sip);
      dres = valid_ip(dipstr, a.dip);
    }

    if (sres && dres && proto == a.protocol) {
      if (p.peerport_count >= a.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = a;
      return &result;
    }
  }
  for (auto b : models[1]) {
    bool sres, dres;
    if (model_ == "V6") {
      sres = valid_ip_v6(sipstr, b.sip);
      dres = valid_ip_v6(dipstr, b.dip);
    } else {
      sres = valid_ip(sipstr, b.sip);
      dres = valid_ip(dipstr, b.dip);
    }

    if (sres && dres) {
      if (p.peerport_count >= b.peers) {
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
      res = valid_ip_v6(sipstr, c.sip);
    else
      res = valid_ip(sipstr, c.sip);

    if (res && proto == c.protocol) {
      if (p.peerport_count >= c.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = c;
      return &result;
    }
  }
  for (auto d : models[3]) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(dipstr, d.dip);
    else
      res = valid_ip(dipstr, d.dip);    

    if (res && proto == d.protocol) {
      if (p.peerport_count >= d.peers) {
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
      res = valid_ip_v6(sipstr, e.sip);
    else
      res = valid_ip(sipstr, e.sip);

    if (res) {
      if (p.peerport_count >= e.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = e;
      return &result;
    }
  }
	for (auto f : models[5]) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(dipstr, f.dip);
    else
      res = valid_ip(dipstr, f.dip);

    if (res) {
      if (p.peerport_count >= f.peers) {
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
      if (p.peerport_count >= h.peers) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = h;
      return &result;
    }
  }
	for (auto i : models[7]) {
    if (p.peerport_count >= i.peers) {
      result.res = true;
    } else {
      result.res = false;
    }
    result.pat = i;
    return &result;
  }
  return nullptr;
}

void IPScanFilter::GenerateEvents(
    const IPScanKey& s, const IPScanStat& p, GenEventRes* events) {
	struct Match_res result;
  auto res = Pickout(s, p, result, event_models);
  if (res && res->res && (res->pat.max == 0 || p.peerport_count < res->pat.max)) {
    Generate(s, p, events, res->pat);
  }
  return;
}

void IPScanFilter::GenerateFeature(const IPScanKey& s, const IPScanStat& p) {
  struct Match_res result;
  auto res = Pickout(s, p, result, feature_models);
  if (res && res->res && p.flows >= res->pat.flows) {
    InsertScanToTSDB(s, p);
  }
  return;
}
