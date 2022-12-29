#include "service_filter.h"
#include "common_model_filter.hpp"
#include "../../common/common.h"
#include "../dump/libnfdump.h"
#include "../../common/log.h"
#include "../../common/ip.h"
#include "../../common/datetime.h"
#include "../../common/strings.h"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include "../define.h"
#include <utility>

using namespace std;

static std::set<Pattern> dip_dport_prot_;
static std::set<Pattern> dip_dport_;
static std::set<Pattern> dip_prot_;
static std::set<Pattern> dport_prot_;
static std::set<Pattern> dip_;
static std::set<Pattern> dport_;
static std::set<Pattern> prot_;
static std::set<Pattern> min_;
static set<u16> udp_port{7, 53, 80, 111, 123, 137, 161, 162, 177, 389, 427, 443, 500, 514, 520, 623, 626,
                    1194, 1604, 2049, 2302, 3283, 3784, 5351, 5353, 5683, 6481, 8767, 9987, 10080, 17185,
                    11211, 26000, 27910, 64738};

ServiceFilter::ServiceFilter(u32 dev_id, const string& model, unique_ptr<TSDB> tsdb)
	: FlowFilter(), dev_id_(dev_id), model_(model), tsdb_(std::move(tsdb)) {}

ServiceFilter* ServiceFilter::Create(u32 dev_id, const string& model, DBBuilder* builder) {
	
	auto* filter = new ServiceFilter(
		dev_id, model, unique_ptr<TSDB>(new TSDB(builder, to_string(dev_id) + "_feature_srv")));
  if (DEBUG) log_info("service filter initialized for update.\n");
  return filter;
}

bool ServiceFilter::CheckFlow(FlowPtr flow) {
	auto r = (master_record_t*)flow;
  uint32_t dip[4];
  memset(dip, 0, sizeof(uint)*4);
  if (model_ == "V6") {
    dip[0] = ( r->v6.dstaddr[0] >> 32 ) & 0xffffffffLL;
    dip[1] = r->v6.dstaddr[0] & 0xffffffffLL;
    dip[2] = ( r->v6.dstaddr[1] >> 32 ) & 0xffffffffLL;
    dip[3] = r->v6.dstaddr[1] & 0xffffffffLL;
  } else
	  dip[0] = r->v4.dstaddr;
	
	PvcKey k;
  std::copy(dip, dip+4, k.ip);
  k.proto = r->prot;
  k.port = r->dstport;
  k.srv_mark = 0;
	auto timestamp = r->first - r->first % tsdb_->time_unit();	
	auto it = caches_.find(timestamp);
	if (it == caches_.end()) {
		auto& cache = caches_[timestamp];
		tsdb_->Scan(timestamp, timestamp, [&cache](const Slice& key, const Slice&) {
								cache.insert(*(const PvcKey*)key.data());
								});
		it = caches_.find(timestamp);
	}

	r->service = it->second.count(k) ? 2 : 0; 
	return r->service;
}
    
bool ServiceFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  if (flowset->size() == 0) return false;
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot != 6 && r.prot != 17) continue;
    if (r.prot == 17 && (!udp_port.count(r.srcport) && !udp_port.count(r.dstport))) continue;
    if (r.srcport == 0 || r.dstport == 0) continue;

    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    UpdateService(r.first, r.last, sip, r.srcport, r.prot, dip, r.dstport, r.tos, r.pname, r.dPkts, r.dOctets);
  }
  return true;
}

bool ServiceFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  if (flowset->size() == 0) return false;
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot != 6 && r.prot != 17) continue;
    if (r.prot == 17 && (!udp_port.count(r.srcport) && !udp_port.count(r.dstport))) continue;
    if (r.srcport == 0 || r.dstport == 0) continue;

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

    UpdateService(r.first, r.last, sip, r.srcport, r.prot, dip, r.dstport, r.tos, r.pname, r.dPkts, r.dOctets);
  }
  return true;
}


void ServiceFilter::UpdateService(u32 first, u32 last, u32 sip[], u16 sport, u16 proto, u32 dip[], 
		                                  u16 dport, u8 tos, char* pname, u64 pkts, u64 bytes) {
  if (proto == 6) {
    if (tos & 0x01) {
      PvcKey req;
      std::copy(dip, dip+4, req.ip);
      req.proto = proto;
      req.port = dport;
      req.srv_mark = 0;
      PvcKey restos;
      std::copy(sip, sip+4, restos.ip);
      restos.proto = proto;
      restos.port = sport;
      restos.srv_mark = 1;
      srvtos_.insert(restos);
      auto it = srvreq_.find(req);
      if (it == srvreq_.end()) {
        PortStat p;
        memset(&p, 0, sizeof(struct PortStat));
        p.first = first;
        p.last = last;
        p.flow_count = 1;
        memcpy(p.app_proto, pname, strlen(pname)+1);
        p.pkts = pkts;
        p.bytes = bytes;
        srvreq_[req] = p;
      } else {
        auto& p = it->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flow_count++;
        memcpy(p.app_proto, pname, strlen(pname)+1);
        p.pkts += pkts;
        p.bytes += bytes;
      }
    }
    PvcKey res;
    std::copy(sip, sip+4, res.ip);
    res.proto = proto;
    res.port = sport;
    res.srv_mark = 1;

    auto it = srvres_.find(res);
    if (it == srvres_.end()) {
      PortStat p;
      memset(&p, 0, sizeof(struct PortStat));
      p.first = first;
      p.last = last;
      p.flow_count = 1;
      memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts = pkts;
      p.bytes = bytes;
      srvres_[res] = p;
    } else {
      auto& p = it->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      p.flow_count++;
      memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts += pkts;
      p.bytes += bytes;
    }
  } else {   //not tcp
    PvcKey req;
    std::copy(dip, dip+4, req.ip);
    req.proto = proto;
    req.port = dport;
    req.srv_mark = 0;

    auto it = srvreq_.find(req);
    if (it == srvreq_.end()) {
      PortStat p;
      memset(&p, 0, sizeof(struct PortStat));
      p.first = first;
      p.last = last;
      p.flow_count = 1;
      memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts = pkts;
      p.bytes = bytes;
      srvreq_[req] = p;
    } else {
      auto& p = it->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      p.flow_count++;
      memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts += pkts;
      p.bytes += bytes;
    }
    PvcKey res;
    std::copy(sip, sip+4, res.ip);
    res.proto = proto;
    res.port = sport;
    res.srv_mark = 1;

    auto its = srvres_.find(res);
    if (its == srvres_.end()) {
      PortStat p;
      memset(&p, 0, sizeof(struct PortStat));
      p.first = first;
      p.last = last;
      p.flow_count = 1;
      memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts = pkts;
      p.bytes = bytes;
      srvres_[res] = p;
    } else {
      auto& p = its->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      p.flow_count++;
      memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts += pkts;
      p.bytes += bytes;
    }
  } 
}

bool ServiceFilter::LoadPatternFromFile() {
  ifstream ifs(AGENT_PAT_FILE);
  if (!ifs.is_open()) {
    log_err(__FILE__": failed to load pattern config: %s\n", AGENT_PAT_FILE);
    return false;
  }

  string line;
  Pattern pat;

  while(getline(ifs, line)) {

		trim(line);
    if (line.empty() || line[0] == '#') continue;
    size_t pos = line.find(",");
    size_t size = line.size();
    vector<string> res;

    while (pos != std::string::npos) {
      string x = line.substr(0, pos);
      res.push_back(trim(x));
      line = line.substr(pos+1, size-pos-1);
      pos = line.find(",");
    }
    res.push_back(line);
    auto result = find(type_.begin(), type_.end(), res[0]);
    if (result == type_.end()) continue;
    pat.type = res[0];
    pat.dip = res[3];
    pat.dport = res[4];
    pat.protocol = res[5];
    if (res[7].empty()) continue;
    pat.flows = atol(res[7].c_str());
    DividePatterns(pat, res);
  }
  return true;
}

void ServiceFilter::DividePatterns(Pattern& pat, vector<string>& res) {

  if (res[0] == "SRV") {
    if (!res[3].empty() && !res[4].empty() && !res[5].empty()) {
      dip_dport_prot_.emplace(pat);
    } else if (!res[3].empty() && !res[4].empty() && res[5].empty()) {
      dip_dport_.emplace(pat);
    } else if (!res[3].empty() && res[4].empty() && !res[5].empty()) {
      dip_prot_.emplace(pat);
    } else if (res[3].empty() && !res[4].empty() && !res[5].empty()) {
      dport_prot_.emplace(pat);
    } else if (!res[3].empty() && res[4].empty() && res[5].empty()) {
      dip_.emplace(pat);
    } else if (res[3].empty() && !res[4].empty() && res[5].empty()) {
      dport_.emplace(pat);
    } else if (res[3].empty() && res[4].empty() && !res[5].empty()) {
      prot_.emplace(pat);
    } else {
      min_.emplace(pat);
    }
  }
}

void ServiceFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<ServiceFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);
  if (!ptr->LoadPatternFromFile()) {
    log_err("Can't load config file.\n");
    return;
  }

  for (auto it=ptr->srvtos_.begin();it!=ptr->srvtos_.end();it++) {
    if (ptr->srvres_.count(*it)) {
      ptr->srvres_.erase(*it);
    }
  }

  for (auto it=ptr->srvres_.begin();it!=ptr->srvres_.end();it++) {
    auto& s = it->first;
    auto& p = it->second;
    PvcKey res; 
    std::copy(s.ip, s.ip+4, res.ip);
    res.proto = s.proto;
    res.port = s.port;
    res.srv_mark = 0;
    if (ptr->srvreq_.count(res)) {
      if (s.proto == 17) {
        if (!udp_port.count(s.port)) continue;
      }
      ptr->GenerateFeature(s, p);
      ptr->GenerateFeature(res, ptr->srvreq_[res]);
    }
  }
}

void ServiceFilter::InsertSrvToTSDB(const PvcKey& s, const PortStat& stat) {
	PortStat new_stat;
	Slice old_value;
	if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
			(old_value.size() >= sizeof(PortStat))) {
		auto* old_stat = (PortStat*)old_value.data();
		new_stat.first = std::min(stat.first, old_stat->first);
		new_stat.last = std::max(stat.last, old_stat->last);
		new_stat.flow_count = stat.flow_count + old_stat->flow_count;
		new_stat.pkts = stat.pkts + old_stat->pkts;
		new_stat.bytes = stat.bytes + old_stat->bytes;
    strcpy(new_stat.app_proto, old_stat->app_proto);
	} else {
		new_stat = stat;
	}
	tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}

void ServiceFilter::FilterService(const feature::FeatureReq& req, feature::FeatureResponse* resp){
	tsdb_->Scan(req.starttime(), req.endtime(),
		[this, &req, resp](const Slice& key, const Slice& value) {
			CheckService(key, value, req);
		});

  for (auto it = res_srv_.begin(); it != res_srv_.end(); ++it)
    resp->MergeFrom(it->second);
}

void ServiceFilter::AddRecord(const PvcKey& key, const FeatureRecord& new_rec) {
  auto it = res_srv_.find(key);
  if (it == res_srv_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_srv_[key] = resp;
  } else {
    auto& resp = res_srv_[key];
    for (s32 i = 0; i < resp.records_size(); i++) {
      auto rec = resp.mutable_records(i);

      u32 s1 = rec->time();
      u32 e1 = s1 + rec->duration();
      u32 s2 = new_rec.time();
      u32 e2 = s2 + new_rec.duration();
      if (e1 + INTERVAL < s2) continue;
      if (e2 + INTERVAL < s1) continue;
      u32 mins = std::min(s1,s2);
      u32 maxe = std::max(e1,e2);
      rec->set_time(mins);
      rec->set_duration(maxe - mins);
      rec->set_bytes(rec->bytes() + new_rec.bytes());
      rec->set_pkts(rec->bytes() + new_rec.pkts());
      rec->set_flows(rec->flows() + new_rec.flows()); 
      rec->set_srv_mark(new_rec.srv_mark());
      rec->set_app_proto(new_rec.app_proto());
      return;
    }
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void ServiceFilter::CheckService(const Slice& key, const Slice& value,
												const feature::FeatureReq& req) {
	const PvcKey& pvckey = *(const PvcKey*)key.data();
	const PortStat& stat = *(const PortStat*)value.data();

	if (stat.last < req.starttime() || stat.first > req.endtime()) return;
  string ip;
  if (model_ == "V6") {
    struct in6_addr ip6;
    std::copy(pvckey.ip, pvckey.ip+4, ip6.s6_addr32);
    ip = ipnum_to_ipstr_v6(ip6);
  } else
    ip = ipnum_to_ipstr(pvckey.ip[0]);

	if (req.has_ip() && req.ip() != ip) return;
	if (req.has_proto() && req.proto() != pvckey.proto) return;
	if (req.has_port() && req.port() != pvckey.port) return;
	if (req.has_flows() && req.flows() > stat.flow_count) return;
  if (req.has_srv_mark() && req.srv_mark() != pvckey.srv_mark) return;
	
  FeatureRecord rec;
	rec.set_time(stat.first);
	rec.set_duration(stat.last-stat.first);
	rec.set_ip(ip);
	rec.set_port(pvckey.port);
	rec.set_protocol(pvckey.proto);
	rec.set_flows(stat.flow_count);
	rec.set_pkts(stat.pkts);
	rec.set_bytes(stat.bytes);
  rec.set_app_proto(stat.app_proto);
  if (pvckey.srv_mark)
    rec.set_srv_mark("res");
  else
    rec.set_srv_mark("req");

	if (DEBUG) log_info("Got Dos Record: %s\n", rec.DebugString().c_str());
	AddRecord(pvckey, rec);
}

///////////////////////////////////////////////////////////////////////

Match_res* ServiceFilter::Pickout(const PvcKey& s, const PortStat& p, 
                                struct Match_res& result) {
  string ipstr;
  if (model_ == "V6") {
    struct in6_addr ip6;
    std::copy(s.ip, s.ip+4, ip6.s6_addr32);
    ipstr = ipnum_to_ipstr_v6(ip6);
  } else
    ipstr = ipnum_to_ipstr(s.ip[0]);

  //string port = to_string(s.port);
  string app_proto = p.app_proto;  
  string proto = proto_to_string(s.proto);
  for (auto a : dip_dport_prot_) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, a.dip);
    else
      res = valid_ip(ipstr, a.dip);
    // if (res && port == a.dport
    if (res && (to_string(s.port) == a.dport || boost::to_upper_copy(app_proto) == boost::to_upper_copy(a.dport))
        && proto == a.protocol) {
      if (p.flow_count >= a.flows) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = a;
      return &result;
    }
  }
  for (auto b : dip_dport_) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, b.dip);
    else
      res = valid_ip(ipstr, b.dip);

    // if (res && port == b.dport) {
    if (res && (to_string(s.port) == b.dport || boost::to_upper_copy(app_proto) == boost::to_upper_copy(b.dport))) {
      if (p.flow_count >= b.flows) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = b;
      return &result;
    }
  }
  for (auto c : dip_prot_) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, c.dip);
    else
      res = valid_ip(ipstr, c.dip);

    if (res && proto == c.protocol) {
      if (p.flow_count >= c.flows) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = c;
      return &result;
    }
  }
  for (auto d : dport_prot_) {
    // if (port == d.dport && proto == d.protocol) { 
    if ((to_string(s.port) == d.dport || boost::to_upper_copy(app_proto) == boost::to_upper_copy(d.dport)) && proto == d.protocol) { 
      if (p.flow_count >= d.flows) {
        result.res = true;   
      } else {
        result.res = false;
      }
      result.pat = d;
      return &result;
    }
  }
  for (auto e : dip_) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, e.dip);
    else
      res = valid_ip(ipstr, e.dip);

    if (res) {
      if (p.flow_count >= e.flows) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = e;
      return &result;
    }
  }
  for (auto f : dport_) {
    // if (port == f.dport) { 
    if ((to_string(s.port) == f.dport || boost::to_upper_copy(app_proto) == boost::to_upper_copy(f.dport))) { 
      if (p.flow_count >= f.flows) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = f;
      return &result;
    }
  }
  for (auto h : prot_) {
    if (proto == h.protocol) { 
      if (p.flow_count >= h.flows) {
        result.res = true;
      } else {
        result.res = false;
      }
      result.pat = h;
      return &result;
    }
  }
  for (auto i : min_) {
    if (p.flow_count >= i.flows) {
      result.res = true;
    } else {
      result.res = false;
    }
    result.pat = i;
    return &result;
  }  
  return nullptr;
}

void ServiceFilter::GenerateFeature(const PvcKey& s, const PortStat& p) {
  struct Match_res result;
  auto res = Pickout(s, p, result);
  if (res && res->res) {
    InsertSrvToTSDB(s, p);
  }
  return;
}
