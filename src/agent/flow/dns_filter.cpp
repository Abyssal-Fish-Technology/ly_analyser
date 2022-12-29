#include "dns_filter.h"
#include "../../common/common.h"
#include "../../common/ip.h"
#include "../../common/asset.h"
#include "../../common/md5.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/datetime.h"
#include "../../common/common_filter.hpp"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include <utility>

#define SPECICAL_CHARACTOR_PATTERN "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\\.?$"

namespace {

void LoadDomainFromFile(const string& file_name, std::map<string, string>& domains) {
  try {
    ifstream ifs(file_name);
    string line;
    size_t pos;
    string domain, type;
    while (getline(ifs, line)) {
      trim(line);
      if (line.empty() || line[0] == '#') continue;
      pos = line.find(",");
      if (pos != std::string::npos) {
        domain = line.substr(0,pos);
        type = line.substr(pos + 1);
        domains[domain] = type;
      }
    }
  } catch (...) {
     log_warning("Could not load domain from file %s\n", file_name.c_str());
  }
}
}

DnsFilter::DnsFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}

DnsFilter* DnsFilter::Create(u32 dev_id, const string& model,
                             DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new DnsFilter(dev_id, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_dns"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_dns"));
  if (DEBUG) log_info("Dns filter initialized.\n");
  return filter;
}

bool DnsFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    string qname = r.qname;
    if ((qname.size()>0) && (r.tos & 0x01 )) {
      UpdateDns(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.qname, r.qtype, r.dPkts, r.dOctets);
    }
  }
  return true;
}

bool DnsFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
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
 
    string qname = r.qname;
    if ((qname.size()>0) && (r.tos & 0x01 )) {
      UpdateDns(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.qname, r.qtype, r.dPkts, r.dOctets);
    }
  }
  return true;
}


bool DnsFilter::JudgeSpecChar(const string& str) {
  regex pattern(SPECICAL_CHARACTOR_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(str, m, pattern);
}

void DnsFilter::UpdateDns(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, char *qname, 
                                     u16 qtype, u64 pkts, u64 bytes) {

  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;
  memcpy(event.domain, qname, strlen(qname) + 1);
  event.qtype = qtype;

  DnsKey dns;
  string domain = qname;
  if (!JudgeSpecChar(domain)) return; 
  
  memset(&dns, 0, sizeof(struct DnsKey));
  std::copy(sip, sip+4, dns.sip);
  std::copy(dip, dip+4, dns.dip);
  memcpy(dns.qname, qname, strlen(qname) + 1);
  dns.qtype = qtype;

  auto it = dns_.find(dns);
  if (it == dns_.end()) {
    DnsStat p;
    memset(&p, 0, sizeof(struct DnsStat));
    p.first = first;
    p.last = last;
    p.flows = 1;
    p.pkts = pkts;
    p.bytes = bytes;
    dns_[dns] = p;

    //统计五元组信息
    EventValue ep;
    ep.first = first;
    ep.last = last;
    ep.flows = 1;
    ep.pkts = pkts;
    ep.bytes = bytes;
    map<EventKey, EventValue> event_tmp;
    event_tmp[event] = ep;
    event_details_[dns] = event_tmp;
  } else {
    auto& p = it->second;
    p.first = MIN(p.first, first);
    p.last = MAX(p.last, last);
    ++p.flows;
    p.pkts += pkts;
    p.bytes += bytes;

    //统计五元组信息
    auto itr = event_details_[dns].find(event);
    if (itr == event_details_[dns].end()) {
      EventValue p;
      p.first = first;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      event_details_[dns][event] = p;
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

event::GenEventRes DnsFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<DnsFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);

  GenEventRes events;
  vector<set<string> > ip_vec;
  vector<set<string> > qname_vec;
  int cnt = 0;
  LoadDomainFromFile(AGENT_DOMAIN_FILE, ptr->domains_);
  for (auto it = ptr->dns_.begin(); it != ptr->dns_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;
    memset(p.bwclass, 0, MAXBWCLASSLEN);
    auto md5_str = MD5(s.qname).toString(); 
    if (ptr->domains_.count(md5_str)) {
      string str = ptr->domains_[md5_str];
      auto size = str.size();
      if (size >= MAXBWCLASSLEN) {
        size = MAXBWCLASSLEN;
        str[MAXBWCLASSLEN - 1] = '\0';
      }
      memcpy(p.bwclass, str.c_str(), size);
    }

    ptr->InsertDnsToTSDB(s, p);
    cnt++;
    for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
      auto event_config = ptr->event_generators_[i].event_config;
      if (cnt == 1) {
        string iplist = const_cast<char*>(event_config.ip().c_str());
        auto vec = split_string(iplist, ",");
        ip_vec.emplace_back(vec);
        string qnamelist = const_cast<char*>(event_config.qname().c_str());
        qname_vec.emplace_back(split_string(qnamelist, ","));
      }
      if (event_config.has_ip() && !event_config.ip().empty()) {
        bool flag = false;
        for (auto& ip : ip_vec[i]) {
          if (model == "V6") {
            struct in6_addr sip6;
            std::copy(s.sip, s.sip+4, sip6.s6_addr32);
            if (valid_ip_v6(ip, ipnum_to_ipstr_v6(sip6))) {
              flag = true;
              break;
            }
          } else {
            if (valid_ip(ip, ipnum_to_ipstr(s.sip[0]))) {
              flag = true;
              break;
            }
          }
        }
        if (!flag) continue;
      }
      //如果配置的qname字段为空，则碰撞ti_dns文件生成事件
      if (!event_config.has_qname() || event_config.qname().empty()) {
        if (ptr->domains_.find(MD5(s.qname).toString()) != ptr->domains_.end()) {
          if (p.flows > event_config.qcount()) {
            ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
            continue;
          }
        }
      } else {
        auto it = qname_vec[i].find(s.qname);
        if (it == qname_vec[i].end()) continue;
        else {
          if (p.flows > event_config.qcount())
            ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
        }
      }
    }
  }
 
  return events;
}

void DnsFilter::InsertDnsToTSDB(const DnsKey& s, const DnsStat& stat) {
  DnsStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(DnsStat))) {
    auto* old_stat = (DnsStat*)old_value.data();
    new_stat.first = std::min(stat.first, old_stat->first);
    new_stat.last = std::max(stat.last, old_stat->last);
    new_stat.pkts = stat.pkts + old_stat->pkts;
    new_stat.bytes = stat.bytes + old_stat->bytes;
    new_stat.flows =  stat.flows + old_stat->flows;
    strcpy(new_stat.bwclass,old_stat->bwclass);
  } else {
    new_stat = stat;
  }
  tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}

void DnsFilter::FilterDns(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckDns(key, value, req);
    });
  
  for (auto it = res_dns_.begin(); it != res_dns_.end(); ++it)
    resp->MergeFrom(it->second);
}

void DnsFilter::FilterDnsEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckDnsEvent(key, value, req, resp);
    });
}

void DnsFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void DnsFilter::AddRecord(const DnsKey& key, const FeatureRecord& new_rec) {
  auto it = res_dns_.find(key);
  if (it == res_dns_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_dns_[key] = resp;
  } else {
    auto& resp = res_dns_[key];
    for (s32 i = 0; i < resp.records_size(); ++i) {
      auto rec = resp.mutable_records(i);

      u32 s1 = rec->time();
      u32 s2 = new_rec.time();
      u32 mins = std::min(s1, s2);
      rec->set_time(mins);
      rec->set_bytes(rec->bytes() + new_rec.bytes());
      rec->set_pkts(rec->bytes() + new_rec.pkts());
      rec->set_flows(rec->flows() + new_rec.flows());
      rec->set_bwclass(new_rec.bwclass());
      return;
    }
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void DnsFilter::CheckDnsEvent(const Slice& key, const Slice& value,
                                  const eventfeature::EventFeatureReq& req,
                                  eventfeature::EventFeatureResponse* resp) {
  const EventKey& pvckey = *(const EventKey*)key.data();
  const EventValue& stat = *(const EventValue*)value.data();

  if (pvckey.time < req.starttime() || pvckey.time > req.endtime()) return;
  if (req.has_obj() && req.obj() != pvckey.obj) return;

  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
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
  rec.set_domain(pvckey.domain);
  rec.set_qtype(pvckey.qtype);
  rec.set_obj(pvckey.obj);
  rec.set_type(pvckey.type);
  rec.set_model(pvckey.model);
  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);

  if (DEBUG) log_info("Got Dos Record: %s\n", rec.DebugString().c_str());
  AddEventRecord(rec, resp);
}

void DnsFilter::CheckDns(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const DnsKey& dnskey = *(const DnsKey*)key.data();
  const DnsStat& stat = *(const DnsStat*)value.data();

  if (stat.first <= req.starttime() || stat.first >= req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(dnskey.sip, dnskey.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(dnskey.dip, dnskey.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(dnskey.sip[0]);
    dip = ipnum_to_ipstr(dnskey.dip[0]);
  }
    
  if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
  if (req.has_sip() && req.sip() != sip) return;
  if (req.has_dip() && req.dip() != dip) return;
  if (req.has_qname() && !strstr(dnskey.qname, req.qname().c_str())) return;
  if (req.has_qtype() && req.qtype() != dnskey.qtype) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_dport(53);
  rec.set_qname(dnskey.qname);
  rec.set_qtype(dnskey.qtype);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);
  rec.set_bwclass(stat.bwclass); 

  if (DEBUG) log_info("Got Dns Record: %s\n", rec.DebugString().c_str());
  AddRecord(dnskey, rec);
}

//////////////////////////////////////////////////////////////////
/* Generate events */

DnsFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et) 
  : event_config(e), dev_id(devid), start_time(st), end_time(et) {
  
  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void DnsFilter::GenerateEvents(const DnsKey& s, const DnsStat& p, GenEventRes* events, EventGenerator& gen) {
  auto event_config = gen.event_config;
  if (common_filter::filter_time_range(gen.start_time, event_config)) {
    auto e = events->add_records(); 
    e->set_time(gen.start_time);
    e->set_type_id(event_config.type_id());
    e->set_config_id(event_config.config_id());
    e->set_devid(gen.dev_id);
    if (model_ == "V6") {
      struct in6_addr sip6, dip6;
      std::copy(s.sip, s.sip+4, sip6.s6_addr32);
      std::copy(s.dip, s.dip+4, dip6.s6_addr32);
      e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]: " + p.bwclass + " " + s.qname);      
    } else
      e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>"+ ipnum_to_ipstr(s.dip[0]) + ": " + p.bwclass + " " + s.qname);  
    e->set_thres_value(event_config.qcount());
    e->set_alarm_value(p.flows);
    e->set_value_type(event_config.data_type());
    e->set_model_id(2);
    
    //生成事件特征数据，即事件五元组、域名详细信息
    GenEventFeature(s, e);
  }
}

void DnsFilter::GenEventFeature(const DnsKey& s, const event::GenEventRecord* e) {
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

void DnsFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}


