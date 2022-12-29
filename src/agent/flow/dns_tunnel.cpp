#include "dns_tunnel.h"
#include "../../common/ip.h"
#include "../../common/asset.h"
#include "../../common/md5.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/file.h"
#include "../../common/datetime.h"
#include "../../common/common_filter.hpp"
#include "../data/dbctx.pb.h"
#include <utility>

#define SPECICAL_CHARACTOR_PATTERN "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\\.?$"

DnstunnelFilter::DnstunnelFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}

DnstunnelFilter* DnstunnelFilter::Create(u32 dev_id, const string& model,
                             DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new DnstunnelFilter(dev_id, model);

  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_dnstunnel"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_dnstunnel"));

  if (DEBUG) log_info("Dns tunnel filter initialized.\n");
  return filter;
}

bool DnstunnelFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    string qname = r.qname;
    if (r.prot == 17 && r.dstport == 53) {
      UpdateDnstunnel(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.qname, r.qtype, r.dPkts, r.dOctets);
    }
  }
  return true;
}

bool DnstunnelFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
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
    if (r.prot == 17 && r.dstport == 53) {
      UpdateDnstunnel(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.qname, r.qtype, r.dPkts, r.dOctets);
    }
  }
  return true;
}

double DnstunnelFilter::DomainEntropy(const string& domain) {   //计算域名信息熵
if (!domain.size()) return 0;
  std::map<char, u32> dual_stat;
  for (auto ch : domain) {
    if (dual_stat.count(ch))
      dual_stat[ch]++;
    else
      dual_stat[ch] = 1;
  }

  double ent = 0;
  for (auto& it : dual_stat) {
    auto p = (double)it.second / domain.size();
    ent += (-log2(p) * p);
  }

  return ent;
}


void DnstunnelFilter::UpdateDnstunnel(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, 
                                      char *qname, u16 qtype, u64 pkts, u64 bytes) {
  if (qtype != 1 && qtype != 5 && qtype != 10 && qtype != 15 && qtype != 16)  return; // A,CNAME,NULL,MX,TXT
  string domain = qname;
  auto len = domain.size();
  if (len < 20) return;
  auto ret = whole_domain_.insert(domain);
  if (!ret.second) return;   //只出现一次的域名参与计算

  //截取二级域名、子域名
  string subdomain, fdomain;
  u32 num_of_point = count(domain.begin(), domain.end(), '.');
  if (num_of_point > 0) {
    size_t pos = domain.find(".");
    if (pos != std::string::npos)
      subdomain = domain.substr(0, pos);

    size_t rpos;
    if (domain[len-1] == '.')
      rpos = domain.rfind(".", len-2);
    else
      rpos = domain.rfind(".");
    if (rpos != std::string::npos) {
      size_t pos = domain.rfind(".", rpos-1);
      if (pos != std::string::npos)
        fdomain = domain.substr(pos+1);
      else
        fdomain = domain;
    }

    if (subdomain == "dnscat") { //dnscat2工具产生的隧道报子域名有dnscat标志
      fdomain == subdomain;
    }
    if (white_domains_.count(subdomain)) return;
    if (white_domains_.count(fdomain)) return;
  }


  DtKey dns;
  memset(&dns, 0, sizeof(DtKey));
  std::copy(sip, sip+4, dns.sip);
  std::copy(dip, dip+4, dns.dip);
  strcpy(dns.fqname, fdomain.c_str());

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

  DtStat p;
  p.first = first;
  p.last = last;
  p.flows = 1;
  p.pkts = pkts;
  p.bytes = bytes;
  
  auto it = all_fp_.find(dns);
  if (it == all_fp_.end()) {
    map<string, DtStat> tmp;
    tmp[domain] = p;
    all_fp_[dns] = tmp;

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
    all_fp_[dns][domain] = p;

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


event::GenEventRes DnstunnelFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<DnstunnelFilter>& ptr, const string& model) {
  LoadLineFromFile(AGENT_SUBDOMAIN_FILE, ptr->white_domains_);
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);

  GenEventRes events;
  vector<set<string> > all_vec;
  int num = 0;
  for (auto it = ptr->all_fp_.begin(); it != ptr->all_fp_.end(); ++it) {
    num++;
    auto& s = it->first;
    auto& p = it->second;

    for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
      auto event_config = ptr->event_generators_[i].event_config;
      if (num == 1) {
        string iplist = const_cast<char*>(event_config.ip().c_str());
        auto vec = split_string(iplist, ",");
        all_vec.emplace_back(vec);
      }
      if (event_config.has_ip() && !event_config.ip().empty()) {
        bool flag = false;
        for (auto& ip : all_vec[i]) {
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

      DtStat tmp;
      //dnscat2工具产生的隧道含有dnscat字符
      if (!strcmp(s.fqname, "dnscat")) {
        bool first = true;
        for (auto itr = p.begin(); itr != p.end(); ++itr) {
          auto& v = itr->second;
          if (first) {
            tmp.first = v.first;
            tmp.last = v.first;
            tmp.flows = v.flows;
            tmp.bytes = v.bytes;
            tmp.pkts = v.pkts;
            first = false;
          } else {
            tmp.first = MIN(tmp.first, v.first);
            tmp.last = MAX(tmp.last, v.last);
            tmp.flows += v.flows;
            tmp.bytes += v.bytes;
            tmp.pkts += v.pkts;
          }
        }
        ptr->GenerateEvents(s, tmp, &events, ptr->event_generators_[i]);
        continue;
      }
      {
        u32 cnt = 0;
        bool first = true;
        for (auto itr = p.begin(); itr != p.end();) {
          auto& v = itr->second;
          if (ptr->DomainEntropy(itr->first) > event_config.detvalue()) {//统计域名信息熵大于配置的值的数量
            cnt++;
            if (first) {
              tmp.first = v.first;
              tmp.last = v.first;
              tmp.flows = v.flows;
              tmp.bytes = v.bytes;
              tmp.pkts = v.pkts;
              first = false;
            } else {
              tmp.first = MIN(tmp.first, v.first);
              tmp.last = MAX(tmp.last, v.last);
              tmp.flows += v.flows;
              tmp.bytes += v.bytes;
              tmp.pkts += v.pkts;
            }
            ++itr;
          } else {
            itr = p.erase(itr);
          }
        }

        if (cnt > event_config.fqcount()) { //信息熵大于配置的值的域名数量大于阈值
          ptr->GenerateEvents(s, tmp, &events, ptr->event_generators_[i]);
        }
      }   

    }
  }
 
  return events;
}

void DnstunnelFilter::InsertDnstunnelToTSDB(const DtKey& s, const DtStat& stat) {
  DtStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(DtStat))) {
    auto* old_stat = (DtStat*)old_value.data();
    new_stat.first = std::min(stat.first, old_stat->first);
    new_stat.last = std::max(stat.last, old_stat->last);
    new_stat.pkts = stat.pkts + old_stat->pkts;
    new_stat.bytes = stat.bytes + old_stat->bytes;
    new_stat.flows =  stat.flows + old_stat->flows;
  } else {
    new_stat = stat;
  }
  tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}

void DnstunnelFilter::FilterDnstunnel(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckDnstunnel(key, value, req);
    });

  for (auto it = res_dns_.begin(); it != res_dns_.end(); ++it) 
    resp->MergeFrom(it->second);
}

void DnstunnelFilter::FilterDnsTunEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckDnsTunEvent(key, value, req, resp);
    });
}

void DnstunnelFilter::AddRecord(const DtKey& key, const FeatureRecord& new_rec) {
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
      rec->set_pkts(rec->pkts() + new_rec.pkts());
      rec->set_flows(rec->flows() + new_rec.flows());
      return;
    }
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void DnstunnelFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void DnstunnelFilter::CheckDnsTunEvent(const Slice& key, const Slice& value,
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
  rec.set_domain(pvckey.domain);
  rec.set_qtype(pvckey.qtype);
  rec.set_type(pvckey.type);
  rec.set_model(pvckey.model);
  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);

  if (DEBUG) log_info("Got Dos Record: %s\n", rec.DebugString().c_str());
  AddEventRecord(rec, resp);
}

void DnstunnelFilter::CheckDnstunnel(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const DtKey& dnskey = *(const DtKey*)key.data();
  const DtStat& stat = *(const DtStat*)value.data();

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
  if (req.has_fqname() && req.fqname().compare(dnskey.fqname)) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_dport(53);
  rec.set_fqname(dnskey.fqname);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);
  
  if (DEBUG) log_info("Got Dns Record: %s\n", rec.DebugString().c_str());
  AddRecord(dnskey, rec);
}

//////////////////////////////////////////////////////////////////
/* Generate events */

DnstunnelFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et) 
  : event_config(e), dev_id(devid), start_time(st), end_time(et) {
  
  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void DnstunnelFilter::GenerateEvents(const DtKey& s, const DtStat& p, GenEventRes* events, EventGenerator& gen) {
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
      e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]: TUN" + " " + s.fqname);
    } else
      e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>"+ ipnum_to_ipstr(s.dip[0]) + ": TUN" + " " + s.fqname);
    e->set_thres_value(event_config.detvalue());
    e->set_alarm_value(all_fp_[s].size());
    e->set_value_type(event_config.data_type());
    e->set_model_id(0); 
    
    //生成事件特征数据，即事件五元组、域名详细信息     
    GenEventFeature(s, e);
  }
}

void DnstunnelFilter::GenEventFeature(const DtKey& s, const event::GenEventRecord* e) {
  for (auto& kv : event_details_[s]) {
    auto k = kv.first;
    auto v = kv.second;

    string domain = k.domain;
    if (all_fp_[s].find(domain) == all_fp_[s].end()) continue;
    k.model = e->model_id();

    k.time = e->time();
    k.type = e->type_id();
    k.model = e->model_id();
    memcpy(k.obj, e->obj().c_str(), e->obj().size()+1);
    InsertEventToTSDB(k, v);
  }
}

void DnstunnelFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}




