#include "mining_filter.h"
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

namespace {

void LoadTiFromFile(const string& file_name, std::map<string, vector<string> >& ti) {
  try {
    ifstream ifs(file_name);
    string line;
    //size_t pos;
    string domain, type;
    while (getline(ifs, line)) {
      vector<string> vec;
      trim(line);
      if (line.empty() || line[0] == '#') continue;
      /* pos = line.find(",");
      if (pos != std::string::npos) {
        domain = line.substr(0,pos);
        type = line.substr(pos + 1);
        domains[domain] = type;
      } */
      csv::fill_vector_from_line(vec, line);
      ti[vec[0]] = vec;
    }
  } catch (...) {
     log_warning("Could not load ti from file %s\n", file_name.c_str());
  }
}
}

MiningFilter::MiningFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}

MiningFilter* MiningFilter::Create(u32 dev_id, const string& model,
                             DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new MiningFilter(dev_id, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_mining"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_mining"));
  if (DEBUG) log_info("Mining filter initialized.\n");
  return filter;
}

bool MiningFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot != 17 && r.prot != 6) continue;
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    UpdateMining(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.qname, r.tos, r.threat_type, r.threat_name, r.threat_time, r.dPkts, r.dOctets);
  }
  return true;
}

bool MiningFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot != 17 && r.prot != 6) continue;
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
 
    UpdateMining(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.qname, r.tos, r.threat_type, r.threat_name, r.threat_time, r.dPkts, r.dOctets);
  }
  return true;
}

void MiningFilter::UpdateMining(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, char *qname, 
                                     u8 tos, char* threat_type, char* threat_name, u64 threat_time, u64 pkts, u64 bytes) {

  //包识别
  string fp_type = threat_type;
  if (boost::to_upper_copy(fp_type) == "MINING" && (tos & 0x01)) {
    EventKey event;
    memset(&event, 0, sizeof(struct EventKey));
    std::copy(sip, sip+4, event.sip);
    event.sport = sport;
    std::copy(dip, dip+4, event.dip);
    event.dport = dport;
    event.proto = proto;
    event.model = 3;
    memcpy(event.coin_name, threat_name, strlen(threat_name)+1);
    event.capusec = threat_time;

    MiningKey threat;
    memset(&threat, 0, sizeof(struct MiningKey));
    std::copy(sip, sip+4, threat.sip);
    std::copy(dip, dip+4, threat.dip);
    //std::copy(sip, sip+4, threat.sip);
    //std::copy(dip, dip+4, threat.dip);
    threat.proto = proto;
    threat.model = 3;
    memcpy(threat.coin_name, threat_name, strlen(threat_name) + 1);

    auto it = cap_mining_.find(threat);
    if (it == cap_mining_.end()) {
      MiningStat threat_stat;
      memset(&threat_stat, 0, sizeof(struct MiningStat));
      threat_stat.first = first;
      threat_stat.last = last;
      threat_stat.flows = 1;
      threat_stat.pkts = pkts;
      threat_stat.bytes = bytes;
      cap_mining_[threat] = threat_stat;

      //五元组统计信息
      EventValue ep;
      ep.first = first;
      ep.last = last;
      ep.flows = 1;
      ep.pkts = pkts;
      ep.bytes = bytes;
      map<EventKey, EventValue> event_tmp;
      event_tmp[event] = ep;
      event_details_[threat] = event_tmp;
    } else {
      auto& threat_stat = it->second;
      threat_stat.first = MIN(threat_stat.first, first);
      threat_stat.last = MAX(threat_stat.last, last);
      ++threat_stat.flows;
      threat_stat.pkts += pkts;
      threat_stat.bytes += bytes;

      //五元组统计信息
      auto itr = event_details_[threat].find(event);
      if (itr == event_details_[threat].end()) {
        EventValue p;
        p.first = first;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        event_details_[threat][event] = p;
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
  
  //dns情报
  if (strlen(qname)) {
    string domain = qname;
    auto md5_domain = MD5(domain).toString();
    if (domains_.count(md5_domain)) {
      auto coin = domains_[md5_domain][2]; //币种
      //事件五元组信息
      EventKey event;
      memset(&event, 0, sizeof(struct EventKey));
      std::copy(sip, sip+4, event.sip);
      event.sport = sport;
      std::copy(dip, dip+4, event.dip);
      event.dport = dport;
      event.proto = proto;
      event.model = 2;
      memcpy(event.domain, qname, strlen(qname) + 1);
      memcpy(event.coin_name, coin.c_str(), coin.size()>=COIN_NAME_LEN ? COIN_NAME_LEN-1 : coin.size());

      MiningKey dns;
      //if (!JudgeSpecChar(domain)) return; 
      
      memset(&dns, 0, sizeof(struct MiningKey));
      if (tos & 0x01) {//dns请求
        std::copy(sip, sip+4, dns.sip);
        std::copy(dip, dip+4, dns.dip);
      } else {
        std::copy(dip, dip+4, dns.sip);
        std::copy(sip, sip+4, dns.dip);
      }
      dns.proto = proto;
      dns.model = 2;
      memcpy(dns.domain, qname, strlen(qname) + 1);
      memcpy(dns.coin_name, coin.c_str(), coin.size()>=COIN_NAME_LEN ? COIN_NAME_LEN-1 : coin.size());
      auto it = ti_mining_.find(dns);
      if (it == ti_mining_.end()) {
        MiningStat p;
        memset(&p, 0, sizeof(struct MiningStat));
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        ti_mining_[dns] = p;

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
  }   //end for dns情报 

  //IP情报
  string sip_str, dip_str;
  if (model_ == "V4") {
    sip_str = ipnum_to_ipstr(sip[0]);
    dip_str = ipnum_to_ipstr(dip[0]);
  } else {
    struct in6_addr sip6, dip6;
    std::copy(sip, sip+4, sip6.s6_addr32);
    std::copy(dip, dip+4, dip6.s6_addr32);
    sip_str = ipnum_to_ipstr_v6(sip6);
    dip_str = ipnum_to_ipstr_v6(dip6);
  }
  if (ips_.count(sip_str) || ips_.count(dip_str)) {
    EventKey event;
    memset(&event, 0, sizeof(struct EventKey));
    std::copy(sip, sip+4, event.sip);
    event.sport = sport;
    std::copy(dip, dip+4, event.dip);
    event.dport = dport;
    event.proto = proto;
    event.model = 2;

    MiningKey ti;
    string coin;
    memset(&ti, 0, sizeof(MiningKey));
    if (ips_.count(dip_str)) {
      std::copy(sip, sip+4, ti.sip);
      std::copy(dip, dip+4, ti.dip);
      coin = ips_[dip_str][2];
      memcpy(ti.coin_name, coin.c_str(), coin.size()>=COIN_NAME_LEN ? COIN_NAME_LEN-1 : coin.size());
      memcpy(event.coin_name, coin.c_str(), coin.size()>=COIN_NAME_LEN ? COIN_NAME_LEN-1 : coin.size());
    } else if (ips_.count(sip_str)) {
      std::copy(dip, dip+4, ti.sip);
      std::copy(sip, sip+4, ti.dip);
      memcpy(ti.coin_name, coin.c_str(), coin.size()>=COIN_NAME_LEN ? COIN_NAME_LEN-1 : coin.size());
      memcpy(event.coin_name, coin.c_str(), coin.size()>=COIN_NAME_LEN ? COIN_NAME_LEN-1 : coin.size());
    }
    ti.proto = proto;
    ti.model = 2;
    auto it = ti_mining_.find(ti);
    if (it == ti_mining_.end()) {
      MiningStat p;
      memset(&p, 0, sizeof(struct MiningStat));
      p.first = first;
      p.last = last;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      ti_mining_[ti] = p;

      //五元组统计信息
      EventValue ep;
      ep.first = first;
      ep.last = last;
      ep.flows = 1;
      ep.pkts = pkts;
      ep.bytes = bytes;
      map<EventKey, EventValue> event_tmp;
      event_tmp[event] = ep;
      event_details_[ti] = event_tmp;
    } else {
      auto& p = it->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      p.flows++;
      p.pkts += pkts;
      p.bytes += bytes;
      
      //五元组统计信息
      auto itr = event_details_[ti].find(event);
      if (itr == event_details_[ti].end()) {
        EventValue p;
        p.first = first;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        event_details_[ti][event] = p;
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

event::GenEventRes MiningFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<MiningFilter>& ptr, const string& model) {
  LoadTiFromFile("/Agent/data/mining_domain", ptr->domains_);
  if (model == "v6")
    LoadTiFromFile("/Agent/data/mining_ip6", ptr->ips_);
  else
    LoadTiFromFile("/Agent/data/mining_ip", ptr->ips_);

  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);

  GenEventRes events;

  for (auto it = ptr->cap_mining_.begin(); it != ptr->cap_mining_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;

    ptr->InsertMiningToTSDB(s, p);    
    for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
      ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
    }
  }
 
  for (auto it = ptr->ti_mining_.begin(); it != ptr->ti_mining_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;
   
    ptr->InsertMiningToTSDB(s, p); 
    for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
      ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
    }
  }

  return events;
}

void MiningFilter::InsertMiningToTSDB(const MiningKey& s, const MiningStat& stat) {
  MiningStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(MiningStat))) {
    auto* old_stat = (MiningStat*)old_value.data();
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

void MiningFilter::FilterMining(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckMining(key, value, req);
    });
  
  for (auto it = res_mining_.begin(); it != res_mining_.end(); ++it)
    resp->MergeFrom(it->second);
}

void MiningFilter::FilterMiningEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckMiningEvent(key, value, req, resp);
    });
}

void MiningFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void MiningFilter::AddRecord(const MiningKey& key, const FeatureRecord& new_rec) {
  auto it = res_mining_.find(key);
  if (it == res_mining_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_mining_[key] = resp;
  } else {
    auto& resp = res_mining_[key];
    for (s32 i = 0; i < resp.records_size(); ++i) {
      auto rec = resp.mutable_records(i);

      u32 s1 = rec->time();
      u32 s2 = new_rec.time();
      u32 mins = std::min(s1, s2);
      rec->set_time(mins);
      rec->set_bytes(rec->bytes() + new_rec.bytes());
      rec->set_pkts(rec->bytes() + new_rec.pkts());
      rec->set_flows(rec->flows() + new_rec.flows());
      return;
    }
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void MiningFilter::CheckMiningEvent(const Slice& key, const Slice& value,
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
  rec.set_obj(pvckey.obj);
  rec.set_type(pvckey.type);
  rec.set_capname(pvckey.coin_name);
  rec.set_capusec(pvckey.capusec);
  rec.set_model(pvckey.model);
  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);

  if (DEBUG) log_info("Got Dos Record: %s\n", rec.DebugString().c_str());
  AddEventRecord(rec, resp);
}

void MiningFilter::CheckMining(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const MiningKey& miningkey = *(const MiningKey*)key.data();
  const MiningStat& stat = *(const MiningStat*)value.data();

  if (stat.first <= req.starttime() || stat.first >= req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(miningkey.sip, miningkey.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(miningkey.dip, miningkey.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(miningkey.sip[0]);
    dip = ipnum_to_ipstr(miningkey.dip[0]);
  }
    
  if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
  if (req.has_sip() && req.sip() != sip) return;
  if (req.has_dip() && req.dip() != dip) return;
  if (req.has_qname() && req.qname() != miningkey.domain) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_qname(miningkey.domain);
  rec.set_threat_name(miningkey.coin_name);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);

  if (DEBUG) log_info("Got Mining Record: %s\n", rec.DebugString().c_str());
  AddRecord(miningkey, rec);
}

//////////////////////////////////////////////////////////////////
/* Generate events */

MiningFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et) 
  : event_config(e), dev_id(devid), start_time(st), end_time(et) {
  
  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void MiningFilter::GenerateEvents(const MiningKey& s, const MiningStat& p, GenEventRes* events, EventGenerator& gen) {
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
      e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]: " + proto_to_string(s.proto) + " " + s.coin_name + " " + s.domain);      
    } else
      e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>"+ ipnum_to_ipstr(s.dip[0]) + ": " + proto_to_string(s.proto) + " " + s.coin_name + " " + s.domain);  
    e->set_thres_value(event_config.qcount());
    e->set_alarm_value(p.flows);
    e->set_value_type(event_config.data_type());
    e->set_model_id(s.model);
    
    //生成事件特征数据，即事件五元组、域名详细信息
    GenEventFeature(s, e);
  }
}

void MiningFilter::GenEventFeature(const MiningKey& s, const event::GenEventRecord* e) {
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

void MiningFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}


