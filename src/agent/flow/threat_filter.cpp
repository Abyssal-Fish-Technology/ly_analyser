#include "threat_filter.h"
#include "../../common/common.h"
#include "../../common/ip.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/datetime.h"
#include "../../common/common_filter.hpp"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include <utility>
#include <boost/algorithm/string.hpp>

// ThreatFilter::ThreatFilter(u32 dev_id, const string& model, unique_ptr<TSDB> tsdb)
//   : FlowFilter(), dev_id_(dev_id), model_(model), tsdb_(std::move(tsdb)) {}

// ThreatFilter* ThreatFilter::Create(u32 dev_id, const string& model, DBBuilder* builder) {
//   auto* filter = new ThreatFilter(
//     dev_id, model, unique_ptr<TSDB>(new TSDB(builder, to_string(dev_id) + "_feature_threat")));
//   if (DEBUG) log_info("Threat filter initialized.\n");
//   return filter;
// }

ThreatFilter::ThreatFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}

ThreatFilter* ThreatFilter::Create(u32 dev_id, const string& model, DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new ThreatFilter(dev_id, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_threat"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_threat"));

  if (DEBUG) log_info("Threat filter initialized.\n");
  return filter;
}

bool ThreatFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if ( strlen(r.threat_type) && (r.tos&0x01) ) {
      uint32_t sip[4], dip[4];
      memset(sip, 0, sizeof(uint)*4);
      memset(dip, 0, sizeof(uint)*4);
      sip[0] = r.v4.srcaddr;
      dip[0] = r.v4.dstaddr;

      UpdateThreats(r.first, r.last, sip, r.srcport, r.prot, dip, r.dstport,
                    r.http_url, r.http_host, r.threat_type, r.threat_name, r.threat_version, r.threat_time,
                    r.dPkts, r.dOctets);
    }
  }

  return true;
}

bool ThreatFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if ( strlen(r.threat_type) && (r.tos&0x01) ) {
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

      UpdateThreats(r.first, r.last, sip, r.srcport, r.prot, dip, r.dstport,
                    r.http_url, r.http_host, r.threat_type, r.threat_name, r.threat_version, r.threat_time,
                    r.dPkts, r.dOctets);    
    }
  }

  return true;
}


void ThreatFilter::UpdateThreats(u32 first, u32 last, u32 sip[], u16 sport, u8 proto, u32 dip[], u16 dport, 
                                 char* url, char* host, char* threat_type, char* threat_name, char* threat_vers, u64 threat_time, 
                                 u64 pkts, u64 bytes) {
  string fp_type = threat_type;
  string fp_name = threat_name;
  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;
  memcpy(event.captype, boost::to_lower_copy(fp_type).c_str(), fp_type.size()+1);
  memcpy(event.capname, boost::to_lower_copy(fp_name).c_str(), fp_name.size()+1);
  memcpy(event.capvers, threat_vers, strlen(threat_vers)+1);
  event.capusec = threat_time;

  ThreatKey threat_key;
  memset(&threat_key, 0, sizeof(ThreatKey));
  std::copy(sip, sip+4, threat_key.sip);
  // threat_key.sport = sport;
  threat_key.proto = proto; 
  std::copy(dip, dip+4, threat_key.dip);
  threat_key.dport = dport;
  // int hlen = strlen(host);
  // memcpy(threat_key.url, host, hlen);
  // memcpy(threat_key.url+hlen, url, strlen(url)+1);
  memcpy(threat_key.fp_type, boost::to_lower_copy(fp_type).c_str(), fp_type.size()+1);
  memcpy(threat_key.fp_name, boost::to_lower_copy(fp_name).c_str(), fp_name.size()+1);

  auto it = threats_.find(threat_key);
  if (it == threats_.end()) {
    ThreatStat threat_stat;
    memset(&threat_stat, 0, sizeof(struct ThreatStat));
    threat_stat.first = first;
    threat_stat.last = last;
    threat_stat.flows = 1;
    threat_stat.pkts = pkts;
    threat_stat.bytes = bytes;
    threats_[threat_key] = threat_stat;

    //五元组统计信息
    EventValue ep;
    ep.first = first;
    ep.last = last;
    ep.flows = 1;
    ep.pkts = pkts;
    ep.bytes = bytes;
    map<EventKey, EventValue> event_tmp;
    event_tmp[event] = ep;
    event_details_[threat_key] = event_tmp;
  } else {
    auto& threat_stat = it->second;
    threat_stat.first = MIN(threat_stat.first, first);
    threat_stat.last = MAX(threat_stat.last, last);
    ++threat_stat.flows;
    threat_stat.pkts += pkts;
    threat_stat.bytes += bytes;

    //五元组统计信息
    auto itr = event_details_[threat_key].find(event);
    if (itr == event_details_[threat_key].end()) {
      EventValue p;
      p.first = first;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      event_details_[threat_key][event] = p;
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

event::GenEventRes ThreatFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<ThreatFilter>& ptr, const string& model) {
  event::GenEventRes events;
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);  
  
  for (auto it = ptr->threats_.begin(); it != ptr->threats_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;
    ptr->InsertThreatToTSDB(s, p);
    for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
      ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
    }
  }

  return events;
}

void ThreatFilter::InsertThreatToTSDB(const ThreatKey& s, const ThreatStat& stat) {
  ThreatStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(ThreatStat))) {
    auto* old_stat = (ThreatStat*)old_value.data();
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

void ThreatFilter::FilterThreat(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckThreat(key, value, req);
    });

  for (auto it = res_threat_.begin(); it != res_threat_.end(); ++it)
    resp->MergeFrom(it->second);
}

void ThreatFilter::AddRecord(const ThreatKey& key, const FeatureRecord& new_rec) {
  auto it = res_threat_.find(key);
  if (it == res_threat_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_threat_[key] = resp;
  } else {
    auto& resp = res_threat_[key];
    for (s32 i = 0; i < resp.records_size(); ++i) {
      auto rec = resp.mutable_records(i);

      u32 s1 = rec->time();
      u32 s2 = new_rec.time();
      u32 mins = std::min(s1, s2);
      rec->set_time(mins);
      rec->set_bytes(rec->bytes() + new_rec.bytes());
      rec->set_pkts(rec->pkts() + new_rec.pkts());
      rec->set_flows(rec->flows() + new_rec.flows());

      if (DEBUG) log_info("Update Record: %s\n", rec->DebugString().c_str());
      return;
    }
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void ThreatFilter::CheckThreat(const Slice& key, const Slice& value, const feature::FeatureReq& req) {
  const ThreatKey& threat_key = *(const ThreatKey*)key.data();
  const ThreatStat& threat_stat = *(const ThreatStat*)value.data();

  if (threat_stat.first <= req.starttime() || threat_stat.first >= req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(threat_key.sip, threat_key.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(threat_key.dip, threat_key.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(threat_key.sip[0]);
    dip = ipnum_to_ipstr(threat_key.dip[0]);
  }

  if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
  if (req.has_sip() && req.sip() != sip) return;
  if (req.has_dip() && req.dip() != dip) return;
  // if (req.has_url() && req.url() != threat_key.url) return;


  FeatureRecord rec;
  rec.set_time(threat_stat.first);
  rec.set_sip(sip);
  // rec.set_sport(threat_key.sport);
  rec.set_dip(dip);
  rec.set_dport(threat_key.dport);
  // rec.set_url(threat_key.url);
  rec.set_threat_type(threat_key.fp_type);
  rec.set_threat_name(threat_key.fp_name);
  rec.set_bytes(threat_stat.bytes);
  rec.set_pkts(threat_stat.pkts);
  rec.set_flows(threat_stat.flows);
  if (DEBUG) log_info("Got Threat Record: %s\n", rec.DebugString().c_str());
  AddRecord(threat_key, rec);
}

void ThreatFilter::FilterThreatEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckThreatEvent(key, value, req, resp);
    });
}

void ThreatFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void ThreatFilter::CheckThreatEvent(const Slice& key, const Slice& value,
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
  rec.set_obj(pvckey.obj);
  rec.set_type(pvckey.type);
  rec.set_model(pvckey.model);

  rec.set_captype(pvckey.captype);
  rec.set_capname(pvckey.capname);
  rec.set_capvers(pvckey.capvers);
  rec.set_capusec(pvckey.capusec);

  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);

  if (DEBUG) log_info("Got threat by cap Record: %s\n", rec.DebugString().c_str());
  AddEventRecord(rec, resp);
}

ThreatFilter::EventGenerator::EventGenerator(
    const config::Event& e, u32 devid, u32 st, u32 et)
    : event_config(e), dev_id(devid), start_time(st), end_time(et) {
  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void ThreatFilter::GenerateEvents(const ThreatKey& s, const ThreatStat& p, GenEventRes* events, EventGenerator& gen) {
  auto event_config = gen.event_config;
  if (common_filter::filter_time_range(gen.start_time, event_config)) {
    auto e = events->add_records();
    e->set_time(gen.start_time);
    e->set_type_id(event_config.type_id());
    e->set_config_id(event_config.config_id());
    e->set_devid(gen.dev_id);
    if (model_ == "V6") {
      struct in6_addr sip6, dip6;
      if (!strcmp(s.fp_type, "mining")) { //挖矿反过来，obj中sip为矿池ip
        std::copy(s.sip, s.sip+4, dip6.s6_addr32);
        std::copy(s.dip, s.dip+4, sip6.s6_addr32);
      } else {
        std::copy(s.sip, s.sip+4, sip6.s6_addr32);
        std::copy(s.dip, s.dip+4, dip6.s6_addr32);
      }
      e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:" + /* to_string(s.sport) + */ ">[" + 
                ipnum_to_ipstr_v6(dip6) + "]:" + to_string(s.dport) + 
                " " + proto_to_string(s.proto) + " " + s.fp_type + " " + s.fp_name);
    } else {
      u32 sip, dip;
      if (!strcmp(s.fp_type, "mining")) { //挖矿反过来，obj中sip为矿池ip
        dip = s.sip[0];
        sip = s.dip[0];
      } else {
        sip = s.sip[0];
        dip = s.dip[0];
      }

      e->set_obj(ipnum_to_ipstr(sip) + ":" + /* to_string(s.sport) + */ ">" +
                ipnum_to_ipstr(dip) + ":" + to_string(s.dport) +
                " " + proto_to_string(s.proto) + " "  + s.fp_type + " " + s.fp_name);
    }
      
    e->set_thres_value(0);
    e->set_alarm_value(p.flows);
    e->set_value_type("fps");
    e->set_model_id(3);

    GenEventFeature(s, e);
  }
}

void ThreatFilter::GenEventFeature(const ThreatKey& s, const event::GenEventRecord* e) {
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

void ThreatFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}
