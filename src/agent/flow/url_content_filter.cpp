#include "url_content_filter.h"

UrlContentFilter::UrlContentFilter(u32 dev_id, const string& model, unique_ptr<TSDB> tsdb)
  : FlowFilter(), dev_id_(dev_id), model_(model), tsdb_(std::move(tsdb)) {}

UrlContentFilter* UrlContentFilter::Create(u32 dev_id, const string& model,
                                     DBBuilder* builder) {
  auto* filter = new UrlContentFilter(
    dev_id, model, unique_ptr<TSDB>(new TSDB(builder, to_string(dev_id) + "_url_content")));
  if (DEBUG) log_info("Url Content filter initialized.\n");
  return filter;
}

bool UrlContentFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    uint32_t dip[4], sip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;
    if (r.http_ret_code == 0) continue;
    if (r.http_url[0] != '\0' && r.prot == 6)
      UpdateUrlCon(r.first, r.last, sip, dip, r.srcport, r.dstport, r.tos, r.http_url, r.http_ret_code, r.dPkts, r.dOctets);
  }
  return true;
}

bool UrlContentFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    uint32_t dip[4], sip[4];
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

    if (r.http_ret_code == 0) continue;
    if (r.http_url[0] != '\0' && r.prot == 6)
      UpdateUrlCon(r.first, r.last, sip, dip, r.srcport, r.dstport, r.tos, r.http_url, r.http_ret_code, r.dPkts, r.dOctets);
  }
  return true;
}

void UrlContentFilter::UpdateUrlCon(u32 first, u32 last, u32 sip[], u32 dip[], u16 sport, u16 dport,
                                    u8 tos, char* url, u16 retcode, u64 pkts, u64 bytes) {
  UrlConKey rec;
  copy(sip, sip+4, rec.sip);
  copy(dip, dip+4, rec.dip);
  rec.sport = sport;
  rec.dport = dport;
  //rec.retcode = retcode;
  //rec.tos = tos;
  memcpy(rec.url, url, strlen(url)+1);
  auto it = flow_rec_.find(rec);
  if (it == flow_rec_.end()) {
    UrlConStat p;
    p.first = first;
    p.last = last;
    p.flows = 1;
    p.pkts = pkts;
    p.bytes = bytes;
    flow_rec_[rec] = p;
  } else {
    auto& p = it->second;
    p.first = MIN(p.first, first);
    p.last = MAX(p.last, last);
    ++p.flows;
    p.pkts += pkts;
    p.bytes += bytes;
  }
} 

void UrlContentFilter::DivideType() {
  for (auto itr = flow_rec_.begin(); itr != flow_rec_.end(); ++itr) {
    auto& s = itr->first;
    auto& p = itr->second;
    
    for (auto& con : event_conf_) {
      //config::Event_Ctype type = Event::INVAILD;
      //u32 config_id;
      auto& event_config = con.second.event_config;
      if (MatchPattern(s.url, event_config.pat())) {
        p.type = event_config.sub_type();
        p.config_id = con.first;
      }
    }
  }
}

bool UrlContentFilter::MatchPattern(const string& str, const string& reg) {
  regex pattern(reg, regex::nosubs);
  smatch m;
  return regex_match(str, m, pattern);
}

/*void UrlContentFilter::InsertUrlConToTSDB(const UrlConKey& s, const UrlConStat& stat) {
  UrlConStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(UrlConStat))) {
    auto* old_stat = (UrlConStat*)old_value.data();
    new_stat.first = std::min(stat.first, old_stat->first);
    new_stat.last = std::max(stat.last, old_stat->last);
    new_stat.pkts = stat.pkts + old_stat->pkts;
    new_stat.bytes = stat.bytes + old_stat->bytes;
    new_stat.flows =  stat.flows + old_stat->flows;
  } else {
    new_stat = stat;
  }
  tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}*/

event::GenEventRes UrlContentFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<UrlContentFilter>& ptr,
                                const string& model, set<string>& asset_ips) {
  GenEventRes events;
  for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
    auto event_config = ptr->event_generators_[i].event_config;
    ptr->event_conf_.insert(pair<u32, EventGenerator>(event_config.config_id(), ptr->event_generators_[i]));
    //ptr->event_conf_[event_config.config_id()] = ptr->event_generators_[i];
  }
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);

  ptr->DivideType(); 
  for (auto it = ptr->flow_rec_.begin(); it != ptr->flow_rec_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;
    if (p.config_id == 0) continue;
    ptr->GenerateEvents(s, p, &events);
  }

  return events;
 /* for (auto it = ptr->url_con_.begin(); it != ptr->url_con_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;
    if (model == "V6") {
      for (auto itr = asset_ips.begin();itr != asset_ips.end();itr++) {
        auto ip_segment = *itr;
        struct in6_addr ip6;
        std::copy(s.ip, s.ip+4, ip6.s6_addr32);
        if (valid_ip_v6(ipnum_to_ipstr_v6(ip6), ip_segment)) {
          ptr->InsertHttpToTSDB(s, p);
          break;
        }
      }
    } else {
      for (auto itr = asset_ips.begin();itr != asset_ips.end();itr++) {
        auto ip_segment = *itr;
        if (valid_ip(ipnum_to_ipstr(s.ip[0]), ip_segment)) {
          ptr->InsertHttpToTSDB(s, p);
          break;
        }
      }
    }
  }*/
}

UrlContentFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et)
  : event_config(e), dev_id(devid), start_time(st), end_time(et) {

  if (DEBUG) log_info("EventGenerator initialized.\n");
}

static string ctype_to_string(const config::Event_Ctype& s) {
  if (s == Event::SQL_INJECT)
    return "SQL_INJECT";
  else if (s == Event::XSS)
    return "XSS";
  else if (s ==  Event::RESO_EXPLORE)
    return "RESO_EXPLORE";
  else if (s == Event::VISIT_ADMIN)
    return "VISIT_ADMIN";
  else if (s == Event::PULL_DB)
    return "PULL_DB";
  else 
    return "";
}

void UrlContentFilter::GenerateEvents(const UrlConKey& s, const UrlConStat& p, GenEventRes* events) {
  EventGenerator& conf = event_conf_[p.config_id];
  if (p.type == Event::PULL_DB) {
    if (p.bytes <= conf.event_config.min()) return;
  } else {
    if (p.flows <= conf.event_config.min()) return;
  }

  auto e = events->add_records();
  e->set_time(conf.start_time);
  e->set_devid(conf.dev_id);
  e->set_type_id(conf.event_config.type_id());
  e->set_config_id(conf.event_config.config_id());
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(s.sip, s.sip+4, sip6.s6_addr32);
    std::copy(s.dip, s.dip+4, dip6.s6_addr32);
    e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:" + to_string(s.sport) + ">[" + ipnum_to_ipstr_v6(dip6) + "]:" + to_string(s.dport) + " TCP " + ctype_to_string(p.type));
  } else
    e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":" + to_string(s.sport) + ">" + ipnum_to_ipstr(s.dip[0]) + ":" + to_string(s.dport) + " TCP " + ctype_to_string(p.type));

  e->set_thres_value(conf.event_config.min());
  e->set_alarm_value(p.flows);
  e->set_value_type("");
  e->set_model_id(3);
  if (DEBUG) log_info("Generated http url content event: %s\n", e->DebugString().c_str());
}


/*void UrlContentFilter::FilterUrlCon(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckUrlCon(key, value, req);
    });

  for (auto it = res_urlcon_.begin(); it != res_urlcon_.end(); ++it)
    resp->MergeFrom(it->second);
}


void UrlContentFilter::AddRecord(const UrlConKey& key, const FeatureRecord& new_rec) {
  auto it = res_urlcon_.find(key);
  if (it == res_urlcon_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_urlcon_[key] = resp;
  } else {
    auto& resp = res_urlcon_[key];
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

void UrlContentFilter::CheckUrlCon(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const UrlConKey& httpkey = *(const UrlConKey*)key.data();
  const UrlConStat& stat = *(const UrlConStat*)value.data();

  if (stat.last < req.starttime() || stat.first > req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(httpkey.sip, httpkey.sip+4, sip6.s6_addr32);
    std::copy(httpkey.dip, httpkey.dip+4, dip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(httpkey.sip[0]);
    dip = ipnum_to_ipstr(httpkey.dip[0]);
  }

  if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
  if (req.has_sip() && req.sip() != sip) return;
  if (req.has_dip() && req.dip() != dip) return;
  if (req.has_port() && req.port() != httpkey.dport) return;
  if (req.has_dport() && req.dport() != httpkey.dport) return;
  //if (req.has_retcode_cur() && req.retcode_cur() <= httpkey.retcode) return;


  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_dport(httpkey.dport);
  rec.set_type(ctype_to_string(p.type));
  //rec.set_retcode(httpkey.retcode);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);

  if (DEBUG) log_info("Got UrlContent Record: %s\n", rec.DebugString().c_str());
  AddRecord(httpkey, rec);
}*/

