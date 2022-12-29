#include "icmp_tunnel.h"
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

IcmpTunnelFilter::IcmpTunnelFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}

IcmpTunnelFilter* IcmpTunnelFilter::Create(u32 dev_id, const string& model,
                             DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new IcmpTunnelFilter(dev_id, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_icmptunnel"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_icmptunnel"));

  if (DEBUG) log_info("IcmpTunnel filter initialized.\n");
  return filter;
}

bool IcmpTunnelFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot != 1) continue;
    string payload(r.icmp_data);
    if (payload.size() == (u32)count(payload.begin(), payload.end(), 'A')) continue;

    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    UpdateIcmpTunnel(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.icmp_data, r.tos, 
                     r.icmp_seq_num, r.icmp_payload_len, r.dPkts, r.dOctets);
  }
  return true;
}

bool IcmpTunnelFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot != 1) continue;
    string payload(r.icmp_data);
    if (payload.size() == (u32)count(payload.begin(), payload.end(), 'A')) continue;

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
 
    UpdateIcmpTunnel(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.icmp_data, r.tos, 
                     r.icmp_seq_num, r.icmp_payload_len, r.dPkts, r.dOctets);
  }
  return true;
}

void IcmpTunnelFilter::UpdateIcmpTunnel(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, 
                                        char* payload, u8 tos, u16 seq, u32 payload_len, u64 pkts, u64 bytes) {
  string load = payload;
  auto cnt = static_cast<u32> (count(load.begin(), load.end(), '.'));
  if (cnt == load.size() || cnt == load.size()-1 || cnt == load.size()-2) return;
  if (load.npos != load.find("abcdefghijklmnopqrstuvw") || load.npos != load.find("!\"#$%&\'()+,-./01234567") ||
      load.npos != load.find("ABCDEFGHIJKLMNOPQRSTUVW"))
    return;

  u8 icmp_type = dport >> 8;  

  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;
  event.icmp_type = icmp_type;
  memcpy(event.icmp_data, payload, strlen(payload)+1);

  IcmpTunKey icmp;
  memset(&icmp, 0, sizeof(struct IcmpTunKey));
  if (tos & 0x01) {
    std::copy(sip, sip+4, icmp.sip);
    std::copy(dip, dip+4, icmp.dip);
  } else {
    std::copy(dip, dip+4, icmp.sip);
    std::copy(sip, sip+4, icmp.dip);
  }
  
  //统计异常icmp type数量，及对应的payload去重后的数量
  if (icmp_type != 0 && icmp_type != 8) {
    auto itr = abnormal_type_.find(icmp);
    if (itr != abnormal_type_.end())  {
      abnormal_type_[icmp].insert(icmp_type);
      abnormal_type_payload_[icmp].insert(payload);
    } else {
      set<u8> types;
      set<string> payloads;
      types.insert(icmp_type);
      payloads.insert(payload);
      abnormal_type_[icmp] = types;
      abnormal_type_payload_[icmp] = payloads;
    }
  }
   
  auto it = icmp_.find(icmp);
  if (it == icmp_.end()) {
    IcmpTunStat p;
    set<string> convs;
    memset(&p, 0, sizeof(struct IcmpTunStat));
    p.first = first;
    p.last = last;
    p.flows = 1;
    p.pkts = pkts;
    p.bytes = bytes;
    icmp_[icmp] = p;
    //统计去重后payload
    convs.insert(payload);
    icmp_cons_[icmp] = convs;
    //统计去重后payload长度
    set<u32> lens{payload_len};
    payload_len_[icmp] = lens;

    //五元组统计信息
    EventValue ep;
    ep.first = first;
    ep.last = last;
    ep.flows = 1;
    ep.pkts = pkts;
    ep.bytes = bytes;
    map<EventKey, EventValue> event_tmp;
    event_tmp[event] = ep;
    event_details_[icmp] = event_tmp;

    //统计相同seq下请求和响应的数量和payload
    map<u16, pair<u32, u32> > seq_cnt;
    if (tos & 0x01) {
      seq_cnt.insert(make_pair(seq, make_pair(1,0)));
    } else {
      seq_cnt.insert(make_pair(seq, make_pair(0,1)));
    }
    req_reply_[icmp] = seq_cnt;
    set<string> con{payload};
    map<u16, set<string> > tmp_seq;
    tmp_seq.insert(make_pair(seq, con));
    seq_payload_.insert(make_pair(icmp, tmp_seq));
  } else {
    auto& p = it->second;
    p.first = MIN(p.first, first);
    p.last = MAX(p.last, last);
    ++p.flows;
    p.pkts += pkts;
    p.bytes += bytes;
    icmp_cons_[icmp].insert(payload);
    payload_len_[icmp].insert(payload_len);

    //五元组统计信息
    auto itr = event_details_[icmp].find(event);
    if (itr == event_details_[icmp].end()) {
      EventValue p;
      p.first = first;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      event_details_[icmp][event] = p;
    } else {
      auto& p = itr->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      p.flows++;
      p.pkts += pkts;
      p.bytes += bytes;
    }

    //统计相同seq下请求和响应的数量和payload
    auto seq_cnt = req_reply_[icmp];
    auto ti = seq_cnt.find(seq);
    if (ti == seq_cnt.end()) {
      if (tos & 0x01) 
        seq_cnt[seq] = make_pair(1,0);
      else
        seq_cnt[seq] = make_pair(0,1);
      //payload
      set<string> con{payload};
      seq_payload_[icmp].insert(make_pair(seq, con));
    } else {
      tos & 0x01 ? seq_cnt[seq].first++ : seq_cnt[seq].second++;
      //payload
      seq_payload_[icmp][seq].insert(payload);
    }
  }
}

event::GenEventRes IcmpTunnelFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<IcmpTunnelFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);

  GenEventRes events;
  vector<set<string>> sip_vec;
  vector<set<string>> dip_vec;
  int cnt = 0;

  for (auto it = ptr->icmp_.begin(); it != ptr->icmp_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;

    ptr->InsertIcmpTunToTSDB(s, p);
    cnt++;
    for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
      auto event_config = ptr->event_generators_[i].event_config;
      if (cnt == 1) {
        //只读一遍配置
        if (event_config.has_sip() && !event_config.sip().empty()) {
          string siplist = const_cast<char*>(event_config.sip().c_str());
          auto vec = split_string(siplist, ",");
          sip_vec.emplace_back(vec);
        } else {
          set<string> s;
          sip_vec.emplace_back(s);
        }
        
        if (event_config.has_dip() && !event_config.dip().empty()) {
          string diplist = const_cast<char*>(event_config.ip().c_str());
          auto vec = split_string(diplist, ",");
          dip_vec.emplace_back(vec);
        } else {
          set<string> d;
          dip_vec.emplace_back(d);
        }
      }

      //if (ptr->icmp_cons_[s].size() < min) continue;

      bool sflag = false;
      if (sip_vec[i].empty()) sflag = true;
      for (auto& sip : sip_vec[i]) {
        if (model == "V6") {
          struct in6_addr sip6;
          std::copy(s.sip, s.sip+4, sip6.s6_addr32);
          if (valid_ip_v6(ipnum_to_ipstr_v6(sip6), sip)){
            sflag = true;
            break;
          }
        } else {
          if (valid_ip(ipnum_to_ipstr(s.sip[0]), sip)){
            sflag = true;
            break;
          }
        }
      }
      if(!sflag) continue;

      bool dflag = false;
      if (dip_vec[i].empty()) dflag = true;
      for (auto& dip : dip_vec[i]) {
        if (model == "V6") {
          struct in6_addr dip6;
          std::copy(s.dip, s.dip+4, dip6.s6_addr32);
          if (valid_ip_v6(ipnum_to_ipstr_v6(dip6), dip)){
            dflag = true;
            break;
          } 
        } else {
          if (valid_ip(ipnum_to_ipstr(s.dip[0]), dip)){
            dflag = true;
            break;
          }
        }
      }
      if(!dflag) continue;

      //有异常type，并且异type的payload去重后数量大于配置的值则检出为隧道
      if(ptr->abnormal_type_.find(s) != ptr->abnormal_type_.end()) {
        if (ptr->abnormal_type_payload_[s].size() > event_config.if1()) {
          ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
          continue;
        }
      } 
      //同一seq上request数量小于reply数量则检出为隧道，否则判断请求响应内容是否一致，不一致则检出为隧道
      bool is_tun = false;
      auto re = ptr->req_reply_[s];
      for (auto& iter : re) {
        auto& k = iter.first;
        auto& v = iter.second;
        if (v.first == 0 || v.second == 0) continue;
        if (v.first < v.second) {   //request < reply
          is_tun = true;
          break;
        } 
        if (ptr->seq_payload_[s][k].size() > event_config.if2()) {  //请求响应内容不一致, payload内容种类大于设置的阈值
          is_tun = true;
          break;
        }
      }
      if (is_tun) {
        ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
        continue;
      } 

      //若以上条件都不满足，则判断payload长度个数是否大于阈值，大于则检出为隧道
      if (ptr->payload_len_[s].size() > event_config.if3())  
        ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
    }
  }
 
  return events;
}

void IcmpTunnelFilter::InsertIcmpTunToTSDB(const IcmpTunKey& s, const IcmpTunStat& stat) {
  IcmpTunStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(IcmpTunStat))) {
    auto* old_stat = (IcmpTunStat*)old_value.data();
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

void IcmpTunnelFilter::FilterIcmpTunnel(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckIcmpTunnel(key, value, req);
    });
  for (auto it = res_icmp_.begin(); it != res_icmp_.end(); ++it)
    resp->MergeFrom(it->second);
}

void IcmpTunnelFilter::FilterIcmptunEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckIcmptunEvent(key, value, req, resp);
    });
}


void IcmpTunnelFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void IcmpTunnelFilter::AddRecord(const IcmpTunKey& key, const FeatureRecord& new_rec) {
  auto it = res_icmp_.find(key);
  if (it == res_icmp_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_icmp_[key] = resp;
  } else {
    auto& resp = res_icmp_[key];
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
      rec->set_flows(rec->flows() + new_rec.flows());
      rec->set_pkts(rec->pkts() + new_rec.pkts());
      rec->set_bytes(rec->bytes() + new_rec.bytes());
      if (DEBUG) log_info("Update Record: %s\n", rec->DebugString().c_str());
      return;
    }
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void IcmpTunnelFilter::CheckIcmptunEvent(const Slice& key, const Slice& value,
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
  rec.set_payload(pvckey.icmp_data);
  rec.set_obj(pvckey.obj);
  rec.set_type(pvckey.type);
  rec.set_icmp_type(pvckey.icmp_type);
  rec.set_model(pvckey.model);
  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);

  if (DEBUG) log_info("Got icmp tun Record: %s\n", rec.DebugString().c_str());
  AddEventRecord(rec, resp);
}

void IcmpTunnelFilter::CheckIcmpTunnel(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const IcmpTunKey& icmptunkey = *(const IcmpTunKey*)key.data();
  const IcmpTunStat& stat = *(const IcmpTunStat*)value.data();

  if (stat.first <= req.starttime() || stat.first >= req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(icmptunkey.sip, icmptunkey.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(icmptunkey.dip, icmptunkey.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(icmptunkey.sip[0]);
    dip = ipnum_to_ipstr(icmptunkey.dip[0]);
  }
    
  if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
  if (req.has_sip() && req.sip() != sip) return;
  if (req.has_dip() && req.dip() != dip) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);

  if (DEBUG) log_info("Got IcmpTun Record: %s\n", rec.DebugString().c_str());
  AddRecord(icmptunkey, rec);
}

//////////////////////////////////////////////////////////////////
/* Generate events */

IcmpTunnelFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et) 
  : event_config(e), dev_id(devid), start_time(st), end_time(et) {
  
  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void IcmpTunnelFilter::GenerateEvents(const IcmpTunKey& s, const IcmpTunStat& p, GenEventRes* events, EventGenerator& gen) {
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
      e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]:  ");      
    } else
      e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>"+ ipnum_to_ipstr(s.dip[0]) + ":  ");  
    e->set_thres_value(event_config.min());
    e->set_alarm_value(payload_len_[s].size());
    e->set_value_type(event_config.data_type());
    e->set_model_id(0);

    //生成事件特征数据，即事件五元组详细信息
    GenEventFeature(s, e);
  }
}

void IcmpTunnelFilter::GenEventFeature(const IcmpTunKey& s, const event::GenEventRecord* e) {
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

void IcmpTunnelFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}
