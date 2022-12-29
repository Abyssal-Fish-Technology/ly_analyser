#include "bw_filter.h"
#include "../../common/common.h"
#include "common_model_filter.hpp"
#include "../../common/strings.h"
#include "../../common/log.h"
#include "../../common/ip.h"
#include "../define.h"
#include <iostream>
#include <sstream>

static set<Pattern> pats_;
static char kBPS[] = "bps";
static char kPPS[] = "pps";
static char kFPS[] = "sps";

BWFilter::BWFilter(u32 devid, const string& model) 
	: FlowFilter(), devid_(devid), model_(model) {}

BWFilter* BWFilter::Create(u32 devid, const policy::PolicyData& policy_data,
													 DBBuilder* builder, DBBuilder* event_builder, 
                           const string& model, const string& label) {
  unique_ptr<BWFilter> filter(new BWFilter(devid, model));
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(devid) + "_feature_" + label));
  if (event_builder && label == "black")
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(devid) + "_event_" + label));

	if (label == "black")
			filter->is_black_list_ = true;

  for (const auto& item : policy_data.item()) {
//    if (item.has_ip() && item.has_port()) {
      // ip + port.
  //    filter->ip_port_pairs_.emplace(ipstr_to_ipnum(item.ip()), item.port());
/*    } else if (item.has_ip() && item.has_pip()) {
      // ip + peer ip.
      filter->ip_pip_pairs_.emplace(ipstr_to_ipnum(item.ip()),
                                    ipstr_to_ipnum(item.pip()));
    } else if (item.has_ip() && item.has_pport()) {
      // ip + peer port.
      filter->ip_pport_pairs_.emplace(ipstr_to_ipnum(item.ip()), item.pport());*/
   // } else if (item.has_ip()) {
      // ip.
 			if (item.has_ip()) {
        if (item.ip().find(":") != std::string::npos) // ipv6
          filter->ips6_.emplace(item.ip());
        else //ipv4
      	  filter->ips_.emplace(ipstr_to_ipnum(item.ip()));
   /* } else if (item.has_port()) {
      // port.
      filter->ports_.emplace(item.port());*/
    }
  }
	
  if (DEBUG) log_info("Init raw filter %s.\n", label.c_str());
  return filter.release();
}

BWFilter* BWFilter::Create(u32 devid, DBBuilder* builder, DBBuilder* event_builder, 
                            const string& model, const string& label) {
	auto* filter = new BWFilter(devid, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(devid) + "_feature_" + label));
  if (event_builder && label == "black")
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(devid) + "_event_" + label));

	return filter;
}

bool BWFilter::CheckFlow(FlowPtr flow) {
  auto r = (master_record_t*)flow;
  bool match = false;
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
    string sip = ipnum_to_ipstr_v6(s6);
    string dip = ipnum_to_ipstr_v6(d6);

    if (!ips6_.empty()) {
      match |= ips6_.find(sip) != ips6_.end() || ips6_.find(dip) != ips6_.end(); 
    }

  } else {
    u32 sip = r->v4.srcaddr;
    u32 dip = r->v4.dstaddr;
    if (!ips_.empty()) {
      match |= ips_.find(sip) != ips_.end() || ips_.find(dip) != ips_.end(); 
    }
  }
 /* if (!ports_.empty()) {
    match |= (r->prot == 6 || r->prot == 13) &&
             (ports_.find(r->srcport) != ports_.end() ||
              ports_.find(r->dstport) != ports_.end());
  }
  if (!ip_pip_pairs_.empty()) {
    match |= ip_pip_pairs_.find(make_pair(sip, dip)) != ip_pip_pairs_.end() ||
             ip_pip_pairs_.find(make_pair(dip, sip)) != ip_pip_pairs_.end();
  }*/
/*  if (!ip_port_pairs_.empty()) {
    match |= (r->prot == 6 || r->prot == 13) &&
             (ip_port_pairs_.find(make_pair(sip, r->srcport)) != ip_port_pairs_.end() ||
              ip_port_pairs_.find(make_pair(dip, r->dstport)) != ip_port_pairs_.end());
  }*/
 /* if (!ip_pport_pairs_.empty()) {
    match |= (r->prot == 6 || r->prot == 13) &&
             (ip_pport_pairs_.find(make_pair(sip, r->dstport)) != ip_pport_pairs_.end() ||
              ip_pport_pairs_.find(make_pair(dip, r->srcport)) != ip_pport_pairs_.end());
  }*/
  return match;
}

void BWFilter::Merge(const BWFilter& filter) {
  ips_.insert(filter.ips_.begin(), filter.ips_.end());
 // ports_.insert(filter.ports_.begin(), filter.ports_.end());
 // ip_pip_pairs_.insert(filter.ip_pip_pairs_.begin(), filter.ip_pip_pairs_.end());
//  ip_port_pairs_.insert(filter.ip_port_pairs_.begin(), filter.ip_port_pairs_.end());
 // ip_pport_pairs_.insert(filter.ip_pport_pairs_.begin(), filter.ip_pport_pairs_.end());
}

bool BWFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for (auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    UpdateBW(r.first, r.last, r.v4.srcaddr, r.srcport, r.v4.dstaddr, r.dstport, r.prot, r.dPkts, r.dOctets, r.tos);
  }
  return true;
}


bool BWFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
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

    UpdateBW6(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.dPkts, r.dOctets, r.tos);
  }
  return true;
}

bool BWFilter::UpdateBW(u32 first, u32 last, u32 sip, u16 sport, u32 dip, u16 dport, u16 proto, u64 pkts, u64 bytes, u8 tos) {
  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  event.sip[0] = sip;
  event.sport = sport;
  event.dip[0] = dip;
  event.dport = dport;
  event.proto = proto;

  if (proto == 6) {
    if ((tos & 0x01) && ips_.find(dip) != ips_.end()) {
      BWKey k;
      k.sip[0] = dip;
      k.dip[0] = sip;
      k.proto = proto;
      k.ti_mark = true;
      auto it = bws_.find(k);
      if (it == bws_.end()) {
        BWStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        bws_[k] = p;

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
        ++p.flows;
        p.pkts += pkts;
        p.bytes += bytes;

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
  } else {
    if (ips_.find(sip) != ips_.end()) {
      BWKey k;
      k.sip[0] = sip;
      k.dip[0] = dip;
      k.proto = proto;
      k.ti_mark = false;
      auto it = bws_.find(k);
      if (it == bws_.end()) {
        BWStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        bws_[k] = p;

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
        ++p.flows;
        p.pkts += pkts;
        p.bytes += bytes;

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
    } else if (ips_.find(dip) != ips_.end()) {
      BWKey k;
      k.sip[0] = dip;
      k.dip[0] = sip;
      k.proto = proto;
      k.ti_mark = true;
      auto it = bws_.find(k);
      if (it == bws_.end()) {
        BWStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        bws_[k] = p;

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
        ++p.flows;
        p.pkts += pkts;
        p.bytes += bytes;

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

bool BWFilter::UpdateBW6(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, u64 pkts, u64 bytes, u8 tos) {
  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;

  struct in6_addr sip6, dip6;
  std::copy(sip, sip+4, sip6.s6_addr32);
  std::copy(dip, dip+4, dip6.s6_addr32);

  if (proto == 6) {
    if ((tos & 0x01) && ips6_.find(ipnum_to_ipstr_v6(dip6)) != ips6_.end()) {
      BWKey k;
      std::copy(dip, dip+4, k.sip);
      std::copy(sip, sip+4, k.dip);
      k.proto = proto;
      k.ti_mark = true;
      auto it = bws_.find(k);
      if (it == bws_.end()) {
        BWStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        bws_[k] = p;

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
        ++p.flows;
        p.pkts += pkts;
        p.bytes += bytes;

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
  } else {
    if (ips6_.find(ipnum_to_ipstr_v6(sip6)) != ips6_.end()) {
      BWKey k;
      std::copy(sip, sip+4, k.sip);
      std::copy(dip, dip+4, k.dip);
      k.proto = proto;
      k.ti_mark = false;
      auto it = bws_.find(k);
      if (it == bws_.end()) {
        BWStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        bws_[k] = p;

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
        ++p.flows;
        p.pkts += pkts;
        p.bytes += bytes;

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
    } else if (ips6_.find(ipnum_to_ipstr_v6(dip6)) != ips6_.end()) {
      BWKey k;
      std::copy(dip, dip+4, k.sip);
      std::copy(sip, sip+4, k.dip);
      k.proto = proto;
      k.ti_mark = true;
      auto it = bws_.find(k);
      if (it == bws_.end()) {
        BWStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        bws_[k] = p;

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
        ++p.flows;
        p.pkts += pkts;
        p.bytes += bytes;

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

event::GenEventRes BWFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<BWFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);
  GenEventRes events;
  ptr->DivideMode();
	for(auto it = ptr->bws_.begin(); it != ptr->bws_.end(); ++it) {
		auto& s = it->first;
		auto& p = it->second;
		ptr->InsertBWToTSDB(s, p);
		if (ptr->is_black_list_ && s.ti_mark) 
			ptr->GenerateEvents(s, p, &events);
	}	
  return events;
}

void BWFilter::InsertBWToTSDB(const BWKey& s, const BWStat& stat) {
	
	BWStat new_stat;
	Slice old_value;

	if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
									(old_value.size() >= sizeof(BWStat))) {
		auto* old_stat = (BWStat*)old_value.data();
    new_stat.first = std::min(stat.first, old_stat->first);
    new_stat.last = std::max(stat.last, old_stat->last);
    new_stat.flows = stat.flows + old_stat->flows;
    new_stat.pkts = stat.pkts + old_stat->pkts;
    new_stat.bytes = stat.bytes + old_stat->bytes;
  } else {
    new_stat = stat;
  }
  tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));

}


void BWFilter::FilterBwlist(const feature::FeatureReq& req, 
																	feature::FeatureResponse* resp) {
	tsdb_->Scan(
		req.starttime(), req.endtime(),
			[this, &req, resp](const Slice& key, const Slice& value) {
      CheckBwlist(key, value, req);
  });
  
  for (auto it = res_bws_.begin(); it != res_bws_.end(); ++it)
    resp->MergeFrom(it->second);
}

void BWFilter::FilterBWEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckBWEvent(key, value, req, resp);
    });
}

void BWFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void BWFilter::AddRecord(const BWKey& key, const FeatureRecord& new_rec) {
  auto it = res_bws_.find(key);
  if (it == res_bws_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_bws_[key] = resp;
  } else {
    auto& resp = res_bws_[key];
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

void BWFilter::CheckBWEvent(const Slice& key, const Slice& value,
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

void BWFilter::CheckBwlist(const Slice& key, 
													 const Slice& value, 
													 const feature::FeatureReq& req) {
	const BWKey& bwkey = *(const BWKey*)key.data();
	const BWStat& stat = *(const BWStat*)value.data();
	if (stat.last < req.starttime() || stat.first > req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(bwkey.sip, bwkey.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(bwkey.dip, bwkey.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(bwkey.sip[0]);
    dip = ipnum_to_ipstr(bwkey.dip[0]);
  }

	if (req.has_sip() && req.sip() != sip) return;
	if (req.has_dip() && req.dip() != dip) return;
	if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
	if (req.has_proto() && req.proto() != bwkey.proto) return;
  if (req.has_ti_mark() && req.ti_mark() != bwkey.ti_mark) return;

  string ti_mark;
	FeatureRecord rec;
	rec.set_time(stat.first);
  rec.set_duration(stat.last - stat.first);
	rec.set_sip(sip);
	rec.set_protocol(bwkey.proto);
	rec.set_dip(dip);
	rec.set_flows(stat.flows);
	rec.set_pkts(stat.pkts);
	rec.set_bytes(stat.bytes);
  if (bwkey.ti_mark)
    ti_mark = "res";
  else 
    ti_mark = "req";  
  rec.set_ti_mark(ti_mark);
	if (DEBUG) log_info("Got Bwlist Record: %s\n", rec.DebugString().c_str());
	AddRecord(bwkey, rec);
}

BWFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et)
	    : event_config(e), dev_id(devid), start_time(st), end_time(et) {
	if (DEBUG) log_info("EventGenerator initialized.\n");
}

void BWFilter::DivideMode() {
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

void BWFilter::GenerateEvents(const BWKey& s, const BWStat& p, GenEventRes* events) {

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
        e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]: " + proto_to_string(s.proto) + " ");
      } else
        e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>" + ipnum_to_ipstr(s.dip[0]) + ": " + proto_to_string(s.proto) + " ");
      e->set_thres_value(pat.min);
      e->set_alarm_value(value);
      e->set_value_type(data_type);
      e->set_model_id(2);

      //生成事件特征数据，即事件五元组详细信息
      GenEventFeature(s, e);
    }
  }
}

void BWFilter::GenEventFeature(const BWKey& s, const event::GenEventRecord* e) {
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

void BWFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}
