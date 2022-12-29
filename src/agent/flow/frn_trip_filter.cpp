#include "frn_trip_filter.h"
#include "../../common/common.h"
#include "../../common/ip.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/datetime.h"
#include "../../common/common_filter.hpp"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include <utility>

FrnTripFilter::FrnTripFilter(u32 dev_id, const string& model)
	: FlowFilter(), dev_id_(dev_id) {}

FrnTripFilter* FrnTripFilter::Create(u32 dev_id, const string& model, DBBuilder* event_builder) {
	auto* filter = new FrnTripFilter(dev_id, model);
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_frn"));
	if (DEBUG) log_info("FrnTrip filter initialized.\n");
	return filter;
}

bool FrnTripFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
	for(auto it = flowset->begin(); it != flowset->end(); it++) {
		auto r = *it;
    if (r.prot != 6) continue;
		if(!(r.tos & 0x01)) continue;
		uint32_t sip[4], dip[4];
		memset(sip, 0, sizeof(uint)*4);
		memset(dip, 0, sizeof(uint)*4);
		sip[0] = r.v4.srcaddr;
		dip[0] = r.v4.dstaddr;

		UpdateFrnTrip(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.dPkts, r.dOctets);
		
	}
	return true;
}

bool FrnTripFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
	for(auto it = flowset->begin(); it != flowset->end(); it++) {
		auto r = *it;
    if (r.prot != 6) continue;
		if(!(r.tos & 0x01)) continue;
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
 
		UpdateFrnTrip(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.dPkts, r.dOctets);
		
	}
	return true;
}

void FrnTripFilter::UpdateFrnTrip(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, u64 pkts, u64 bytes) {
  //事件五元组信息  
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;

	FrnTripKey ftkey;
	
	memset(&ftkey, 0, sizeof(struct FrnTripKey));
	std::copy(sip, sip+4, ftkey.sip);
	std::copy(dip, dip+4, ftkey.dip);
	ftkey.dport = dport;

	auto it = frntrips_.find(ftkey);
	if (it == frntrips_.end()) {
		FrnTripStat p;
		memset(&p, 0, sizeof(struct FrnTripStat));
		p.first = first;
		p.last = last;
		p.flows = 1;
		p.pkts = pkts;
		p.bytes = bytes;
		frntrips_[ftkey] = p;

    //统计五元组信息
    EventValue ep;
    ep.first = first;
    ep.last = last;
    ep.flows = 1;
    ep.pkts = pkts;
    ep.bytes = bytes;
    map<EventKey, EventValue> event_tmp;
    event_tmp[event] = ep;
    event_details_[ftkey] = event_tmp;
	} else {
		auto& p = it->second;
		p.first = MIN(p.first, first);
		p.last = MAX(p.last, last);
		++p.flows;
		p.pkts += pkts;
		p.bytes += bytes;

    //统计五元组信息
    auto itr = event_details_[ftkey].find(event);
    if (itr == event_details_[ftkey].end()) {
      EventValue p;
      p.first = first;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      event_details_[ftkey][event] = p;
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

event::GenEventRes FrnTripFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<FrnTripFilter>& ptr, const string& model, std::set<string>& asset_ips) {
	if (model == "V6")
		ptr->UpdateByFlowV6(flowset);
	else
		ptr->UpdateByFlow(flowset);

	GenEventRes events;
	vector<set<string>> sip_vec;
	vector<set<string>> dip_vec;
	u32 min = 0;

	int cnt = 0;
	for (auto it = ptr->frntrips_.begin(); it != ptr->frntrips_.end(); ++it) {
		auto& s = it->first;
		auto& p = it->second;

		cnt++;
		for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
			auto event_config = ptr->event_generators_[i].event_config;

			if (cnt == 1) {
				// 只读取一遍规则
				// min
				if (event_config.has_min())
					min = event_config.min();
				// sip
				if (event_config.has_sip() && !event_config.sip().empty()) {
					//规则设置了sip则读取规则配置
					string siplist = const_cast<char*>(event_config.sip().c_str());
					auto vec = split_string(siplist, ",");
					sip_vec.emplace_back(vec);
				} else {
					// 规则未设置sip则使用internal_ip作为sip
					sip_vec.emplace_back(asset_ips);
				}
				// dip
				if (event_config.has_dip() && !event_config.dip().empty()) {
					string diplist = const_cast<char*>(event_config.ip().c_str());
					auto vec = split_string(diplist, ",");
					dip_vec.emplace_back(vec);
				} else {
          set<string> em;
          dip_vec.emplace_back(em);
        }
			}
			// 是否小于规则设置的流量阈值
			if (p.bytes < min) continue;

			// 是否在规则设置的检测IP中
			bool sflag = false;
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
	
			ptr->GenerateEvents(s, p, &events, ptr->event_generators_[i]);
		}
	}

	return events;
}


//////////////////////////////////////////////////////////////////
/* Generate events */

FrnTripFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et) 
	: event_config(e), dev_id(devid), start_time(st), end_time(et) {
	
	if (DEBUG) log_info("EventGenerator initialized.\n");
}

void FrnTripFilter::GenerateEvents(const FrnTripKey& s, const FrnTripStat& p, GenEventRes* events, EventGenerator& gen) {
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
			e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]:" + to_string(s.dport) + " TCP ");      
		} else {
			e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>"+ ipnum_to_ipstr(s.dip[0]) + ":" + to_string(s.dport) + " TCP ");  
		}
		e->set_thres_value(event_config.min());
		e->set_alarm_value(p.bytes);
		e->set_value_type(event_config.data_type());
    e->set_model_id(0);

    //生成事件特征数据，即事件五元组详细信息
    GenEventFeature(s, e);
	}
}

void FrnTripFilter::GenEventFeature(const FrnTripKey& s, const event::GenEventRecord* e) {
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

void FrnTripFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}

void FrnTripFilter::CheckFrnTripEvent(const Slice& key, const Slice& value,
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

void FrnTripFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void FrnTripFilter::FilterFrnTripEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckFrnTripEvent(key, value, req, resp);
    });
}
