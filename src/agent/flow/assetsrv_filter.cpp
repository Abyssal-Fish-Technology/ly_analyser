#include "assetsrv_filter.h"
#include "common_model_filter.hpp"
#include "../../common/common.h"
#include "../dump/libnfdump.h"
#include "../../common/log.h"
#include "../../common/ip.h"
#include "../../common/asset.h"
#include "../../common/datetime.h"
#include "../../common/strings.h"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include "../define.h"
#include <utility>

#define SRVMAXPORT 65535

using namespace std;
using namespace event;

static std::vector<set<Pattern>> event_models;
static std::vector<set<Pattern>> feature_models;

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

AssetsrvFilter::AssetsrvFilter(u32 dev_id, const string& model)
	: FlowFilter(), dev_id_(dev_id), model_(model) {}

AssetsrvFilter* AssetsrvFilter::Create(u32 dev_id, const string& model, DBBuilder* builder, DBBuilder* event_builder) {
	
	auto* filter = new AssetsrvFilter(dev_id, model);
  if (builder) 
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_asset_srv"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_srv"));
  if (DEBUG) log_info("asset assetsrv filter initialized for update.\n");
  return filter;
}

bool AssetsrvFilter::CheckFlow(FlowPtr flow) {
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
    
bool AssetsrvFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  set<u16> tcp_port{11211, 12345, 18080, 10080, 27910};
  for(auto it=flowset->begin();it!=flowset->end();it++) {
    auto r = *it;
    if (r.tcp_flags == 20) continue;
    if (r.prot != 6 && r.prot != 17) continue;
    if (r.prot == 17 && (!udp_port.count(r.srcport) && !udp_port.count(r.dstport))) continue;
    if (r.srcport == 0 || r.dstport == 0) continue;
    if (r.prot == 6 && ((r.srcport >= SRVMAXPORT && !tcp_port.count(r.srcport)) ||
                        (r.dstport >= SRVMAXPORT && !tcp_port.count(r.dstport)))) continue;

    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;
    UpdateService(r.first, r.last, sip, r.srcport, r.prot, dip, r.dstport, r.tos, r.pname, r.dPkts, r.dOctets,
                  r.service_type, r.service_name, r.service_version, r.dev_type, r.dev_name, r.dev_vendor,
                  r.dev_model, r.os_type, r.os_name, r.os_version, r.midware_type, r.midware_name, r.midware_version,
                  r.service_time, r.dev_time, r.os_time, r.midware_time);
  }
  return true;
}

bool AssetsrvFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  set<u16> tcp_port{11211, 12345, 18080, 10080, 27910};
  for(auto it=flowset->begin();it!=flowset->end();it++) {
    auto r = *it;
    if (r.tcp_flags == 20) continue;
    if (r.prot != 6 && r.prot != 17) continue;
    if (r.prot == 17 && (!udp_port.count(r.srcport) && !udp_port.count(r.dstport))) continue;
    if (r.srcport == 0 || r.dstport == 0) continue;
    if (r.prot == 6 && ((r.srcport >= SRVMAXPORT && !tcp_port.count(r.srcport)) ||
                        (r.dstport >= SRVMAXPORT && !tcp_port.count(r.dstport)))) continue;
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

    UpdateService(r.first, r.last, sip, r.srcport, r.prot, dip, r.dstport, r.tos, r.pname, r.dPkts, r.dOctets,
                  r.service_type, r.service_name, r.service_version, r.dev_type, r.dev_name, r.dev_vendor,
                  r.dev_model, r.os_type, r.os_name, r.os_version, r.midware_type, r.midware_name, r.midware_version,
                  r.service_time, r.dev_time, r.os_time, r.midware_time);
  }
  return true;
}

void AssetsrvFilter::UpdateService(u32 first, u32 last, u32 sip[], u16 sport, u16 proto,
                          u32 dip[], u16 dport, u8 tos, char* pname, u64 pkts, u64 bytes,
                          char* service_type, char* service_name, char* service_version,
                          char* dev_type, char* dev_name, char* dev_vendor, char* dev_model,
                          char* os_type, char* os_name, char* os_version,
                          char* midware_type, char* midware_name, char* midware_version,
                          u64 srv_time, u64 dev_time, u64 os_time, u64 midware_time) {
  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;

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
        if (0 != strlen(pname))
          memcpy(p.app_proto, pname, strlen(pname)+1);
        else
          memcpy(p.app_proto, service_name, strlen(service_name)+1);
        
        p.pkts = pkts;
        p.bytes = bytes;
        memcpy(p.srv_type, service_type, strlen(service_type)+1);
        memcpy(p.srv_name, service_name, strlen(service_name)+1);
        memcpy(p.srv_version, service_version, strlen(service_version)+1);
        memcpy(p.dev_type, dev_type, strlen(dev_type)+1);
        memcpy(p.dev_name, dev_name, strlen(dev_name)+1);
        memcpy(p.dev_vendor, dev_vendor, strlen(dev_vendor)+1);
        memcpy(p.dev_model, dev_model, strlen(dev_model)+1);
        memcpy(p.os_type, os_type, strlen(os_type)+1);
        memcpy(p.os_name, os_name, strlen(os_name)+1);
        memcpy(p.os_version, os_version, strlen(os_version)+1);
        memcpy(p.midware_type, midware_type, strlen(midware_type)+1);
        memcpy(p.midware_name, midware_name, strlen(midware_name)+1);
        memcpy(p.midware_version, midware_version, strlen(midware_version)+1);
        if (strlen(service_type)) p.srv_time = srv_time;
        if (strlen(dev_type)) p.dev_time = dev_time;
        if (strlen(os_type)) p.os_time = os_time;
        if (strlen(midware_type)) p.midware_time = midware_time;
        srvreq_[req] = p;
      } else {
        auto& p = it->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flow_count++;
        if (0 != strlen(pname)) memcpy(p.app_proto, pname, strlen(pname)+1);
        p.pkts += pkts;
        p.bytes += bytes;
        if (0 != strlen(service_type)) {
          if (0 == strlen(pname))
            memcpy(p.app_proto, service_name, strlen(service_name)+1);

          memcpy(p.srv_type, service_type, strlen(service_type)+1);
          memcpy(p.srv_name, service_name, strlen(service_name)+1);
          memcpy(p.srv_version, service_version, strlen(service_version)+1);
          p.srv_time = srv_time;
        }
        if (0 != strlen(dev_type)) {
          memcpy(p.dev_type, dev_type, strlen(dev_type)+1);
          memcpy(p.dev_name, dev_name, strlen(dev_name)+1);
          memcpy(p.dev_vendor, dev_vendor, strlen(dev_vendor)+1);
          memcpy(p.dev_model, dev_model, strlen(dev_model)+1);
          p.dev_time = dev_time;
        }
        if (0 != strlen(os_type)) {
          memcpy(p.os_type, os_type, strlen(os_type)+1);
          memcpy(p.os_name, os_name, strlen(os_name)+1);
          memcpy(p.os_version, os_version, strlen(os_version)+1);
          p.os_time = os_time;
        }
        if (0 != strlen(midware_type)) {
          memcpy(p.midware_type, midware_type, strlen(midware_type)+1);
          memcpy(p.midware_name, midware_name, strlen(midware_name)+1);
          memcpy(p.midware_version, midware_version, strlen(midware_version)+1);
          p.midware_time = midware_time;
        }
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
      if (0 != strlen(pname))
        memcpy(p.app_proto, pname, strlen(pname)+1);
      else
        memcpy(p.app_proto, service_name, strlen(service_name)+1);
      p.pkts = pkts;
      p.bytes = bytes;
      memcpy(p.srv_type, service_type, strlen(service_type)+1);
      memcpy(p.srv_name, service_name, strlen(service_name)+1);
      memcpy(p.srv_version, service_version, strlen(service_version)+1);
      memcpy(p.dev_type, dev_type, strlen(dev_type)+1);
      memcpy(p.dev_name, dev_name, strlen(dev_name)+1);
      memcpy(p.dev_vendor, dev_vendor, strlen(dev_vendor)+1);
      memcpy(p.dev_model, dev_model, strlen(dev_model)+1);
      memcpy(p.os_type, os_type, strlen(os_type)+1);
      memcpy(p.os_name, os_name, strlen(os_name)+1);
      memcpy(p.os_version, os_version, strlen(os_version)+1);
      memcpy(p.midware_type, midware_type, strlen(midware_type)+1);
      memcpy(p.midware_name, midware_name, strlen(midware_name)+1);
      memcpy(p.midware_version, midware_version, strlen(midware_version)+1);
      if (strlen(service_type)) p.srv_time = srv_time;
      if (strlen(dev_type)) p.dev_time = dev_time;
      if (strlen(os_type)) p.os_time = os_time;
      if (strlen(midware_type)) p.midware_time = midware_time;
      srvres_[res] = p;

      //统计五元组信息
      EventValue ep;
      ep.first = first;
      ep.last = last;
      ep.flows = 1;
      ep.pkts = pkts;
      ep.bytes = bytes;
      map<EventKey, EventValue> event_tmp;
      event_tmp[event] = ep;
      event_details_[res] = event_tmp;
    } else {
      auto& p = it->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      p.flow_count++;
      if (0 != strlen(pname)) memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts += pkts;
      p.bytes += bytes;
      if (0 != strlen(service_type)) {
        if (0 == strlen(pname))
          memcpy(p.app_proto, service_name, strlen(service_name)+1);
        memcpy(p.srv_type, service_type, strlen(service_type)+1);
        memcpy(p.srv_name, service_name, strlen(service_name)+1);
        memcpy(p.srv_version, service_version, strlen(service_version)+1);
        p.srv_time = srv_time;
      }
      if (0 != strlen(dev_type)) {
        memcpy(p.dev_type, dev_type, strlen(dev_type)+1);
        memcpy(p.dev_name, dev_name, strlen(dev_name)+1);
        memcpy(p.dev_vendor, dev_vendor, strlen(dev_vendor)+1);
        memcpy(p.dev_model, dev_model, strlen(dev_model)+1);
        p.dev_time = dev_time;
      }
      if (0 != strlen(os_type)) {
        memcpy(p.os_type, os_type, strlen(os_type)+1);
        memcpy(p.os_name, os_name, strlen(os_name)+1);
        memcpy(p.os_version, os_version, strlen(os_version)+1);
        p.os_time = os_time;
      }
      if (0 != strlen(midware_type)) {
        memcpy(p.midware_type, midware_type, strlen(midware_type)+1);
        memcpy(p.midware_name, midware_name, strlen(midware_name)+1);
        memcpy(p.midware_version, midware_version, strlen(midware_version)+1);
        p.midware_time = midware_time;
      }
     
      //统计五元组信息 
      auto itr = event_details_[res].find(event);
      if (itr == event_details_[res].end()) {
        EventValue p;
        p.first = first;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        event_details_[res][event] = p;
      } else {
        auto& p = itr->second;
        p.first = MIN(p.first, first);
        p.last = MAX(p.last, last);
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;
      }
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
      if (0 != strlen(pname))
        memcpy(p.app_proto, pname, strlen(pname)+1);
      else
        memcpy(p.app_proto, service_name, strlen(service_name)+1);
      p.pkts = pkts;
      p.bytes = bytes;
      memcpy(p.srv_type, service_type, strlen(service_type)+1);
      memcpy(p.srv_name, service_name, strlen(service_name)+1);
      memcpy(p.srv_version, service_version, strlen(service_version)+1);
      memcpy(p.dev_type, dev_type, strlen(dev_type)+1);
      memcpy(p.dev_name, dev_name, strlen(dev_name)+1);
      memcpy(p.dev_vendor, dev_vendor, strlen(dev_vendor)+1);
      memcpy(p.dev_model, dev_model, strlen(dev_model)+1);
      memcpy(p.os_type, os_type, strlen(os_type)+1);
      memcpy(p.os_name, os_name, strlen(os_name)+1);
      memcpy(p.os_version, os_version, strlen(os_version)+1);
      memcpy(p.midware_type, midware_type, strlen(midware_type)+1);
      memcpy(p.midware_name, midware_name, strlen(midware_name)+1);
      memcpy(p.midware_version, midware_version, strlen(midware_version)+1);
      if (strlen(service_type)) p.srv_time = srv_time;
      if (strlen(dev_type)) p.dev_time = dev_time;
      if (strlen(os_type)) p.os_time = os_time;
      if (strlen(midware_type)) p.midware_time = midware_time;
      srvreq_[req] = p;
    } else {
      auto& p = it->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      p.flow_count++;
      if (0 != strlen(pname)) memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts += pkts;
      p.bytes += bytes;
      if (0 != strlen(service_type)) {
        if (0 == strlen(pname))
          memcpy(p.app_proto, service_name, strlen(service_name)+1);
        memcpy(p.srv_type, service_type, strlen(service_type)+1);
        memcpy(p.srv_name, service_name, strlen(service_name)+1);
        memcpy(p.srv_version, service_version, strlen(service_version)+1);
        p.srv_time = srv_time;
      }
      if (0 != strlen(dev_type)) {
        memcpy(p.dev_type, dev_type, strlen(dev_type)+1);
        memcpy(p.dev_name, dev_name, strlen(dev_name)+1);
        memcpy(p.dev_vendor, dev_vendor, strlen(dev_vendor)+1);
        memcpy(p.dev_model, dev_model, strlen(dev_model)+1);
        p.dev_time = dev_time;
      }
      if (0 != strlen(os_type)) {
        memcpy(p.os_type, os_type, strlen(os_type)+1);
        memcpy(p.os_name, os_name, strlen(os_name)+1);
        memcpy(p.os_version, os_version, strlen(os_version)+1);
        p.os_time = os_time;
      }
      if (0 != strlen(midware_type)) {
        memcpy(p.midware_type, midware_type, strlen(midware_type)+1);
        memcpy(p.midware_name, midware_name, strlen(midware_name)+1);
        memcpy(p.midware_version, midware_version, strlen(midware_version)+1);
        p.midware_time = midware_time;
      }
    } 
    PvcKey res;
    std::copy(sip, sip+4, res.ip);
    res.proto = proto;
    res.port = sport;
    if (!udp_port.count(sport)) return;   //udp回应只要sport在udp端口列表中的
    res.srv_mark = 1;

    auto its = srvres_.find(res);
    if (its == srvres_.end()) {
      PortStat p;
      memset(&p, 0, sizeof(struct PortStat));
      p.first = first;
      p.last = last;
      p.flow_count = 1;
      if (0 != strlen(pname))
        memcpy(p.app_proto, pname, strlen(pname)+1);
      else
        memcpy(p.app_proto, service_name, strlen(service_name)+1);

      p.pkts = pkts;
      p.bytes = bytes;
      memcpy(p.srv_type, service_type, strlen(service_type)+1);
      memcpy(p.srv_name, service_name, strlen(service_name)+1);
      memcpy(p.srv_version, service_version, strlen(service_version)+1);
      memcpy(p.dev_type, dev_type, strlen(dev_type)+1);
      memcpy(p.dev_name, dev_name, strlen(dev_name)+1);
      memcpy(p.dev_vendor, dev_vendor, strlen(dev_vendor)+1);
      memcpy(p.dev_model, dev_model, strlen(dev_model)+1);
      memcpy(p.os_type, os_type, strlen(os_type)+1);
      memcpy(p.os_name, os_name, strlen(os_name)+1);
      memcpy(p.os_version, os_version, strlen(os_version)+1);
      memcpy(p.midware_type, midware_type, strlen(midware_type)+1);
      memcpy(p.midware_name, midware_name, strlen(midware_name)+1);
      memcpy(p.midware_version, midware_version, strlen(midware_version)+1);
      if (strlen(service_type)) p.srv_time = srv_time;
      if (strlen(dev_type)) p.dev_time = dev_time;
      if (strlen(os_type)) p.os_time = os_time;
      if (strlen(midware_type)) p.midware_time = midware_time;
      srvres_[res] = p;

      //统计五元组信息
      EventValue ep;
      ep.first = first;
      ep.last = last;
      ep.flows = 1;
      ep.pkts = pkts;
      ep.bytes = bytes;
      map<EventKey, EventValue> event_tmp;
      event_tmp[event] = ep;
      event_details_[res] = event_tmp;
    } else {
      auto& p = its->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      p.flow_count++;
      if (0 != strlen(pname)) memcpy(p.app_proto, pname, strlen(pname)+1);
      p.pkts += pkts;
      p.bytes += bytes;
      if (0 != strlen(service_type)) {
        if (0 == strlen(pname))
          memcpy(p.app_proto, service_name, strlen(service_name)+1);
        memcpy(p.srv_type, service_type, strlen(service_type)+1);
        memcpy(p.srv_name, service_name, strlen(service_name)+1);
        memcpy(p.srv_version, service_version, strlen(service_version)+1);
        p.srv_time = srv_time;
      }
      if (0 != strlen(dev_type)) {
        memcpy(p.dev_type, dev_type, strlen(dev_type)+1);
        memcpy(p.dev_name, dev_name, strlen(dev_name)+1);
        memcpy(p.dev_vendor, dev_vendor, strlen(dev_vendor)+1);
        memcpy(p.dev_model, dev_model, strlen(dev_model)+1);
        p.dev_time = dev_time;
      }
      if (0 != strlen(os_type)) {
        memcpy(p.os_type, os_type, strlen(os_type)+1);
        memcpy(p.os_name, os_name, strlen(os_name)+1);
        memcpy(p.os_version, os_version, strlen(os_version)+1);
        p.os_time = os_time;
      }
      if (0 != strlen(midware_type)) {
        memcpy(p.midware_type, midware_type, strlen(midware_type)+1);
        memcpy(p.midware_name, midware_name, strlen(midware_name)+1);
        memcpy(p.midware_version, midware_version, strlen(midware_version)+1);
        p.midware_time = midware_time;
      }

      //统计五元组信息 
      auto itr = event_details_[res].find(event);
      if (itr == event_details_[res].end()) {
        EventValue p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        event_details_[res][event] = p;
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

bool AssetsrvFilter::LoadPatternFromFile() {
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
  
  feature_models.push_back(ip_port_proto_);
  feature_models.push_back(ip_port_);
  feature_models.push_back(ip_proto_);
  feature_models.push_back(port_proto_);
  feature_models.push_back(ip_);
  feature_models.push_back(port_);
  feature_models.push_back(proto_);
  feature_models.push_back(flows_);
  return true;
}

void AssetsrvFilter::DividePatterns(Pattern& pat, vector<string>& res) {

  if (res[0] == "SRV") {
    if (!res[3].empty() && !res[4].empty() && !res[5].empty()) {
      ip_port_proto_.emplace(pat);
    } else if (!res[3].empty() && !res[4].empty() && res[5].empty()) {
      ip_port_.emplace(pat);
    } else if (!res[3].empty() && res[4].empty() && !res[5].empty()) {
      ip_proto_.emplace(pat);
    } else if (res[3].empty() && !res[4].empty() && !res[5].empty()) {
      port_proto_.emplace(pat);
    } else if (!res[3].empty() && res[4].empty() && res[5].empty()) {
      ip_.emplace(pat);
    } else if (res[3].empty() && !res[4].empty() && res[5].empty()) {
      port_.emplace(pat);
    } else if (res[3].empty() && res[4].empty() && !res[5].empty()) {
      proto_.emplace(pat);
    } else {
      flows_.emplace(pat);
    }
  }
}

event::GenEventRes AssetsrvFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<AssetsrvFilter>& ptr, 
                                                  const string& model, std::set<string>& asset_ips) {
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

  for (auto it=ptr->srvtos_.begin();it!=ptr->srvtos_.end();it++) {
    if (ptr->srvres_.count(*it)) {
      ptr->srvres_.erase(*it);
    }
  }

  for (auto it=ptr->srvres_.begin();it!=ptr->srvres_.end();it++) {
    auto& s = it->first;
    auto& p = it->second;
    
    if (model == "V6") {
      for (auto itr = asset_ips.begin();itr != asset_ips.end();itr++) {
        auto ip_segment = *itr;
        struct in6_addr ip6;
        std::copy(s.ip, s.ip+4, ip6.s6_addr32);
        if (valid_ip_v6(ipnum_to_ipstr_v6(ip6), ip_segment)) {
          PvcKey res;
          std::copy(s.ip, s.ip+4, res.ip);
          res.proto = s.proto;
          res.port = s.port;
          res.srv_mark = 0;
          if (ptr->srvreq_.count(res)) {
            ptr->GenerateFeature(s, p);
            ptr->GenerateFeature(res, ptr->srvreq_[res]);
            ptr->GenerateEvents(s, p, &events);
          }
          break;
        }
      }
    } else {
      for (auto itr = asset_ips.begin();itr != asset_ips.end();itr++) {
        auto ip_segment = *itr;
        if (valid_ip(ipnum_to_ipstr(s.ip[0]), ip_segment)) {
          PvcKey res;
          std::copy(s.ip, s.ip+4, res.ip);
          res.proto = s.proto;
          res.port = s.port;
          res.srv_mark = 0;
          if (ptr->srvreq_.count(res)) {
            ptr->GenerateFeature(s, p);
            ptr->GenerateFeature(res, ptr->srvreq_[res]);
            ptr->GenerateEvents(s, p, &events);
          }
          break;
        }
      }
    }
  }

  return events;
}

void AssetsrvFilter::InsertSrvToTSDB(const PvcKey& s, const PortStat& stat) {

	/*if (DEBUG) {
		ostringstream oss;
		oss << "Found assetsrv: " << datetime::format_timestamp(stat.first) << ' '
        << stat.last - stat.first << "s PROTO:" << proto_to_string(s.proto) << ' '
        << ipnum_to_ipstr(s.ip) << " : " << s.port << " flow_count:" 
				<< stat.flow_count << " pkts:" << stat.pkts
        << " bytes" << stat.bytes << '\n';
    log_info("%s\n", oss.str().c_str());
	}*/
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
    if (0 != strlen(stat.app_proto))
      strcpy(new_stat.app_proto, stat.app_proto);
    else
      strcpy(new_stat.app_proto, old_stat->app_proto);
    if (0 != strlen(stat.srv_type)) {
      strcpy(new_stat.srv_type, stat.srv_type);
      strcpy(new_stat.srv_name, stat.srv_name);
      strcpy(new_stat.srv_version, stat.srv_version);
      new_stat.srv_time = stat.srv_time;
    }  else {
      strcpy(new_stat.srv_type, old_stat->srv_type);
      strcpy(new_stat.srv_name, old_stat->srv_name);
      strcpy(new_stat.srv_version, old_stat->srv_version);
      new_stat.srv_time = old_stat->srv_time;
    }
    if (0 != strlen(stat.dev_type)) {
      strcpy(new_stat.dev_type, stat.dev_type);
      strcpy(new_stat.dev_name, stat.dev_name);
      strcpy(new_stat.dev_vendor, stat.dev_vendor);
      strcpy(new_stat.dev_model, stat.dev_model);
      new_stat.dev_time = stat.dev_time;
    }  else {
      strcpy(new_stat.dev_type, old_stat->dev_type);
      strcpy(new_stat.dev_name, old_stat->dev_name);
      strcpy(new_stat.dev_vendor, old_stat->dev_vendor);
      strcpy(new_stat.dev_model, old_stat->dev_model);
      new_stat.dev_time = old_stat->dev_time;
    }
    if (0 != strlen(stat.os_type)) {
      strcpy(new_stat.os_type, stat.os_type);
      strcpy(new_stat.os_name, stat.os_name);
      strcpy(new_stat.os_version, stat.os_version);
      new_stat.os_time = stat.os_time;
    }  else {
      strcpy(new_stat.os_type, old_stat->os_type);
      strcpy(new_stat.os_name, old_stat->os_name);
      strcpy(new_stat.os_version, old_stat->os_version);
      new_stat.os_time = old_stat->os_time;
    }
    if (0 != strlen(stat.midware_type)) {
      strcpy(new_stat.midware_type, stat.midware_type);
      strcpy(new_stat.midware_name, stat.midware_name);
      strcpy(new_stat.midware_version, stat.midware_version);
      new_stat.midware_time = stat.midware_time;
    }  else {
      strcpy(new_stat.midware_type, old_stat->midware_type);
      strcpy(new_stat.midware_name, old_stat->midware_name);
      strcpy(new_stat.midware_version, old_stat->midware_version);
      new_stat.midware_time = old_stat->midware_time;
    }
	} else {
		new_stat = stat;
	}
	tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}

void AssetsrvFilter::FilterService(const feature::FeatureReq& req, feature::FeatureResponse* resp){
	tsdb_->Scan(req.starttime(), req.endtime(),
		[this, &req, resp](const Slice& key, const Slice& value) {
			CheckService(key, value, req);
		});

  for (auto it = res_srvs_.begin(); it != res_srvs_.end(); ++it)
    resp->MergeFrom(it->second);
}

void AssetsrvFilter::FilterServiceEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckServiceEvent(key, value, req, resp);
    });
}

void AssetsrvFilter::AddRecord(const PvcKey& key, const FeatureRecord& new_rec) {
  auto it = res_srvs_.find(key);
  if (it == res_srvs_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_srvs_.insert(pair<PvcKey, FeatureResponse>(key, resp));
  } else {
    auto& resp = res_srvs_[key];
    for (s32 i = 0; i < resp.records_size(); ++i) {
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
      if (!new_rec.app_proto().empty()) rec->set_app_proto(new_rec.app_proto());
      if (!new_rec.srv_type().empty()) {
        rec->set_srv_type(new_rec.srv_type());
        rec->set_srv_name(new_rec.srv_name());
        rec->set_srv_version(new_rec.srv_version());
        rec->set_srv_time(new_rec.srv_time());
      }
      if (!new_rec.dev_type().empty()) {
        rec->set_dev_type(new_rec.dev_type());
        rec->set_dev_name(new_rec.dev_name());
        rec->set_dev_vendor(new_rec.dev_vendor());
        rec->set_dev_model(new_rec.dev_model());
        rec->set_dev_time(new_rec.dev_time());
      }
      if (!new_rec.os_type().empty()) {
        rec->set_os_type(new_rec.os_type());
        rec->set_os_name(new_rec.os_name());
        rec->set_os_version(new_rec.os_version());
        rec->set_os_time(new_rec.os_time());
      }
      if (!new_rec.midware_type().empty()) {
        rec->set_midware_type(new_rec.midware_type());
        rec->set_midware_name(new_rec.midware_name());
        rec->set_midware_version(new_rec.midware_version());
        rec->set_midware_time(new_rec.midware_time());
      }
      return;
		}
    auto rec = resp.add_records();
    *rec = new_rec;
    if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
  }
}

void AssetsrvFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void AssetsrvFilter::CheckServiceEvent(const Slice& key, const Slice& value,
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


void AssetsrvFilter::CheckService(const Slice& key, const Slice& value,
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
  rec.set_srv_type(stat.srv_type);
  rec.set_srv_name(stat.srv_name);
  rec.set_srv_version(stat.srv_version);
  rec.set_srv_time(stat.srv_time);
  rec.set_dev_type(stat.dev_type);
  rec.set_dev_name(stat.dev_name);
  rec.set_dev_vendor(stat.dev_vendor);
  rec.set_dev_model(stat.dev_model);
  rec.set_dev_time(stat.dev_time);
  rec.set_os_type(stat.os_type);
  rec.set_os_name(stat.os_name);
  rec.set_os_version(stat.os_version);
  rec.set_os_time(stat.os_time);
  rec.set_midware_type(stat.midware_type);
  rec.set_midware_name(stat.midware_name);
  rec.set_midware_version(stat.midware_version);
  rec.set_midware_time(stat.midware_time);
  if (pvckey.srv_mark)
    rec.set_srv_mark("res");
  else
    rec.set_srv_mark("req");

  if (DEBUG) log_info("Got Dos Record: %s\n", rec.DebugString().c_str());
	AddRecord(pvckey, rec);
}

///////////////////////////////////////////////////////////////////////
//AssetsrvFilter::EventGenerator
///////////////////////////////////////////////////////////////////////

void AssetsrvFilter::DivideMode() {
	Pattern pat;
	for (u32 i = 0; i < event_generators_.size(); ++i) {
		auto event_config = event_generators_[i].event_config;
		pat.flows = event_config.min();
  	pat.start_time = event_generators_[i].start_time;
  	pat.config_id = event_config.config_id();
  	pat.type_id = event_config.type_id();
  	if (event_config.has_max())
			pat.max = event_config.max();
		else
			pat.max = 0;

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

	if (!event_config.ip().empty() && event_config.has_port() && !event_config.protocol().empty()) {
    	pat.dip = event_config.ip();
    	pat.dport = to_string(event_config.port());
    	pat.protocol = event_config.protocol();
    	dip_dport_prot_.emplace(pat);
  	} else if (!event_config.ip().empty() && event_config.has_port() && event_config.protocol().empty()) {
    	pat.dip = event_config.ip();
    	pat.dport = to_string(event_config.port());
    	dip_dport_.emplace(pat);
  	} else if (!event_config.ip().empty() && !event_config.has_port() && !event_config.protocol().empty()) {
    	pat.dip = event_config.ip();
    	pat.protocol = event_config.protocol();
    	dip_prot_.emplace(pat);
  	} else if (event_config.ip().empty() && event_config.has_port() && !event_config.protocol().empty()) {
    	pat.dport = to_string(event_config.port());
    	pat.protocol = event_config.protocol();
    	dport_prot_.emplace(pat);
  	} else if (!event_config.ip().empty() && !event_config.has_port() && event_config.protocol().empty()) {
   		pat.dip = event_config.ip();
    	dip_.emplace(pat);
  	} else if (event_config.ip().empty() && event_config.has_port() && event_config.protocol().empty()) {
    	pat.dport = to_string(event_config.port());
    	dport_.emplace(pat);
  	} else if (event_config.ip().empty() && !event_config.has_port() && !event_config.protocol().empty()) {
    	pat.protocol = event_config.protocol();
    	prot_.emplace(pat);
  	} else {
    	min_.emplace(pat);
 	 	}
	}
  event_models.push_back(dip_dport_prot_);
  event_models.push_back(dip_dport_);
  event_models.push_back(dip_prot_);
  event_models.push_back(dport_prot_);
  event_models.push_back(dip_);
  event_models.push_back(dport_);
  event_models.push_back(prot_);
  event_models.push_back(min_);
}


AssetsrvFilter::EventGenerator::EventGenerator(
		const config::Event& e, u32 devid, u32 st, u32 et)
		: event_config(e), dev_id(devid), start_time(st), end_time(et) {
	if (DEBUG) log_info("EventGenerator initialized.\n");
}

void AssetsrvFilter::Generate(const PvcKey& s, const PortStat& p, GenEventRes* events, Pattern& pat) {
	if (common_model_filter::filter_time_range(pat)) {
  	auto e = events->add_records();
  	e->set_time(pat.start_time);
  	e->set_type_id(pat.type_id);
  	e->set_config_id(pat.config_id);
  	e->set_devid(dev_id_);
    if (model_ == "V6") {
      struct in6_addr ip6;
      std::copy(s.ip, s.ip+4, ip6.s6_addr32);
      e->set_obj(":>[" + ipnum_to_ipstr_v6(ip6) + "]:" + to_string(s.port) + " " +
                proto_to_string(s.proto) + " ");
    } else
  	  e->set_obj(":>" + ipnum_to_ipstr(s.ip[0]) + ":" + to_string(s.port) + " " +
                proto_to_string(s.proto) + " ");
  	e->set_thres_value(pat.flows);
  	e->set_alarm_value(p.flow_count);
    e->set_value_type("flow_count");
    e->set_model_id(0);
    //生成事件特征数据，即事件五元组详细信息
    GenEventFeature(s, e);
  	if (DEBUG) log_info("Generated assetsrv event: %s\n", e->DebugString().c_str());
	}
}

void AssetsrvFilter::GenEventFeature(const PvcKey& s, const event::GenEventRecord* e) {
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

void AssetsrvFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p))); 
}

Match_res* AssetsrvFilter::Pickout(const PvcKey& s, const PortStat& p, 
                                struct Match_res& result, vector<set<Pattern>>& models) {
  set<Pattern> dip_dport_prot_ = models[0];
  set<Pattern> dip_dport_ = models[1];
  set<Pattern> dip_prot_ = models[2];
  set<Pattern> dport_prot_ = models[3];
  set<Pattern> dip_ = models[4];
  set<Pattern> dport_ = models[5];
  set<Pattern> prot_ = models[6];
  set<Pattern> min_ = models[7];

  string ipstr;
  if (model_ == "V6") {
    struct in6_addr ip6;
    std::copy(s.ip, s.ip+4, ip6.s6_addr32);
    ipstr = ipnum_to_ipstr_v6(ip6);
  } else
    ipstr = ipnum_to_ipstr(s.ip[0]);

  string proto = proto_to_string(s.proto);
  string app_proto = p.app_proto;
  for (auto a : dip_dport_prot_) {
    bool res;
    if (model_ == "V6")
      res = valid_ip_v6(ipstr, a.dip);
    else
      res = valid_ip(ipstr, a.dip);
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

void AssetsrvFilter::GenerateEvents(
    const PvcKey& s, const PortStat& p, GenEventRes* events) {
  struct Match_res result;
  auto res = Pickout(s, p, result, event_models);
  if (res && res->res && (res->pat.max == 0 || p.flow_count < res->pat.max)) {
    Generate(s, p, events, res->pat);
  }
  return;
}

void AssetsrvFilter::GenerateFeature(const PvcKey& s, const PortStat& p) {
  struct Match_res result;
  auto res = Pickout(s, p, result, feature_models);
  if (res && res->res) {
    InsertSrvToTSDB(s, p);
  }
  return;
}
