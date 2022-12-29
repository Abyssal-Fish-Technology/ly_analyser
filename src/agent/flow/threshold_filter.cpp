#include "threshold_filter.h"
#include "../../common/common.h"
#include "../dump/libnfdump.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/ip.h"
#include "../../common/common_filter.hpp"


// These are used for Event::data_type.
static char kBPS[] = "bps";
static char kPPS[] = "pps";
static char kFPS[] = "sps";

ThresholdFilter::ThresholdFilter(
    const Event& event_config, u32 dev_id, const string& model, u32 start_time, u32 end_time,
    unique_ptr<MOFilter> mo_filter)
  : event_config_(event_config),
    dev_id_(dev_id),
    model_(model),
    start_time_(start_time),
    end_time_(end_time),
    bytes_(0),
    pkts_(0),
    flows_(0),
    mo_filter_(std::move(mo_filter)) {}

ThresholdFilter* ThresholdFilter::Create(
    CachedConfig* config, const Event& event_config, u32 dev_id, const string& model, u32 start_time,
    u32 end_time, DBBuilder* event_builder) {
  unique_ptr<MOFilter> mo_filter;
  if (event_config.has_moid()) {
    mo_filter.reset(
      MOFilter::Create(
        config, dev_id, to_string(event_config.moid()),
        event_config.grep_rule()));
    if (!mo_filter) return nullptr;
  }


  unique_ptr<ThresholdFilter> filter(new ThresholdFilter(
      event_config, dev_id, model, start_time, end_time, std::move(mo_filter)));
  if (DEBUG) log_info("FixedThreshold filter initialized for update.\n");
  
  if (filter->mo_filter_) {
    for (s32 i = 0; i < filter->mo_filter_->config_->config().mo_size(); i++) {
      if (filter->mo_filter_->config_->config().mo(i).id() == filter->event_config_.moid()) {
        filter->direction_ = filter->mo_filter_->config_->config().mo(i).direction();
        break;
      }
    }
  }

  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_mo"));
  
  return filter.release();
}
    
bool ThresholdFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  if (model_ == "V6") {
    for(auto it = flowset->begin(); it != flowset->end(); it++) {
      UpdateThresholdV6(&*it);
    }
  } else {
    for(auto it = flowset->begin(); it != flowset->end(); it++) {
      UpdateThreshold(&*it);
    }
  }
  return true;
}

bool ThresholdFilter::UpdateThreshold(FlowPtr flow) {
  auto r = (master_record_t*)flow;
  u32 sip = r->v4.srcaddr;
  u32 dip = r->v4.dstaddr;
  u16 sport = r->srcport;
  u16 dport = r->dstport;
  u64 pkts = r->dPkts;
  u64 bytes = r->dOctets;
  u16 proto = r->prot;
  u32 first = r->first;
  u32 last = r->last;

  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  event.sip[0] = sip;
  event.sport = sport;
  event.dip[0] = dip;
  event.dport = dport;
  event.proto = proto;

  bool match = mo_filter_ && mo_filter_->CheckFlow(flow);
  if (match) {
    if (direction_ == "IN") {
      TiKey k;
      k.lip[0] = sip;
      k.tip[0] = dip;
      k.tport = dport;
      k.proto = proto;
      auto it = tis_.find(k);
      if (it == tis_.end()) {
        TiStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        tis_[k] = p;

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
        p.flows++;
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
    if (direction_ == "OUT") {
      TiKey k;
      k.lip[0] = dip;
      k.tip[0] = sip;
      k.tport = sport;
      k.proto = proto;

      auto it = tis_.find(k);
      if (it == tis_.end()) {
        TiStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        tis_[k] = p;

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
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;

        //五元组统计信息
        auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.last = last;
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
    if (direction_ == "ALL") 
      return true;
  }
  return true;
}

bool ThresholdFilter::UpdateThresholdV6(FlowPtr flow) {
  auto r = (master_record_t*)flow;
  if (r->prot == 6 && (r->tos & 0x01) != 0x01) return false;   //tcp对外请求，识别发起动作
  
  uint32_t sip[4], dip[4];
  memset(sip, 0, sizeof(uint)*4);
  memset(dip, 0, sizeof(uint)*4);
  sip[0] = ( r->v6.srcaddr[0] >> 32 ) & 0xffffffffLL;
  sip[1] = r->v6.srcaddr[0] & 0xffffffffLL;
  sip[2] = ( r->v6.srcaddr[1] >> 32 ) & 0xffffffffLL;
  sip[3] = r->v6.srcaddr[1] & 0xffffffffLL;
  dip[0] = ( r->v6.dstaddr[0] >> 32 ) & 0xffffffffLL;
  dip[1] = r->v6.dstaddr[0] & 0xffffffffLL;
  dip[2] = ( r->v6.dstaddr[1] >> 32 ) & 0xffffffffLL;
  dip[3] = r->v6.dstaddr[1] & 0xffffffffLL;

  u16 sport = r->srcport;
  u16 dport = r->dstport;
  u64 pkts = r->dPkts;
  u64 bytes = r->dOctets;
  u16 proto = r->prot;
  u32 first = r->first;
  u32 last = r->last;

  //
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;

  bool match = mo_filter_ && mo_filter_->CheckFlow(flow);
  if (match) {
    if (direction_ == "IN") {
      TiKey k;
      std::copy(sip, sip+4, k.tip);
      std::copy(dip, dip+4, k.lip);
      k.tport = dport;
      k.proto = proto;
      auto it = tis_.find(k);
      if (it == tis_.end()) {
        TiStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        tis_[k] = p;

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
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes; 

        //五元组统计信息
        auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.last = last;
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
    if (direction_ == "OUT") {
      TiKey k;
      std::copy(dip, dip+4, k.tip);
      std::copy(sip, sip+4, k.lip);
      k.tport = sport;
      k.proto = proto;

      auto it = tis_.find(k);
      if (it == tis_.end()) {
        TiStat p;
        p.first = first;
        p.last = last;
        p.flows = 1;
        p.pkts = pkts;
        p.bytes = bytes;
        tis_[k] = p;

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
        p.flows++;
        p.pkts += pkts;
        p.bytes += bytes;

        //五元组统计信息
        auto itr = event_details_[k].find(event);
        if (itr == event_details_[k].end()) {
          EventValue p;
          p.first = first;
          p.last = last;
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
    if (direction_ == "ALL") 
      return true;
  }
  return true;
}
event::GenEventRes ThresholdFilter::CheckThreshold(std::vector<master_record_t>* flowset, unique_ptr<ThresholdFilter>& ptr, const string& model) {
  ptr->UpdateByFlow(flowset);
  event::GenEventRes events;
  u32 interval = ptr->end_time_ - ptr->start_time_;
  if (interval == 0) {
    log_err("Could not check threshold. Start time equals end time.\n");
    return events;
  }

  double bps = 0, pps = 0, fps = 0;
  const string& data_type = ptr->event_config_.data_type();
  for (auto it = ptr->tis_.begin(); it != ptr->tis_.end(); it++) {
    auto& s = it->first;
    auto& p = it->second;
    if (ptr->event_config_.thres_type() == "abs") {
      bps = double(p.bytes) / interval;
      pps = double(p.pkts) / interval;
      fps = double(p.flows) / interval;
    } else {
      log_err("thres_type not supported:%s.\n", ptr->event_config_.thres_type().c_str());
      break;
    }
    
    double value = 0;
    if (data_type == kBPS) {
      value = bps;
    } else if (data_type == kPPS) {
      value = pps;
    } else if (data_type == kFPS) {
      value = fps;
    } else {
      log_err("data_type not supported:%s.\n",
              ptr->event_config_.data_type().c_str());
      break;
    }
    double thres_value = 0;
    if (!ptr->ExceedThreshold(value, &thres_value) || !common_filter::filter_time_range(ptr->start_time_, ptr->event_config_)) {
      // Do not generate event.
      continue;
    }
    
    auto e = events.add_records();;
    e->set_time(ptr->start_time_);
    e->set_type_id(ptr->event_config_.type_id());
    e->set_config_id(ptr->event_config_.config_id());
    e->set_devid(ptr->dev_id_);
    if (model == "V6") {
      struct in6_addr sip6, dip6;
      std::copy(s.lip, s.lip+4, sip6.s6_addr32);
      std::copy(s.tip, s.tip+4, dip6.s6_addr32);
      e->set_obj("[" + ipnum_to_ipstr_v6(dip6) + "]:" + to_string(s.tport) + ">[" + ipnum_to_ipstr_v6(sip6) + "]: " + 
                  proto_to_string(s.proto) + " " + to_string(ptr->event_config_.moid())); 
    } else
      e->set_obj(ipnum_to_ipstr(s.tip[0]) + ":" + to_string(s.tport) + ">" + ipnum_to_ipstr(s.lip[0]) + 
              ": " + proto_to_string(s.proto) + " " + to_string(ptr->event_config_.moid()));
    e->set_thres_value(thres_value);
    e->set_alarm_value(value);
    e->set_value_type(data_type);
    e->set_model_id(3);
    
    //生成事件特征数据，即事件五元组详细信息
    ptr->GenEventFeature(s, e);
  }

  return events;
}

void ThresholdFilter::GenEventFeature(const TiKey& s, const event::GenEventRecord* e) {
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

void ThresholdFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}

bool ThresholdFilter::ExceedThreshold(double value, double* thres_value) {
  bool exceed = false;
  if (event_config_.has_max() && value >= event_config_.max()) {
    exceed = true;
    if (thres_value) *thres_value = event_config_.max();
  } else if (event_config_.has_min() && value >= event_config_.min()) {
    exceed = true;
    if (thres_value) *thres_value = event_config_.min();
  }
  return exceed;
} 
 
void ThresholdFilter::CheckMoEvent(const Slice& key, const Slice& value,
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

void ThresholdFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void ThresholdFilter::FilterMoEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckMoEvent(key, value, req, resp);
    });
}
