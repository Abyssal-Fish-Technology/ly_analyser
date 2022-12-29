#include "dga_filter.h"
#include "../../common/ip.h"
#include "../../common/asset.h"
#include "../../common/md5.h"
#include "../../common/log.h"
#include "../../common/file.h"
#include "../../common/strings.h"
#include "../../common/datetime.h"
#include "../../common/common_filter.hpp"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include <utility>

#define SPECICAL_CHARACTOR_PATTERN "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\\.?$"

static std::map<char, int> letter_map = {{'-', 2}, {'_', 3}, {'.', 4}, {'0', 5}, {'1', 6}, {'2', 7}, {'3', 8}, {'4', 9}, {'5', 10}, {'6', 11},
       {'7', 12}, {'8', 13}, {'9', 14}, {'a', 15}, {'b', 16}, {'c', 17}, {'d', 18}, {'e', 19}, {'f', 20}, {'g', 21}, {'h', 22}, {'i', 23},
       {'j', 24}, {'k', 25}, {'l', 26}, {'m', 27}, {'n', 28}, {'o', 29}, {'p', 30}, {'q', 31}, {'r', 32}, {'s', 33}, {'t', 34}, {'u', 35},
       {'v', 36}, {'w', 37}, {'x', 38}, {'y', 39}, {'z', 40}};


DgaFilter::DgaFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}


DgaFilter* DgaFilter::Create(u32 dev_id, const string& model, DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new DgaFilter(dev_id, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_dga"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_dga"));

  LoadLineFromFile("/Agent/data/dga_white", filter->not_tld_); 
  if (DEBUG) log_info("Dga filter initialized.\n");

  return filter;
}


bool DgaFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot != 17) continue;
    string qname = r.qname;
    if (!JudgeSpecChar(qname)) continue;
    if (qname.size() == 0) continue;
    if (not_tld_.count(qname) != 0) continue; //白名单过滤
    string tmp_str;
    if (qname[qname.size()-1] == '.')
      tmp_str = qname.substr(0, qname.size()-1);
    else
      tmp_str = qname;

    auto pos = tmp_str.rfind(".");
    if (pos != tmp_str.npos) {
     auto top = tmp_str.substr(pos+1);
     if (not_tld_.count(top) != 0) continue;
    }
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    if ((qname.size()>0) && (r.tos & 0x01 )) {
      UpdateDga(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.qname, r.dPkts, r.dOctets);
    }
  }
  return true;
}

bool DgaFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.prot != 17) continue;
    string qname = r.qname;
    if (!JudgeSpecChar(qname)) continue;
    if (qname.size() == 0) continue;
    if (not_tld_.count(qname) != 0) continue;
    string tmp_str;
    if (qname[qname.size()-1] == '.')
      tmp_str = qname.substr(0, qname.size()-1);
    else
      tmp_str = qname;

    auto pos = tmp_str.rfind(".");
    if (pos != tmp_str.npos) {
     auto top = tmp_str.substr(pos+1);
     if (not_tld_. count(top) != 0) continue;
    }
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
 
    if ((qname.size()>0) && (r.tos & 0x01 )) {
      UpdateDga(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, r.qname, r.dPkts, r.dOctets);
    }
  }
  return true;
}


bool DgaFilter::JudgeSpecChar(const string& str) {
  regex pattern(SPECICAL_CHARACTOR_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(str, m, pattern);
}

void DgaFilter::UpdateDga(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto, 
                          char *qname, u64 pkts, u64 bytes) {

  DgaKey dga;
  string domain = qname;
  domains_[domain] = 0;
  
  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;
  memcpy(event.domain, qname, strlen(qname)+1);
 
  memset(&dga, 0, sizeof(struct DgaKey));
  std::copy(sip, sip+4, dga.sip);
  std::copy(dip, dip+4, dga.dip);
  memcpy(dga.qname, qname, strlen(qname) + 1);

  auto it = dga_.find(dga);
  if (it == dga_.end()) {
    DgaStat p;
    memset(&p, 0, sizeof(struct DgaStat));
    p.first = first;
    p.last = last;
    p.flows = 1;
    p.pkts = pkts;
    p.bytes = bytes;
    dga_[dga] = p;

    //五元组统计信息
    EventValue ep;
    ep.first = first;
    ep.last = last;
    ep.flows = 1;
    ep.pkts = pkts;
    ep.bytes = bytes;
    map<EventKey, EventValue> event_tmp;
    event_tmp[event] = ep;
    event_details_[dga] = event_tmp;
  } else {
    auto& p = it->second;
    p.first = MIN(p.first, first);
    p.last = MAX(p.last, last);
    ++p.flows;
    p.pkts += pkts;
    p.bytes += bytes;

    //五元组统计信息
    auto itr = event_details_[dga].find(event);
    if (itr == event_details_[dga].end()) {
      EventValue p;
      p.first = first;
      p.last = last;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      event_details_[dga][event] = p;
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

tensorflow::Tensor DgaFilter::Domain2Tensor(const vector<string>& domains) {
  long long int s = domains.size();
  tensorflow::Tensor index(DT_INT32, tensorflow::TensorShape({s, 128}));
  auto input_mapped = index.tensor<int, 2>();

  for (int i = 0; i < s; ++i) {
    auto domain = domains[i];
    vector<int> all_vec;
    for (auto& ch : domain) {
      if (!letter_map.count(ch))
        all_vec.push_back(1);
      else
        all_vec.push_back(letter_map[ch]);
    }
    auto tmp = all_vec.size();
    if (tmp < 128) {
      for (u32 m = 0; m < 128-tmp; ++m)
        all_vec.push_back(0);
    }
    for(int j=0;j<128;j++){
      input_mapped(i,j) =all_vec[j];
    }
  }

  //tensorflow::Tensor index(DT_INT32, tensorflow::TensorShape({1, 128}));
  //std::copy_n(all_vec.begin(), all_vec.size(), index.flat<int>().data());

  return index;
}

bool DgaFilter::IsDgaDomain() {
  vector<string> domain_list;
  for (auto& ti : domains_) {
    domain_list.push_back(ti.first);
  }
  std::vector<tensorflow::Tensor> outputs;
  auto img = Domain2Tensor(domain_list);
  std::vector<std::pair<string, tensorflow::Tensor> > inputs = {{"domain:0", img}};

  auto status = session_->Run(inputs, {"Identity:0"}, {}, &outputs);
  if (!status.ok()) {
    log_err("error: %s\n", status.ToString().c_str());
    return false;
  }

  for (u32 i = 0; i < domain_list.size(); ++i) {
    auto s = domain_list[i];
    domains_[s] = outputs[0].matrix<float>()(i) * 100;
  }

  return true;
}
  
bool DgaFilter::CreateSession() {
  //创建tensorflow运行环境
  //创建session
  session_ = std::unique_ptr<tensorflow::Session>(tensorflow::NewSession(SessionOptions()));
  //  将pb原始模型导入到GraphDef中
  GraphDef graph_def;
  std::string graph_path = "/Agent/data/models/dga_model.pb";
  auto status = ReadBinaryProto(Env::Default(), graph_path, &graph_def);
  if (!status.ok()) {
    log_err("error: %s\n", status.ToString().c_str());
    return false;
  }
  //将原始模型加载到session中
  status = session_->Create(graph_def);
  if (!status.ok()) {
    log_err("error: %s\n", status.ToString().c_str());
    return false;
  } 

  return true;
}

event::GenEventRes DgaFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<DgaFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);

  GenEventRes events;

  if (!ptr->CreateSession()) return events;  //创建tensorflow运行环境加载pb模型

  //计算每个域名通过模型算出的数值
  if (!ptr->IsDgaDomain()) return events;
  
  for (auto it = ptr->dga_.begin(); it != ptr->dga_.end();) {
    auto& s = it->first;
    auto& p = it->second;
  
    bool is_dga = false;
    for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
      auto event_config = ptr->event_generators_[i].event_config;
      //判断是不是dga域名
      is_dga = ptr->domains_[s.qname] > event_config.min() ? true : false;
      if (is_dga) {
        p.score = ptr->domains_[s.qname];
        if (event_config.has_sip() && !event_config.sip().empty()) {
          if (model == "V6") {
            struct in6_addr sip6;
            std::copy(s.sip, s.sip+4, sip6.s6_addr32);
            if (!valid_ip_v6(event_config.sip(), ipnum_to_ipstr_v6(sip6))) {
              continue;
            }
          } else {
            if (!valid_ip(event_config.sip(), ipnum_to_ipstr(s.sip[0]))) {
              continue;
            }
          }
        }

        if (event_config.has_dip() && !event_config.dip().empty()) {
          if (model == "V6") {
            struct in6_addr dip6;
            std::copy(s.dip, s.dip+4, dip6.s6_addr32);
            if (!valid_ip_v6(event_config.dip(), ipnum_to_ipstr_v6(dip6))) {
              continue;
            }
          } else {
            if (!valid_ip(event_config.sip(), ipnum_to_ipstr(s.dip[0]))) {
              continue;
            }
          }
        }
           
        EventSumKey k;
        std::copy(s.sip, s.sip+4, k.sip);
        std::copy(s.dip, s.dip+4, k.dip);
        k.index = i;       //匹配的配置的下标
        auto it = ptr->all_events_.find(k);
        if (it == ptr->all_events_.end()) {
          EventValue ep;
          ep.first = p.first;
          ep.last = p.last;
          ep.flows = p.flows;
          ep.pkts = p.pkts;
          ep.bytes = p.bytes;
          ep.score = p.score;
          ep.dga_cnt = 1;
          ptr->all_events_[k] = ep; 
        } else {
          auto& ep = it->second;
          ep.first = MIN(ep.first, p.first);
          ep.last = MAX(ep.last, p.last);
          ep.flows++;
          ep.pkts += p.pkts;
          ep.bytes += p.bytes;
          ep.score = p.score;
          ep.dga_cnt++; //同一sip、dip下不同dga域名的数量
        }
        break;
      }
    }  //end for config
    if (!is_dga) {
      auto k = it->first;
      ptr->event_details_.erase(k);
      ptr->dga_.erase(it++);
    } else {
      ptr->InsertDgaToTSDB(s, p);
      ++it;
    }
  }
 
  for (auto it = ptr->all_events_.begin(); it != ptr->all_events_.end(); ++it) {
    ptr->GenerateEvents(it->first, it->second, &events);
  }
  return events;
}

void DgaFilter::InsertDgaToTSDB(const DgaKey& s, const DgaStat& stat) {
  DgaStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(DgaStat))) {
    auto* old_stat = (DgaStat*)old_value.data();
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

void DgaFilter::FilterDga(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckDga(key, value, req);
    });
  
  for (auto it = res_dga_.begin(); it != res_dga_.end(); ++it)
    resp->MergeFrom(it->second);
}

void DgaFilter::FilterDgaEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckDgaEvent(key, value, req, resp);
    });
}

void DgaFilter::AddRecord(const DgaKey& key, const FeatureRecord& new_rec) {
  auto it = res_dga_.find(key);
  if (it == res_dga_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_dga_[key] = resp;
  } else {
    auto& resp = res_dga_[key];
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

void DgaFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}


void DgaFilter::CheckDgaEvent(const Slice& key, const Slice& value,
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
  rec.set_domain(pvckey.domain);
  rec.set_obj(pvckey.obj);
  rec.set_type(pvckey.type);
  rec.set_model(pvckey.model);
  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);

  if (DEBUG) log_info("Got Dos Record: %s\n", rec.DebugString().c_str());
  AddEventRecord(rec, resp);
}

void DgaFilter::CheckDga(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const DgaKey& dgakey = *(const DgaKey*)key.data();
  const DgaStat& stat = *(const DgaStat*)value.data();

  if (stat.first <= req.starttime() || stat.first >= req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(dgakey.sip, dgakey.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(dgakey.dip, dgakey.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(dgakey.sip[0]);
    dip = ipnum_to_ipstr(dgakey.dip[0]);
  }
    
  if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
  if (req.has_sip() && req.sip() != sip) return;
  if (req.has_dip() && req.dip() != dip) return;
  if (req.has_qname() && req.qname() != dgakey.qname) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_qname(dgakey.qname);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);

  if (DEBUG) log_info("Got Dga Record: %s\n", rec.DebugString().c_str());
  AddRecord(dgakey, rec);
}

//////////////////////////////////////////////////////////////////
/* Generate events */

DgaFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et) 
  : event_config(e), dev_id(devid), start_time(st), end_time(et) {
  
  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void DgaFilter::GenerateEvents(const EventSumKey& s, const EventValue& p, GenEventRes* events) {
  auto gen = event_generators_[s.index];
  auto event_config = gen.event_config;
  if (common_filter::filter_time_range(gen.start_time, event_config) && p.dga_cnt > event_config.qcount()) {
    auto e = events->add_records(); 
    e->set_time(gen.start_time);
    e->set_type_id(event_config.type_id());
    e->set_config_id(event_config.config_id());
    e->set_devid(gen.dev_id);
    if (model_ == "V6") {
      struct in6_addr sip6, dip6;
      std::copy(s.sip, s.sip+4, sip6.s6_addr32);
      std::copy(s.dip, s.dip+4, dip6.s6_addr32);
      e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]: " + " ");      
    } else
      e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>"+ ipnum_to_ipstr(s.dip[0]) + ": " + " ");  
    e->set_thres_value(event_config.min());
    e->set_alarm_value(p.score);
    e->set_value_type(event_config.data_type());
    e->set_model_id(1);
    
    //生成事件特征数据，即事件五元组详细信息
    GenEventFeature(s, e); 
  }
}

void DgaFilter::GenEventFeature(const EventSumKey& s, const event::GenEventRecord* e) {
  for (auto kv : event_details_) {
    auto k = kv.first;

    if (k.sip[0] != s.sip[0] || k.sip[1] != s.sip[1] || k.sip[2] != s.sip[2] || k.sip[3] != s.sip[3]) continue;
    if (k.dip[0] != s.dip[0] || k.dip[1] != s.dip[1] || k.dip[2] != s.dip[2] || k.dip[3] != s.dip[3]) continue;

    for (auto it : kv.second) {
      auto k = it.first;
      auto v = it.second;
      k.time = e->time();
      k.type = e->type_id();
      k.model = e->model_id();
      memcpy(k.obj, e->obj().c_str(), e->obj().size()+1);
      InsertEventToTSDB(k, v); 
    }   
  }
}

void DgaFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}
