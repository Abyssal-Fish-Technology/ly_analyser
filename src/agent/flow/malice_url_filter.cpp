#include "MaliceUrlFilter.h"

#include "../../common/common.h"
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

static std::map<char, int> letter_map = {{'0', 2}, {'1', 3}, {'2', 4}, {'3', 5}, {'4', 6}, {'5', 7}, {'6', 8}, {'7', 9}, {'8', 10}, {'9', 11}, {'a', 12}, {'b', 13}, {'c', 14}, {'d', 15}, {'e', 16}, {'f', 17}, {'g', 18}, {'h', 19}, {'i', 20}, {'j', 21}, {'k', 22}, {'l', 23}, {'m', 24}, {'n', 25}, {'o', 26}, {'p', 27}, {'q', 28}, {'r', 29}, {'s', 30}, {'t', 31}, {'u', 32}, {'v', 33}, {'w', 34}, {'x', 35}, {'y', 36}, {'z', 37}, {'A', 38}, {'B', 39}, {'C', 40}, {'D', 41}, {'E', 42}, {'F', 43}, {'G', 44}, {'H', 45}, {'I', 46}, {'J', 47}, {'K', 48}, {'L', 49}, {'M', 50}, {'N', 51}, {'O', 52}, {'P', 53}, {'Q', 54}, {'R', 55}, {'S', 56}, {'T', 57}, {'U', 58}, {'V', 59}, {'W', 60}, {'X', 61}, {'Y', 62}, {'Z', 63}, {'!', 64}, {'"', 65}, {'#', 66}, {'$', 67}, {'%', 68}, {'&', 69}, {'\'', 70}, {'(', 71}, {')', 72}, {'*', 73}, {'+', 74}, {',', 75}, {'-', 76}, {'.', 77}, {'/', 78}, {',', 79}, {';', 80}, {'<', 81}, {'=', 82}, {'>', 83}, {'?', 84}, {'@', 85}, {'[', 86}, {'\\', 87}, {']', 88}, {'^', 89}, {'_', 90}, {'`', 91}, {'{', 92}, {'|', 93}, {'}', 94}, {'~', 95}};

MaliceUrlFilter::MaliceUrlFilter(u32 dev_id, const string& model)
  : FlowFilter(), dev_id_(dev_id), model_(model) {}

MaliceUrlFilter* MaliceUrlFilter::Create(u32 dev_id, const string& model, DBBuilder* builder, DBBuilder* event_builder) {
  auto* filter = new MaliceUrlFilter(dev_id, model);
  if (builder)
    filter->tsdb_.reset(new TSDB(builder, to_string(dev_id) + "_feature_malice_url"));
  if (event_builder)
    filter->event_tsdb_.reset(new TSDB(event_builder, to_string(dev_id) + "_event_malice_url"));

  //LoadLineFromFile("/Agent/data/url_white", filter->not_tld_);
  if (DEBUG) log_info("malice url filter initialized.\n");

  return filter;
}

bool MaliceUrlFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    string url = r.http_url;
    if (url.size() == 0) continue;
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    if ((url.size()>0) && (r.tos & 0x01 )) {
      UpdateMaliceUrl(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, url, r.dPkts, r.dOctets);
    }
  }
  return true;
}

bool MaliceUrlFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    string url = r.http_url;
    if (url.size() == 0) continue;
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

    if ((url.size()>0) && (r.tos & 0x01 )) {
      UpdateMaliceUrl(r.first, r.last, sip, r.srcport, dip, r.dstport, r.prot, url, r.dPkts, r.dOctets);
    }
  }
  return true;
}

void MaliceUrlFilter::UpdateMaliceUrl(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[], u16 dport, u16 proto,
                          const string& url, u64 pkts, u64 bytes) {

  url_score_[url] = 0;

  //事件五元组信息
  EventKey event;
  memset(&event, 0, sizeof(struct EventKey));
  std::copy(sip, sip+4, event.sip);
  event.sport = sport;
  std::copy(dip, dip+4, event.dip);
  event.dport = dport;
  event.proto = proto;
  memcpy(event.url, url.c_str(), url.size()+1);

  MaliceUrlKey eachUrl;
  memset(&eachUrl, 0, sizeof(struct MaliceUrlKey));
  std::copy(sip, sip+4, eachUrl.sip);
  std::copy(dip, dip+4, eachUrl.dip);
  eachUrl.dport = dport;
  memcpy(eachUrl.url, url, url.size() + 1);

  auto it = url_.find(eachUrl);
  if (it == url_.end()) {
    MaliceUrlStat p;
    memset(&p, 0, sizeof(struct MaliceUrlStat));
    p.first = first;
    p.last = last;
    p.flows = 1;
    p.pkts = pkts;
    p.bytes = bytes;
    url_[eachUrl] = p;

    //五元组统计信息
    EventValue ep;
    ep.first = first;
    ep.last = last;
    ep.flows = 1;
    ep.pkts = pkts;
    ep.bytes = bytes;
    map<EventKey, EventValue> event_tmp;
    event_tmp[event] = ep;
    event_details_[eachUrl] = event_tmp;
  } else {
    auto& p = it->second;
    p.first = MIN(p.first, first);
    p.last = MAX(p.last, last);
    ++p.flows;
    p.pkts += pkts;
    p.bytes += bytes;

    //五元组统计信息
    auto itr = event_details_[eachUrl].find(event);
    if (itr == event_details_[eachUrl].end()) {
      EventValue p;
      p.first = first;
      p.last = last;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      event_details_[eachUrl][event] = p;
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

tensorflow::Tensor MaliceUrlFilter::Url2Tensor(const vector<string>& urls) {
  long long int s = urls.size();
  tensorflow::Tensor index(DT_INT32, tensorflow::TensorShape({s, 256}));
  auto input_mapped = index.tensor<int, 2>();

  for (int i = 0; i < s; ++i) {
    auto url = urls[i];
    vector<int> all_vec;
    for (auto& ch : url) {
      if (!letter_map.count(ch))
        all_vec.push_back(1);
      else
        all_vec.push_back(letter_map[ch]);
    }
    auto tmp = all_vec.size();
    if (tmp < 256) {
      for (u32 m = 0; m < 256-tmp; ++m)
        all_vec.push_back(0);
    }
    for(int j=0;j<256;j++){
      input_mapped(i,j) =all_vec[j];
    }
  }

  return index;
}

void MaliceUrlFilter::IsMaliceUrl() {
  vector<string> url_list;
  for (auto& ti : url_score_) {
    url_list.push_back(ti.first);
  }
  std::vector<tensorflow::Tensor> outputs;
  auto img = Url2Tensor(url_list);
  std::vector<std::pair<string, tensorflow::Tensor> > inputs = {{"domain:0", img}};

  auto status = session_->Run(inputs, {"Identity:0"}, {}, &outputs);
  if (!status.ok()) {
    log_err("error: %s\n", status.ToString().c_str());
    return;
  }

  for (u32 i = 0; i < url_list.size(); ++i) {
    auto s = url_list[i];
    url_score_[s] = outputs[0].matrix<float>()(i) * 100;
  }
}

void MaliceUrlFilter::CreateSession() {
  //创建tensorflow运行环境
  //创建session
  session_ = std::unique_ptr<tensorflow::Session>(tensorflow::NewSession(SessionOptions()));
  //  将pb原始模型导入到GraphDef中
  GraphDef graph_def;
  std::string graph_path = "/Agent/data/models/url_model.pb";
  auto status = ReadBinaryProto(Env::Default(), graph_path, &graph_def);
  if (!status.ok()) {
    log_err("error: %s\n", status.ToString().c_str());
    return;
  }
  //将原始模型加载到session中
  status = session_->Create(graph_def);
  if (!status.ok()) {
    log_err("error: %s\n", status.ToString().c_str());
    return;
  }
}

event::GenEventRes MaliceUrlFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<MaliceUrlFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);

  GenEventRes events;

  ptr->CreateSession();  //创建tensorflow运行环境
  //计算每个url通过模型算出的数值
  ptr->IsMaliceUrl();

  for (auto it = ptr->url_.begin(); it != ptr->url_.end();) {
    auto& s = it->first;
    auto& p = it->second;

    //bool is_malice_url = false;
    for (u32 i = 0; i < ptr->event_generators_.size(); ++i) {
      auto event_config = ptr->event_generators_[i].event_config;
      //判断是不是恶意url
      is_dga = ptr->url_score_[s.url] > event_config.min() ? true : false;
      if (is_dga) {
        p.score = ptr->url_score_[s.url];
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

        /*EventSumKey k;
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
          ep.url_cnt = 1;
          ptr->all_events_[k] = ep;
        } else {
          auto& ep = it->second;
          ep.first = MIN(ep.first, p.first);
          ep.last = MAX(ep.last, p.last);
          ep.flows++;
          ep.pkts += p.pkts;
          ep.bytes += p.bytes;
          ep.score = p.score;
        }*/
        ptr->GenerateEvents(s, p, &events);
        break;
      }
    }  //end for config
    /*if (!is_malice_url) {
      auto k = it->first;
      ptr->event_details_.erase(k);
      ptr->url_.erase(it++);
    } else {
      ptr->InsertMaliceUrlToTSDB(s, p);
      ++it;
    }*/
  }
  
  /*for (auto it = ptr->all_events_.begin(); it != ptr->all_events_.end(); ++it) {
    ptr->GenerateEvents(it->first, it->second, &events);
  }*/
  return events;
}


void MaliceUrlFilter::InsertMaliceUrlToTSDB(const MaliceUrlKey& s, const MaliceUrlStat& stat) {
  MaliceUrlStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(MaliceUrlStat))) {
    auto* old_stat = (MaliceUrlStat*)old_value.data();
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

void MaliceUrlFilter::FilterMaliceUrl(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckMaliceUrl(key, value, req);
    });

  for (auto it = res_url_.begin(); it != res_url_.end(); ++it)
    resp->MergeFrom(it->second);
}

void MaliceUrlFilter::FilterMaliceUrlEvent(const eventfeature::EventFeatureReq& req, eventfeature::EventFeatureResponse* resp) {
  event_tsdb_->Scan(req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckMaliceUrlEvent(key, value, req, resp);
    });
}

void MaliceUrlFilter::AddRecord(const MaliceUrlKey& key, const FeatureRecord& new_rec) {
  auto it = res_url_.find(key);
  if (it == res_url_.end()) {
    FeatureResponse resp;
    auto rec = resp.add_records();
    *rec = new_rec;
    res_url_[key] = resp;
  } else {
    auto& resp = res_url_[key];
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

void MaliceUrlFilter::AddEventRecord(const EventFeatureRecord& new_rec, EventFeatureResponse* resp) {
  auto rec = resp->add_records();
  *rec = new_rec;
}

void MaliceUrlFilter::CheckMaliceUrlEvent(const Slice& key, const Slice& value,
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
  rec.set_url(pvckey.url);
  rec.set_obj(pvckey.obj);
  rec.set_type(pvckey.type);
  rec.set_model(pvckey.model);
  rec.set_flows(stat.flows);
  rec.set_pkts(stat.pkts);
  rec.set_bytes(stat.bytes);

  if (DEBUG) log_info("Got Dos Record: %s\n", rec.DebugString().c_str());
  AddEventRecord(rec, resp);
}


void MaliceUrlFilter::CheckMaliceUrl(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req) {
  const MaliceUrlKey& urlKey = *(const MaliceUrlKey*)key.data();
  const MaliceUrlStat& stat = *(const MaliceUrlStat*)value.data();

  if (stat.first <= req.starttime() || stat.first >= req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(urlKey.sip, urlKey.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(urlKey.dip, urlKey.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(urlKey.sip[0]);
    dip = ipnum_to_ipstr(urlKey.dip[0]);
  }

  if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
  if (req.has_sip() && req.sip() != sip) return;
  if (req.has_dip() && req.dip() != dip) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_url(urlKey.url);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);

  if (DEBUG) log_info("Got MaliceUrl Record: %s\n", rec.DebugString().c_str());
  AddRecord(urlKey, rec);
}

MaliceUrlFilter::EventGenerator::EventGenerator(const config::Event& e, u32 devid, u32 st, u32 et)
  : event_config(e), dev_id(devid), start_time(st), end_time(et) {

  if (DEBUG) log_info("EventGenerator initialized.\n");
}

void MaliceUrlFilter::GenerateEvents(const MaliceUrlKey& s, const MaliceUrlStat& p, GenEventRes* events, EventGenerator& gen) {
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
      e->set_obj("[" + ipnum_to_ipstr_v6(sip6) + "]:>[" + ipnum_to_ipstr_v6(dip6) + "]:" + to_string(s.dport) + " ");
    } else
      e->set_obj(ipnum_to_ipstr(s.sip[0]) + ":>"+ ipnum_to_ipstr(s.dip[0]) + ":" + to_string(s.dport) + " ");
    e->set_thres_value(event_config.min());
    e->set_alarm_value(p.score);
    e->set_value_type(event_config.data_type());
    e->set_model_id(1);

    //生成事件特征数据，即事件五元组详细信息
    GenEventFeature(s, e);
  }
}

void MaliceUrlFilter::GenEventFeature(const MaliceUrlKey& s, const event::GenEventRecord* e) {
  for (auto kv : event_details_[s]) {
    //auto k = kv.first;

    //if (k.sip[0] != s.sip[0] || k.sip[1] != s.sip[1] || k.sip[2] != s.sip[2] || k.sip[3] != s.sip[3]) continue;
    //if (k.dip[0] != s.dip[0] || k.dip[1] != s.dip[1] || k.dip[2] != s.dip[2] || k.dip[3] != s.dip[3]) continue;

    //for (auto it : kv.second) {
      auto k = it.first;
      auto v = it.second;
      k.time = e->time();
      k.type = e->type_id();
      k.model = e->model_id();
      memcpy(k.obj, e->obj().c_str(), e->obj().size()+1);
      InsertEventToTSDB(k, v);
    //}
  }
}

void MaliceUrlFilter::InsertEventToTSDB(const EventKey& s, const EventValue& p) {
  event_tsdb_->Put(p.first, Slice(&s, sizeof(s)), Slice(&p, sizeof(p)));
}
