#include "tcpinit_filter.h"
#include "../../common/common.h"
#include "../../common/ip.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/datetime.h"
#include "../../common/common_filter.hpp"
#include "../data/dbctx.pb.h"
#include "../data/tsdb.h"
#include <utility>

TcpinitFilter::TcpinitFilter(u32 dev_id, const string& model, unique_ptr<TSDB> tsdb)
  : FlowFilter(), dev_id_(dev_id), model_(model), tsdb_(std::move(tsdb)) {}

TcpinitFilter* TcpinitFilter::Create(u32 dev_id, const string& model, DBBuilder* builder) {
  auto* filter = new TcpinitFilter(
    dev_id, model, unique_ptr<TSDB>(new TSDB(builder, to_string(dev_id) + "_feature_tcpinit")));
  if (DEBUG) log_info("Tcpinit filter initialized.\n");
  return filter;
}


bool TcpinitFilter::UpdateByFlow(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.tcp_flags == 20) continue;     //过滤reset包
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    if (r.prot == 6) {
      UpdateTcpinits(r.first, r.last, sip, r.srcport, dip, r.dstport, r.tos, r.http_ret_code, r.pname, r.service_name, r.dPkts, r.dOctets);
    }
  }

  return true;
}

bool TcpinitFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
    auto r = *it;
    if (r.tcp_flags == 20) continue;     //过滤reset包
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

    if (r.prot == 6) {
      UpdateTcpinits(r.first, r.last, sip, r.srcport, dip, r.dstport, r.tos, r.http_ret_code, r.pname, r.service_name, r.dPkts, r.dOctets);
    }
  }

  return true;
}


void TcpinitFilter::UpdateTcpinits(u32 first, u32 last, u32 sip[], u16 sport, u32 dip[],
    u16 dport, u8 tos, u16 retcode, char* pname, char* service_name, u64 pkts, u64 bytes) {
  if (!strlen(pname)) 
    memcpy(pname, service_name, strlen(service_name)+1);

  if (tos & 0x01) {    //请求
    TvcKey ttcpinit;
    std::copy(sip, sip+4, ttcpinit.sip);
    std::copy(dip, dip+4, ttcpinit.dip);
    ttcpinit.dport = dport;
    ttcpinit.retcode = retcode;
    //ttcpinit.is_req = true;
    auto it = tcpinit_req_.find(ttcpinit);
    if (it == tcpinit_req_.end()) {
      TcpinitStat p;
      memset(&p, 0, sizeof(struct TcpinitStat));
      p.first = first;
      p.last = last;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      if (0 != strlen(pname))
        memcpy(p.app_proto, pname, strlen(pname)+1);

      tcpinit_req_[ttcpinit] = p;
    } else {
      auto& p = it->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      ++p.flows;
      p.pkts += pkts;
      p.bytes += bytes;
      if (0 != strlen(pname)) 
        memcpy(p.app_proto, pname, strlen(pname)+1);
    }
  } else {
    TvcKey ttcpinit;
    std::copy(sip, sip+4, ttcpinit.dip);
    std::copy(dip, dip+4, ttcpinit.sip);
    ttcpinit.dport = sport;
    ttcpinit.retcode = retcode;
    //ttcpinit.is_req = false;
    auto it = tcpinit_res_.find(ttcpinit);
    if (it == tcpinit_res_.end()) {
      TcpinitStat p;
      memset(&p, 0, sizeof(struct TcpinitStat));
      p.first = first;
      p.last = last;
      p.flows = 1;
      p.pkts = pkts;
      p.bytes = bytes;
      //p.retcode = retcode;
      if (0 != strlen(pname))
        memcpy(p.app_proto, pname, strlen(pname)+1);

      tcpinit_res_[ttcpinit] = p;
    } else {
      auto& p = it->second;
      p.first = MIN(p.first, first);
      p.last = MAX(p.last, last);
      ++p.flows;
      p.pkts += pkts;
      p.bytes += bytes;
      //p.retcode = retcode;
      if (0 != strlen(pname))
        memcpy(p.app_proto, pname, strlen(pname)+1);
    }
  }
}

void TcpinitFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<TcpinitFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);  
  
  for (auto it = ptr->tcpinit_req_.begin(); it != ptr->tcpinit_req_.end(); ++it) {
    auto s = it->first;
    auto p = it->second;

    if (ptr->tcpinit_res_.count(s)) {
      //ptr->InsertTcpinitToTSDB(s, ptr->tcpinit_res_[tmpKey]);
      if (!strlen(p.app_proto))     
        memcpy(p.app_proto, ptr->tcpinit_res_[s].app_proto, strlen(ptr->tcpinit_res_[s].app_proto)+1); 

      s.has_res = true;
    } else {
      s.has_res = s.retcode ? true : false;
    }

    ptr->InsertTcpinitToTSDB(s, p);
  }
}

void TcpinitFilter::InsertTcpinitToTSDB(const TvcKey& s, const TcpinitStat& stat) {
  TcpinitStat new_stat;
  Slice old_value;
  if (tsdb_->Get(stat.first, Slice(&s, sizeof(s)), &old_value) &&
      (old_value.size() >= sizeof(TcpinitStat))) {
    auto* old_stat = (TcpinitStat*)old_value.data();
    new_stat.first = std::min(stat.first, old_stat->first);
    new_stat.last = std::max(stat.last, old_stat->last);
    new_stat.pkts = stat.pkts + old_stat->pkts;
    new_stat.bytes = stat.bytes + old_stat->bytes;
    new_stat.flows =  stat.flows + old_stat->flows;
    if (strlen(stat.app_proto))
      strcpy(new_stat.app_proto, stat.app_proto);
  } else {
    new_stat = stat;
  }
  tsdb_->Put(stat.first, Slice(&s, sizeof(s)), Slice(&new_stat, sizeof(new_stat)));
}

void TcpinitFilter::FilterTcpinit(const feature::FeatureReq& req, feature::FeatureResponse* resp){
  tsdb_->Scan(
    req.starttime(), req.endtime(),
    [this, &req, resp](const Slice& key, const Slice& value) {
      CheckTcpinit(key, value, req, resp);
    });
}

void TcpinitFilter::AddRecord(const FeatureReq& req,
                              const FeatureRecord& new_rec,
                              feature::FeatureResponse* resp) const {
  auto rec = resp->add_records();
  *rec = new_rec;
  if (DEBUG) log_info("New Record: %s\n", new_rec.DebugString().c_str());
}

void TcpinitFilter::CheckTcpinit(
    const Slice& key,
    const Slice& value,
    const feature::FeatureReq& req, 
    feature::FeatureResponse* resp) {
  const TvcKey& tvckey = *(const TvcKey*)key.data();
  const TcpinitStat& stat = *(const TcpinitStat*)value.data();

  if (stat.first <= req.starttime() || stat.first >= req.endtime()) return;
  string sip, dip;
  if (model_ == "V6") {
    struct in6_addr sip6, dip6;
    std::copy(tvckey.sip, tvckey.sip+4, sip6.s6_addr32);
    sip = ipnum_to_ipstr_v6(sip6);
    std::copy(tvckey.dip, tvckey.dip+4, dip6.s6_addr32);
    dip = ipnum_to_ipstr_v6(dip6);
  } else {
    sip = ipnum_to_ipstr(tvckey.sip[0]);
    dip = ipnum_to_ipstr(tvckey.dip[0]);
  }

  if (req.has_ip() && req.ip() != sip && req.ip() != dip) return;
  if (req.has_sip() && req.sip() != sip) return;
	if (req.has_dip() && req.dip() != dip) return;
	if (req.has_dport() && req.dport() != tvckey.dport) return;

  FeatureRecord rec;
  rec.set_time(stat.first);
  rec.set_sip(sip);
  rec.set_dip(dip);
  rec.set_dport(tvckey.dport);
  rec.set_bytes(stat.bytes);
  rec.set_pkts(stat.pkts);
  rec.set_flows(stat.flows);
  rec.set_retcode(tvckey.retcode);
  rec.set_app_proto(stat.app_proto);
  if (tvckey.has_res)
    rec.set_srv_mark("res");
  else
    rec.set_srv_mark("req");

  if (DEBUG) log_info("Got Tcpinit Record: %s\n", rec.DebugString().c_str());
  AddRecord(req, rec, resp);
}
