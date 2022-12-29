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
    uint32_t sip[4], dip[4];
    memset(sip, 0, sizeof(uint)*4);
    memset(dip, 0, sizeof(uint)*4);
    sip[0] = r.v4.srcaddr;
    dip[0] = r.v4.dstaddr;

    if ((r.tos & 0x01) && (r.prot == 6)) {
      UpdateTcpinits(r.first, r.last, sip, dip, r.dstport, r.dPkts, r.dOctets);
    }
  }

  return true;
}

bool TcpinitFilter::UpdateByFlowV6(std::vector<master_record_t>* flowset) {
  for(auto it = flowset->begin(); it != flowset->end(); it++) {
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

    if ((r.tos & 0x01) && (r.prot == 6)) {
      UpdateTcpinits(r.first, r.last, sip, dip, r.dstport, r.dPkts, r.dOctets);
    }
  }

  return true;
}


void TcpinitFilter::UpdateTcpinits(u32 first, u32 last, u32 sip[], u32 dip[],
    u16 dport, u64 pkts, u64 bytes) {
  TvcKey ttcpinit;
  std::copy(sip, sip+4, ttcpinit.sip);
  std::copy(dip, dip+4, ttcpinit.dip);
  ttcpinit.dport = dport;
  auto it = tcpinits_.find(ttcpinit);
  if (it == tcpinits_.end()) {
    TcpinitStat p;
    memset(&p, 0, sizeof(struct TcpinitStat));
    p.first = first;
    p.last = last;
    p.flows = 1;
    p.pkts = pkts;
    p.bytes = bytes;
    tcpinits_[ttcpinit] = p;
  } else {
    auto& p = it->second;
    p.first = MIN(p.first, first);
    p.last = MAX(p.last, last);
    ++p.flows;
    p.pkts += pkts;
    p.bytes += bytes;
  }
}

void TcpinitFilter::UpdateFinished(std::vector<master_record_t>* flowset, unique_ptr<TcpinitFilter>& ptr, const string& model) {
  if (model == "V6")
    ptr->UpdateByFlowV6(flowset);
  else
    ptr->UpdateByFlow(flowset);  
  
  for (auto it = ptr->tcpinits_.begin(); it != ptr->tcpinits_.end(); ++it) {
    auto& s = it->first;
    auto& p = it->second;
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
  if (DEBUG) log_info("Got Tcpinit Record: %s\n", rec.DebugString().c_str());
  AddRecord(req, rec, resp);
}
