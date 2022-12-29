#ifndef __AGENT__BASELINE_H__
#define __AGENT__BASELINE_H__

#include "../common/common.h"
#include "feature_key.h"
#include "tsdb.h"
#include <set>

class MO {
 public:
  MO(const string& ip) 
};

class Baseline {
 public:
  Baseline(const string& ip) { }
  Baseline(u16 port) { }
  Baseline(u16 proto, u16 port) {
  Baseline
  struct IpKey {
    u32 ip;
  };
  typedef std::set<SvcKey> SvcKeySet;
  struct SvcValue {
    u32 peer_ip;
  };

  Baseline(const std::string& base_dir, bool read_only)
    : read_only_(read_only),
      db_ip_(new DBs(base_dir, "ip", read_only)),
      db_svc_(new DBs(base_dir, "svc", read_only)) {
  }

  ~Baseline() {
  }

  void Update(u32 first, u16 proto, u32 sip, u16 sport, u32 dip, u16 dport) {
    if (read_only_) return;
    UpdateIp(first, sip);
    UpdateIp(first, dip);
    UpdateSvc(first, proto, sip, sport, dip);
    UpdateSvc(first, proto, dip, dport, sip);
  }

  u64 GetXDayIpCount(u32 x) {
    auto t = time(NULL) - x * 24*3600;
    t -= t % TimeUnit;
    auto ctx = db_ip_->GetOrOpenDB(t, MDB_INTEGERKEY);
    return ctx->Size();
  }

  void GetQualifiedSvcSet(u32 x, u32 y, SvcKeySet* result_set) {
    result_set->clear();
    if (y == 0) return;
    u64 client_threshold = GetXDayIpCount(x) * 100 / y;
    auto t = time(NULL) - x * 24*3600;
    t -= t % TimeUnit;
    auto ctx = db_svc_->GetOrOpenDB(t, MDB_DUPSORT|MDB_INTEGERDUP);
    SvcWalkingData walking_data{this, ctx, result_set, client_threshold};
    ctx->WalkKeys(WalkingSvc, &walking_data);
  }
 private:
  struct SvcWalkingData {
    Baseline* self;
    MDBCtx* ctx;
    SvcKeySet* result_set;
    u64 client_threshold;
  };

  static void WalkingSvc(void* cur, void*k_data, u32 k_len, void* v_data, u32 v_len, void* data) {
    auto p = (SvcWalkingData*)data;
    p->self->CheckSvc(cur, (SvcKey*)k_data, p);  
  }
  
  void CheckSvc(void* cur, const SvcKey* key, SvcWalkingData* walking_data) {
    if (walking_data->ctx->GetKeySize(cur) < walking_data->client_threshold) return;
    walking_data->result_set->insert(*key);
  }

  void UpdateIp(u32 first, u32 ip) {
    auto start_time = first - first % TimeUnit;
    for (auto t = start_time; t >= start_time - TimeUnit * BackTrack; t -= TimeUnit) {
      auto ctx = db_ip_->GetOrOpenDB(t, MDB_INTEGERKEY);
      s32 rc = 0;
      // If already found it, stop updating.
      if (!ctx->Put(&ip, sizeof(ip), NULL, 0, 0, &rc) || rc == MDB_KEYEXIST) break;
    }
  }

  void UpdateSvc(u32 first, u16 proto,  u32 ip, u16 port, s32 peer_ip) {
    auto start_time = first - first % TimeUnit;
    for (auto t = start_time; t >= start_time - TimeUnit * BackTrack; t -= TimeUnit) {
      auto ctx = db_svc_->GetOrOpenDB(t, MDB_DUPSORT|MDB_INTEGERDUP);
      s32 rc = 0;
      SvcKey key {ip, proto, port};
      // If already found it, stop updating.
      if (!ctx->Put(&key, sizeof(key), &peer_ip, sizeof(peer_ip), MDB_NODUPDATA, &rc) ||
          rc == MDB_KEYEXIST) break;
    }
  }

  static u32 TimeUnit;
  static u32 BackTrack;
  bool read_only_;
  std::unique_ptr<DBs> db_ip_;
  std::unique_ptr<DBs> db_svc_;
};

#endif  // __AGENT__BASELINE_H__
