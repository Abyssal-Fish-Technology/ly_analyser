#ifndef __AGENT_DATA_TSDB_H__
#define __AGENT_DATA_TSDB_H__

#include <functional>
#include <map>
#include <unordered_map>
#include "../../common/common.h"
#include "../../common/slice.h"
#include "dbctx.h"

class TSDB {
 public:
  typedef std::function<void(const Slice&, const Slice&)> KVFunctor;
  typedef std::function<void(DBCtx::Iterator&)> IteratorFunctor;
  typedef std::function<bool(const Slice&, const Slice&)> FilterFunctor;
  typedef std::function<bool(const std::string&, const std::string&)> StringFilterFunctor;

  TSDB(DBBuilder* builder, const std::string& name)
    : builder_(builder), name_(name) {}

  const std::string& name() { return name_; }
  u32 time_unit() { return builder_->options().time_unit(); }
  bool Contain(u32 timestamp, const Slice& key);
  bool Contain(u32 timestamp, const std::string& key);
  bool Get(u32 timestamp, const Slice& key, Slice* value);
  bool Get(u32 timestamp, const std::string& key, std::string* value);
  Slice Get(u32 timestamp, const Slice& key);
  std::string Get(u32 timestamp, const std::string& key);
  bool Put(u32 timestamp, const Slice& key, const Slice& value,
           DBCtx::Flags flags = DBCtx::DEFAULT);
  bool Put(u32 timestamp, const std::string& key, const std::string& value,
           DBCtx::Flags flags = DBCtx::DEFAULT);
  u64 Size(u32 starttime, u32 endtime);
  u64 Size(u32 starttime, u32 endtime, FilterFunctor filter);
  u64 Size(u32 starttime, u32 endtime, StringFilterFunctor filter);
  void Scan(u32 starttime, u32 endtime, KVFunctor);
  void Scan(u32 starttime, u32 endtime, IteratorFunctor);
  void Scan(u32 starttime, u32 endtime, IteratorFunctor, FilterFunctor filter);
  void Scan(u32 starttime, u32 endtime, IteratorFunctor, StringFilterFunctor filter);

 private:
  class CachedDBCtx {
   public:
    typedef std::unordered_map<std::string, std::string> Cache;
   // CachedDBCtx(bool enable_cache, bool cache_whole_db, DBCtx* ctx)
     // : cache_enabled_(enable_cache), cache_whole_db_(cache_whole_db), ctx_(ctx) {}
    CachedDBCtx(bool enable_cache, bool cache_whole_db, std::unique_ptr<DBCtx> ctx)
      : cache_enabled_(enable_cache), cache_whole_db_(cache_whole_db), ctx_(std::move(ctx)) {}
    ~CachedDBCtx();

    DBCtx* ctx() { return ctx_.get(); }
    Cache* cache() { return &cache_; }

    void CacheWholeDB();

    // Only these are cachable.
    bool Contain(const Slice& key);
    bool Get(const Slice& key, Slice* value);
    bool Put(const Slice& key, const Slice& value, DBCtx::Flags flags);

   private:
    Cache cache_;
    bool cache_enabled_ = false;
    bool cache_whole_db_ = false;
    bool whole_db_cached_ = false;
    std::unique_ptr<DBCtx> ctx_;
  };

  typedef std::map<u32, CachedDBCtx> DBCtxMap;

  CachedDBCtx* GetCtx(u32 timestamp);

  DBBuilder* builder_;
  const std::string name_;
  DBCtxMap map_;
};

#endif // __AGENT_DATA_TSDB_H__
