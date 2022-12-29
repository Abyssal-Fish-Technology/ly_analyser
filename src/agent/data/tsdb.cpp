#include "tsdb.h"

#include "../../common/datetime.h"
#include "../../common/file.h"
#include "../../common/log.h"
#include <tuple>
#include <utility>

using namespace std;

///////////////////////////////////////////////////////////////////////////////
//  TSDB::CachedDBCtx
TSDB::CachedDBCtx::~CachedDBCtx() {
  if (ctx_->options().auto_commit()) ctx_->Commit();
}

bool TSDB::CachedDBCtx::Contain(const Slice& key) {
  return Get(key, nullptr);
}

void TSDB::CachedDBCtx::CacheWholeDB() {
  unique_ptr<DBCtx::Iterator> it(ctx_->NewIterator());
  if (it && it->First()) {
    while (true) {
      cache_.emplace(it->KeyStr(), it->ValueStr());
      if (!it->NextKey()) break;
    }
  }
  whole_db_cached_ = true;
}

bool TSDB::CachedDBCtx::Get(const Slice& key, Slice* value) {
  if (!cache_enabled_) return ctx_->Get(key, value);

  if (cache_whole_db_) {
    if (!whole_db_cached_) CacheWholeDB();
    auto it = cache_.find(key.ToString());
    if (it == cache_.end()) return false;
    if (value) *value = it->second;
    return true;
  }

  auto it = cache_.find(key.ToString());
  if (it == cache_.end()) {
    Slice v;
    ctx_->Get(key, &v);
    it = cache_.emplace(key.ToString(), v.ToString()).first;
  }
  if (value) *value = it->second;
  return !it->second.empty();
}

bool TSDB::CachedDBCtx::Put(const Slice& key, const Slice& value, DBCtx::Flags flags) {
  bool rv = ctx_->Put(key, value, flags);
  if (cache_enabled_) cache_[key.ToString()] = value.ToString();
  return rv;
}

///////////////////////////////////////////////////////////////////////////////
//  TSDB
TSDB::CachedDBCtx* TSDB::GetCtx(u32 timestamp) {
  timestamp -= timestamp % time_unit();
  auto it = map_.find(timestamp);
  if (it == map_.end()) {
    unique_ptr<DBCtx> db(builder_->Build(datetime::format_date(timestamp), datetime::format_timestamp(timestamp) + '_' + name_));
  //  auto db = builder_->Build(datetime::format_date(timestamp), datetime::format_timestamp(timestamp) + '_' + name_);
    if (!db.get()) return nullptr;
    return &map_.emplace(piecewise_construct,
                         forward_as_tuple(timestamp),
                         forward_as_tuple(true, false, std::move(db))).first->second;
  }
  return &it->second;
}

bool TSDB::Contain(u32 timestamp, const Slice& key) {
  auto ctx = GetCtx(timestamp);
  return ctx && ctx->Contain(key);
}

bool TSDB::Contain(u32 timestamp, const std::string& key) {
  auto ctx = GetCtx(timestamp);
  return ctx && ctx->Contain(Slice(key));
}

bool TSDB::Get(u32 timestamp, const Slice& key, Slice* value) {
  auto ctx = GetCtx(timestamp);
  return ctx && ctx->Get(key, value);
}

bool TSDB::Get(u32 timestamp, const std::string& key, std::string* value) {
  if (value) {
    Slice val;
    bool rv = Get(timestamp, Slice(key), &val);
    *value = val.ToString();
    return rv;
  } else {
    return Get(timestamp, Slice(key), nullptr);
  }
}

Slice TSDB::Get(u32 timestamp, const Slice& key) {
  Slice val;
  Get(timestamp, key, &val);
  return val;
}

std::string TSDB::Get(u32 timestamp, const std::string& key) {
  return Get(timestamp, Slice(key)).ToString();
}

bool TSDB::Put(u32 timestamp, const Slice& key, const Slice& value,
              DBCtx::Flags flags) {
  auto ctx = GetCtx(timestamp);
  return ctx && ctx->Put(key, value, flags);
}

bool TSDB::Put(u32 timestamp, const string& key, const string& value,
              DBCtx::Flags flags) {
  return Put(timestamp, Slice(key), Slice(value), flags);
}

u64 TSDB::Size(u32 starttime, u32 endtime) {
  return Size(starttime, endtime, (FilterFunctor)nullptr);
}

u64 TSDB::Size(u32 starttime, u32 endtime, FilterFunctor filter) {
  u64 size = 0;
  if (filter) {
    Scan(starttime, endtime, [&size](DBCtx::Iterator&){ ++size; }, filter);
    return size;
  }
  
  s32 step = time_unit();
  for (auto t = starttime; t <= endtime; t += step) {
    auto ctx = GetCtx(t);
    if (ctx) size += ctx->ctx()->Size();
  }
  return size;
}

void TSDB::Scan(u32 starttime, u32 endtime, KVFunctor kvfunctor) {
  Scan(starttime, endtime,
       [&kvfunctor](DBCtx::Iterator& it) { kvfunctor(it.Key(), it.Value()); },
       (FilterFunctor)nullptr);
}
void TSDB::Scan(u32 starttime, u32 endtime, IteratorFunctor iterator) {
  Scan(starttime, endtime, iterator, (FilterFunctor)nullptr);
}
  
void TSDB::Scan(u32 starttime, u32 endtime, IteratorFunctor iterator, FilterFunctor filter) {
  s32 step = time_unit();

  //starttime,endtime取整，防止少取数据
  starttime -= starttime % step;
  endtime -= endtime % step;

  for (auto t = starttime; t <= endtime; t += step) {
    auto ctx = GetCtx(t);
    if (!ctx) continue;
    unique_ptr<DBCtx::Iterator> it(ctx->ctx()->NewIterator());
    if (it->First()) {
      while (true) {
        if ((!filter || filter(it->Key(), it->Value())) && iterator) iterator(*it);
        if (!it->NextKey()) break;
      }
    }
  }
}

void TSDB::Scan(u32 starttime, u32 endtime, IteratorFunctor iterator, StringFilterFunctor filter) {
  Scan(starttime, endtime, iterator,
       (FilterFunctor)([&filter](const Slice& key, const Slice& value) -> bool {
         return filter(key.ToString(), value.ToString());
       }));
}
