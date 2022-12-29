#include "web_cache.h"

#include <google/protobuf/text_format.h>
#include "../../common/common.h"
#include "../../common/datetime.h"
#include "../../common/file.h"
#include "../../common/log.h"
#include "../../common/sha256.h"
#include "../define.h"

#define CACHE_ENTRY_LIMIT 1048578

using namespace std;
using google::protobuf::Message;
using google::protobuf::TextFormat;

namespace {

////////////////////////////////////////////////////////////////////////////
string truncate(const string& s, u32 size) {
  return s.length() > size ? s.substr(0, size - 3) + "..." : s;
}

////////////////////////////////////////////////////////////////////////////
string cache_key(const string& key) {
  return sha256(key);
}

////////////////////////////////////////////////////////////////////////////
string prepare_cache_file(const string& cache_key) {
  string first_level = AGENT_CACHE_DIR"/" + cache_key.substr(0, 1);
  mkdir(first_level.c_str(), 0700);
  string second_level = first_level + "/" + cache_key.substr(1, 2);
  mkdir(second_level.c_str(), 0700);
  return second_level + "/" + cache_key;
}

////////////////////////////////////////////////////////////////////////////
bool save_to_file_cache(const string& key, const string& value) {
  ofstream ofs(prepare_cache_file(cache_key(key)), ios::out);
  ofs << value;
  return true;
}

////////////////////////////////////////////////////////////////////////////
string load_from_file_cache(const string& key) {
  string file_name = prepare_cache_file(cache_key(key));
  if (!file_exists(file_name)) return string();
  ifstream ifs(file_name);
  stringstream buffer;
  buffer << ifs.rdbuf();
  return buffer.str();
}

}  // namespace

////////////////////////////////////////////////////////////////////////////
string WebCache::TSDBCache::Get(u32 time, const string& key) {
  string value = tsdb_->Get(time, key);
  if (DEBUG) {
    log_info("TSDBCache::Get [%s]: %s => %s\n",
             datetime::format_timestamp(time).c_str(),
             key.c_str(), truncate(value, 80).c_str());
  }
  return value;
}

////////////////////////////////////////////////////////////////////////////
bool WebCache::TSDBCache::Put(u32 time, const string& key, const string& value) {
  bool succeed = tsdb_->Put(time, key, value);
  if (DEBUG) {
    log_info("TSDBCache::Put [%s]: %s => %s %s\n",
             datetime::format_timestamp(time).c_str(),
             key.c_str(), truncate(value, 80).c_str(),
             succeed ? "succeeded" : "failed");
  }
  return succeed;
}

////////////////////////////////////////////////////////////////////////////
// File based.
string WebCache::InternalGet(const string& key) {
  return load_from_file_cache(prefix_ + key);
}

bool WebCache::InternalUpdate(const string& key, const string& value) {
  if (value.size() > CACHE_ENTRY_LIMIT) return false;
  return save_to_file_cache(prefix_ + key, value);
}

////////////////////////////////////////////////////////////////////////////
// TSDB based.
string WebCache::InternalGet(u32 time, const string& key) {
  if (!tsdb_cache_) tsdb_cache_.reset(new TSDBCache(builder_));
  return tsdb_cache_->Get(time, prefix_ + key);
}

bool WebCache::InternalUpdate(u32 time, const string& key, const string& value) {
  if (value.size() > CACHE_ENTRY_LIMIT) return false;
  if (!tsdb_cache_) tsdb_cache_.reset(new TSDBCache(builder_));
  return tsdb_cache_->Put(time, prefix_ + key, value);
}

////////////////////////////////////////////////////////////////////////////
string WebCache::Get(const string& key) {
  return InternalGet(key);
}

string WebCache::Get(u32 time, const string& key) {
  return InternalGet(time, key);
}

bool WebCache::Get(const Message& key, Message* value) {
  string key_str;
  TextFormat::PrintToString(key, &key_str);
  string value_str = Get(key_str);
  if (value_str.empty()) return false;
  return TextFormat::ParseFromString(value_str, value);
}

bool WebCache::Get(u32 time, const Message& key, Message* value) {
  string key_str;
  TextFormat::PrintToString(key, &key_str);
  string value_str = Get(time, key_str);
  if (value_str.empty()) return false;
  return TextFormat::ParseFromString(value_str, value);
}

bool WebCache::Update(const string& key, const string& value) {
  return InternalUpdate(key, value);
}

bool WebCache::Update(u32 time, const string& key, const string& value) {
  return InternalUpdate(time, key, value);
}

bool WebCache::Update(const Message& key, const Message& value) {
  string key_str;
  TextFormat::PrintToString(key, &key_str);
  string value_str;
  TextFormat::PrintToString(value, &value_str);
  if (DEBUG) {
    log_info("Update Web Cache: %s => %s\n",
             key_str.c_str(), truncate(value_str, 80).c_str());
  }
  return InternalUpdate(key_str, value_str);
}

bool WebCache::Update(u32 time, const Message& key, const Message& value) {
  string key_str;
  TextFormat::PrintToString(key, &key_str);
  string value_str;
  TextFormat::PrintToString(value, &value_str);
  if (DEBUG) {
    log_info("Update Web Cache [%s]: %s => %s\n",
             datetime::format_timestamp(time).c_str(),
             key_str.c_str(), truncate(value_str, 80).c_str());
  }
  return InternalUpdate(time, key_str, value_str);
}
