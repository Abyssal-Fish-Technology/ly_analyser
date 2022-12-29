#include "unqlite_db.h"

#include <cstring>
#include <math.h>
#include <iomanip>
#include <string>
#include "../../common/log.h"
#include "../../common/datetime.h"
#include "../../common/strings.h"
#include "../../common/stringutil.h"

using namespace std;

string escape_str(const void* data, int size) {
  const char* p = (const char*)data;
  ostringstream oss;
  for (int i = 0; i < size; ++i, ++p) {
    if (*p < 32 || *p > 127) {
      oss << "/0x" << hex << *p << ' ';
    } else {
      oss << *p;
    }
  }
  return oss.str();
}

///////////////////////////////////////////////////////////////////////////////
int Consume(const void* data, unsigned int len, void* user_data) {
   ((string*)user_data)->append((const char*)data, len);
   return UNQLITE_OK;
 }

///////////////////////////////////////////////////////////////////////////////
// Unqliterator
///////////////////////////////////////////////////////////////////////////////
class UnqliteIterator : public DBCtx::Iterator {
 public:
  UnqliteIterator(UnqliteCtx* ctx, unqlite_kv_cursor* cursor);
  ~UnqliteIterator() override;
  bool First() override;
  bool NextKey() override;
  bool NextValue() override{ return false; }
  bool Seek(const Slice& key) override;
  bool Seek(const Slice& key, const Slice& value) override;
  bool Replace(const Slice& value) override;
  const Slice Key() override;
  string KeyStr() override;
  const Slice Value() override;
  string ValueStr() override;
  u32 DupValueCount() override { return 1; }

 private:
  UnqliteCtx* ctx_;
  unqlite_kv_cursor* cursor_;
  string key_;
  string value_;
};

UnqliteIterator::UnqliteIterator(UnqliteCtx* ctx, unqlite_kv_cursor* cursor) 
  : ctx_(ctx), cursor_(cursor) {}

UnqliteIterator::~UnqliteIterator() {
  unqlite_kv_cursor_release(ctx_->db_, cursor_);
}

bool UnqliteIterator::First() {
  return UNQLITE_OK == unqlite_kv_cursor_first_entry(cursor_);
}

bool UnqliteIterator::NextKey() {
  return UNQLITE_OK == unqlite_kv_cursor_next_entry(cursor_);
}

bool UnqliteIterator::Seek(const Slice& key) {
  return
    UNQLITE_OK == unqlite_kv_cursor_seek(cursor_, key.data(), key.size(),
                                         UNQLITE_CURSOR_MATCH_EXACT);
}

bool UnqliteIterator::Seek(const Slice& key, const Slice& value) {
  return Seek(key) && (value == Value());
}

bool UnqliteIterator::Replace(const Slice& value) {
  const Slice key = Key();
  return !key.empty() && ctx_->Put(key, value);
}

const Slice UnqliteIterator::Key() {
  key_.clear();
  if (UNQLITE_OK != unqlite_kv_cursor_key_callback(cursor_, &Consume, &key_)) {
    return Slice();
  } else {
    return Slice(key_.data(), key_.size());
  }
}

string UnqliteIterator::KeyStr() {
  key_.clear();
  unqlite_kv_cursor_key_callback(cursor_, &Consume, &key_);
  return key_;
}

const Slice UnqliteIterator::Value() {
  value_.clear();
  if (UNQLITE_OK !=
      unqlite_kv_cursor_data_callback(cursor_, &Consume, &value_)) {
    return Slice();
  } else {
    return Slice(value_.data(), value_.size());
  }
}

string UnqliteIterator::ValueStr() {
  value_.clear();
  unqlite_kv_cursor_data_callback(cursor_, &Consume, &value_);
  return value_;
}

///////////////////////////////////////////////////////////////////////////////
// UnqliteCtx
///////////////////////////////////////////////////////////////////////////////
UnqliteCtx::UnqliteCtx(const DBCtxOptions& options, unqlite* db) :
  DBCtx(options), db_(db), error_code_(UNQLITE_OK) {}

UnqliteCtx::~UnqliteCtx() {
  unqlite_close(db_);
}

UnqliteCtx* UnqliteCtx::Create(const DBCtxOptions& options) {
  unqlite* db = nullptr;
  string db_path = options.db_path() + '/' + options.db_name();
  auto flag = options.read_only() ? UNQLITE_OPEN_READONLY : UNQLITE_OPEN_CREATE;
  if (UNQLITE_OK != unqlite_open(&db, db_path.c_str(), flag)) {
    log_err("Failed to %s unqlite db %s\n",
            options.read_only() ? "open" : "create",
            db_path.c_str());
    return nullptr;
  }
  if (DEBUG) {
    log_info("%s unqlite db %s\n",
            options.read_only() ? "Opened" : "Open/Created",
            db_path.c_str());
  }
  return new UnqliteCtx(options, db);
}

DBCtx::Iterator* UnqliteCtx::NewIterator() {
  unqlite_kv_cursor* cursor;
  error_code_ = unqlite_kv_cursor_init(db_, &cursor);
  if (Error()) {
    log_err("Failed to create unqlite kv cursor.\n");
    return nullptr;
  }
  return new UnqliteIterator(this, cursor);
}

bool UnqliteCtx::Get(const Slice& key, Slice* value) {
  value_.clear();
  error_code_ = unqlite_kv_fetch_callback(db_, key.data(), key.size(),
                                          &Consume, &value_);

  if (Error()) return false;
  if (value) { value->assign(value_.data(), value_.size()); } 
  return true;
}
    
bool UnqliteCtx::Put(const Slice& key, const Slice& value, Flags flags) {
  error_code_ = unqlite_kv_store(db_, key.data(), key.size(),
                                 value.data(), value.size());
  return !Error();
}
  
bool UnqliteCtx::Error() const  {
  return UNQLITE_OK != error_code_;
}

bool UnqliteCtx::NotFound() const {
  return error_code_ == UNQLITE_NOTFOUND;
}

bool UnqliteCtx::Commit() {
  error_code_ = unqlite_commit(db_);
  return !Error() || UNQLITE_READ_ONLY == error_code_;
}

