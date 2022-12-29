#include "mdb.h"

#include <math.h>
#include <iomanip>
#include "../../common/log.h"
#include "../../common/datetime.h"
#include "../../common/strings.h"
#include "../../common/stringutil.h"

#define MDB_ISOK(rc) (!rc)
#define MDB_CHECK(rc) {\
  static u32 err_count; \
  error_code_ = (rc); \
  if (error_code_ && (err_count++ < 50)) { \
    log_err("%s:%d mdb_error:%d %s\n", __FILE__, __LINE__,\
            error_code_, ErrorMsg().c_str()); \
  }\
}

using namespace std;

namespace {
string envflagsstr(int flags) {
  string s;
  if (flags & MDB_NOSUBDIR) s += "NOSUBDIR ";
  if (flags & MDB_RDONLY) s + "RDONLY ";
  if (flags & MDB_NOSYNC) s += "NOSYNC ";
  if (flags & MDB_NOMETASYNC) s += "NOMETASYNC ";
  if (flags & MDB_WRITEMAP) s += "WRITEMAP ";
  if (flags & MDB_NOTLS) s += "NOTLS ";
  if (flags & MDB_NOLOCK) s += "NOLOCK ";
  if (flags & MDB_NORDAHEAD) s += "NORDAHEAD ";
  if (flags & MDB_NOMEMINIT) s += "NOMEMINIT ";
  return s;
}
} // namespace

///////////////////////////////////////////////////////////////////////////////
// MDBIterator
///////////////////////////////////////////////////////////////////////////////
class MDBIterator : public DBCtx::Iterator {
 public:
  MDBIterator(MDBCtx* ctx, MDB_cursor* cursor) : ctx_(ctx), cursor_(cursor){}
  ~MDBIterator() override { mdb_cursor_close(cursor_); }

  bool First() override {
    return !(error_code_ = mdb_cursor_get(cursor_, &key_, &value_, MDB_FIRST));
  }
  bool NextKey() override {
    return !(error_code_ = mdb_cursor_get(cursor_, &key_, &value_, MDB_NEXT_NODUP));
  }
  bool NextValue() override {
    return !(error_code_ = mdb_cursor_get(cursor_, &key_, &value_, MDB_NEXT_DUP));
  }
  bool Seek(const Slice& key) override {
    key_.mv_data = (void*)key.data();
    key_.mv_size = key.size();
    return !(error_code_ = mdb_cursor_get(cursor_, &key_, &value_, MDB_SET));
  }
  bool Seek(const Slice& key, const Slice& value) override {
    key_.mv_data = (void*)key.data();
    key_.mv_size = key.size();
    value_.mv_data = (void*)value.data();
    value_.mv_size = value.size();
    return !(error_code_ = mdb_cursor_get(cursor_, &key_, &value_, MDB_GET_BOTH));
  }
  bool Replace(const Slice& value) override {
    return !(error_code_ = mdb_cursor_put(cursor_, &key_, &value_, MDB_CURRENT));
  }
  const Slice Key() override { return Slice(key_.mv_data, key_.mv_size); }
  const Slice Value() override { return Slice(value_.mv_data, value_.mv_size); }
  u32 DupValueCount() override {
    if (!cursor_) return 0;
    size_t size = 0;
    MDB_CHECK(mdb_cursor_count(cursor_, &size));
    return ERROR() ? 0 : size;
  }

  bool Error() const { return error_code_;}
  const string& ErrorMsg() { return error_msg_ = mdb_strerror(error_code_); }

 private:
  MDBCtx* ctx_;
  MDB_cursor* cursor_;
  MDB_val key_{0, 0};
  MDB_val value_{0, 0};
  string error_msg_;
  int error_code_ = 0;
};

///////////////////////////////////////////////////////////////////////////////
// MDBCtx
///////////////////////////////////////////////////////////////////////////////
MDBCtx* MDBCtx::Create(const DBCtxOptions& options) {
  MDBCtx* ctx = new MDBCtx(options);
  if (!ctx->Init()) {
    delete ctx;
    return nullptr;
  }
  return ctx;
}

MDBCtx::~MDBCtx() {
  CleanupEnv();
}

bool MDBCtx::Init() {
  MDB_CHECK(mdb_env_create(&env_));
  if (Error()) {CleanupEnv(); return false;}
  if (options().db_path().find("xday") >= 0) {
    int page_size = sysconf(_SC_PAGE_SIZE);
    u64 map_size = (options().mdb_max_map_size() + page_size - 1)/ page_size * page_size;
    if (DEBUG) {
      log_info("mdb_env_set_mapsize(%llu)\n", map_size);
    }
    MDB_CHECK(mdb_env_set_mapsize(env_, map_size));
  }
  if (Error()) {CleanupEnv(); return false;}
  if (DEBUG) {
    log_info("%p mdb_env_set_maxdbs(%u)\n", this, options().mdb_max_db());
  }
  MDB_CHECK(mdb_env_set_maxdbs(env_, options().mdb_max_db()));
  if (Error()) {CleanupEnv(); return false;}
  int flags = MDB_NOSUBDIR;
  string flags_str = "NOSUBDIR ";
  if (options().read_only()) {
    flags |= MDB_RDONLY;
  } else {
    //flags |= MDB_WRITEMAP;
  }
  if (DEBUG) {
    log_info("%p mdb_env_open(%s, %s)\n",
      this, options().db_path().c_str(), envflagsstr(flags).c_str());
  }
  auto previous_mask = umask(0);
  error_code_ = mdb_env_open(env_, options().db_path().c_str(), flags, 0666);
  umask(previous_mask);
  if (Error()) {
    static int logged;
    if (logged++ < 10) {
      MDB_CHECK(Error());
      log_err("%p mdb_env_open error path:%s\n", this, options().db_path().c_str());
    }
    CleanupEnv(); return false;
  } else if (DEBUG) {
    log_info("%p mdb_env_open succ:%s\n", this, options().db_path().c_str());
  }
  return true;
}

DBCtx::Iterator* MDBCtx::NewIterator() {
  if (!txn_ && !Begin()) return NULL;
  MDB_cursor* cur;
  MDB_CHECK(mdb_cursor_open(txn_, dbi_, &cur));
  if (Error() || !cur) return NULL;
  return new MDBIterator(this, cur);
}

void MDBCtx::CleanupEnv() {
  if (env_) {
    if (DEBUG) log_info("%p, mdb_env_close path:%s\n", this, options().db_path().c_str());
    mdb_env_close(env_);
    env_ = NULL;
  }
}

bool MDBCtx::Contain(const Slice& key) {
  return Get(key, nullptr);
}

bool MDBCtx::Get(const Slice& key, Slice* value) {
  if (!txn_ && !Begin()) return false;
  MDB_val k, v{0, 0};
  k.mv_data = (void*)key.data();
  k.mv_size = key.size();
  error_code_ = mdb_get(txn_, dbi_, &k, &v);
  if (Error() && !NotFound()) MDB_CHECK(error_code_);
  if (value) value->assign(v.mv_data, v.mv_size);
  static u32 log_count;
  if (DEBUG && log_count++ < 50) {
    stringstream s;
    s << "mdb_get #" << log_count << ' ';
    s << "key:" << k.mv_size << "bytes "; 
    for (u32 i = 0; i < k.mv_size; ++i) {
      s << StringPrintf("%02x ", ((u8*)k.mv_data)[i]);
    }
    s << "value:" << v.mv_size << "bytes "; 
    for (u32 i = 0; i < v.mv_size; ++i) {
      s << StringPrintf("%02x ", ((u8*)v.mv_data)[i]);
    }
    //if (DEBUG) log_info("%p %s\n", this, s.str().c_str());
  }
  return !Error();
}

bool MDBCtx::Put(
    const Slice& key, const Slice& value, Flags flags) {
  if (!txn_ && !Begin()) return false;
  MDB_val k, v;
  k.mv_data = (void*)key.data();
  k.mv_size = key.size();
  v.mv_data = (void*)value.data();
  v.mv_size = value.size();
  int mdb_flags = 0;
  if (flags & NODUPDATA) mdb_flags |= MDB_NODUPDATA;
  if (flags & NOOVERWRITE) mdb_flags |= MDB_NOOVERWRITE;
  if (flags & APPEND) mdb_flags |= MDB_APPEND;
  if (flags & APPENDDUP) mdb_flags |= MDB_APPENDDUP;
  
  static u32 log_count;
  ++log_count;
  if (DEBUG && (log_count < 50)) {
    stringstream s;
    s << "mdb_put #" << log_count << ' ';
    if (mdb_flags & MDB_NODUPDATA) s << "NODUPDATA ";
    if (mdb_flags & MDB_NOOVERWRITE) s << "NOOVERWRITE ";
    if (mdb_flags & MDB_APPEND) s << "APPEND ";
    if (mdb_flags & MDB_APPENDDUP) s << "APPENDDUP ";
    s << "key:" << k.mv_size << "bytes "; 
    for (u32 i = 0; i < k.mv_size; ++i) {
      s << StringPrintf("%02x ", ((u8*)k.mv_data)[i]);
    }
    s << "value:" << v.mv_size << "bytes "; 
    for (u32 i = 0; i < v.mv_size; ++i) {
      s << StringPrintf("%02x ", ((u8*)v.mv_data)[i]);
    }
    cerr << s.str() << endl;
    log_info("%p %s\n", this, s.str().c_str());
  }
  if (DEBUG && ((log_count % 1000) == 0)) {
    log_info("%p mdb_put %u times.\n", this, log_count);
  }
  
  error_code_ = mdb_put(txn_, dbi_, &k, &v, mdb_flags);
  if (Error() && !KeyExist()) {
    MDB_CHECK(error_code_);
    return false;
  }
  return true;
}

bool MDBCtx::NotFound() const {
  return Error() && error_code_ == MDB_NOTFOUND;
}

bool MDBCtx::KeyExist() const {
  return Error() && error_code_ == MDB_KEYEXIST;
}

bool MDBCtx::Begin() {
  if (!Initialized() && !Init()) return false;

  int flags = options().read_only() ? MDB_RDONLY : 0;
  if (DEBUG) {
    log_info("%p mdb_txn_begin(%s, %s, flags:%s)\n", this,
        options().db_path().c_str(),
        options().db_name().c_str(),
        flags & MDB_RDONLY ? "RDONLY":"");
  }
  MDB_CHECK(mdb_txn_begin(env_, NULL, flags, &txn_));
  if (Error()) return false;
  flags = 0;
  string flags_str;
  if (!options().read_only()) {
    flags |= MDB_CREATE;
    flags_str += "MDB_CREATE ";
  }
  if (options().dup_sort()) {
    flags |= MDB_DUPSORT;
    flags_str += "MDB_DUPSORT ";
    if (options().dup_fixed()) {
      flags |= MDB_DUPFIXED;
      flags_str += "MDB_DUPFIXED";
    }
  }
  //if (options().integer_key()) flags |= MDB_INTEGERKEY;
  if (DEBUG) {
    log_info("%p mdb_dbi_open(%s, %s, flags:%s)\n",
        this, options().db_path().c_str(),
        options().db_name().c_str(), flags_str.c_str());
  }
  MDB_CHECK(mdb_dbi_open(txn_, options().db_name().c_str(), flags, &dbi_));
  if (DEBUG && !Error()) {
    log_info("%p mdb_dbi_open succ. %s %s %ju entries in db.\n",
        this, options().db_path().c_str(), options().db_name().c_str(), Size());
  }
  return !Error();
}

bool MDBCtx::Commit() {
  if (DEBUG) {
    log_info("%p mdb_txn_commit %s %s\n", this, options().db_path().c_str(),
        options().db_name().c_str());
  }
  MDB_CHECK(mdb_txn_commit(txn_));
  return !Error();
}

u64 MDBCtx::Size() {
  if (!txn_) return 0;
  MDB_stat stat;
  MDB_CHECK(mdb_stat(txn_, dbi_, &stat));
  if (Error()) return 0; 
  return stat.ms_entries;
}
  
const string& MDBCtx::ErrorMsg() {
  return error_msg_ = mdb_strerror(error_code_);
}

