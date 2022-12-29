#ifndef __AGENT_DATA_DBCTX_H__
#define __AGENT_DATA_DBCTX_H__

#include "../../common/common.h"
#include "../../common/slice.h"
#include "dbctx.pb.h"
#include <memory>

class DBCtx {
 public:
  explicit DBCtx(const DBCtxOptions& options) : options_(options) {}
  virtual ~DBCtx() {}

  enum Status {
    OK, KEYEXIST, NOTFOUND, ERROR
  };
  enum Flags {
    DEFAULT = 0, NODUPDATA = 1, NOOVERWRITE = 2, APPEND = 4, APPENDDUP = 8
  };

  class Iterator {
   public:
    virtual ~Iterator() {}
    virtual bool First() = 0;
    virtual bool NextKey() = 0;
    virtual bool NextValue() = 0;
    virtual bool Seek(const Slice& key) = 0;
    virtual bool Seek(const std::string& key) { return Seek(Slice(key)); }
    virtual bool Seek(const Slice& key, const Slice& value) = 0;
    virtual bool Seek(const std::string& key, const std::string& value) {
      return Seek(Slice(key), Slice(value));
    }
    virtual bool Replace(const Slice& value) = 0;
    virtual bool Replace(const std::string& value) {
      return Replace(Slice(value));
    }
    virtual const Slice Key() = 0;
    virtual std::string KeyStr() { return Key().ToString(); }
    virtual const Slice Value() = 0;
    virtual std::string ValueStr() { return Value().ToString(); }
    virtual u32 DupValueCount() = 0;
  };

  inline const DBCtxOptions& options() {return options_;}
  virtual Iterator* NewIterator()= 0;
  virtual bool Contain(const Slice& key) = 0;
  virtual bool Contain(const std::string& key) { return Contain(Slice(key));}
  virtual bool Get(const Slice& key, Slice* value) = 0;
  virtual bool Get(const std::string& key, std::string* value) {
    Slice val;
    bool rv = Get(Slice(key), &val);
    if (value) *value = val.ToString();
    return rv;
  }
  virtual Slice Get(const Slice& key) {
    Slice val;
    Get(key, &val);
    return val;
  }
  virtual std::string Get(const std::string& key) { return Get(Slice(key)).ToString(); }
  virtual bool Put(const Slice& key, const Slice& value, Flags flags = DEFAULT) = 0;
  virtual bool Put(const std::string& key, const std::string& value, Flags flags = DEFAULT) {
    return Put(Slice(key), Slice(value), flags);
  }
  virtual bool Begin() = 0;
  virtual bool Commit() = 0;
  virtual u64 Size() = 0;
  virtual bool Error() const = 0;
  virtual bool NotFound() const = 0;
  virtual bool KeyExist() const = 0;

 private:
  const DBCtxOptions options_;
};

class DBBuilder {
 public:
  DBBuilder(const DBCtxOptions& options, const std::string& base_path);

  const DBCtxOptions& options() { return options_; }
  DBCtx* Build(const std::string& sub_path, const std::string& db_name);

 private:
  DBCtxOptions options_;
};

#endif // __AGENT_DATA_DBCTX_H__
