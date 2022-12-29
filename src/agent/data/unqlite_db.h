#ifndef __AGENT_DATA_UNQLITE_DB_H__
#define __AGENT_DATA_UNQLITE_DB_H__

#include <vector>
#include <unqlite.h>
#include "../../common/common.h"
#include "dbctx.h"

class unqlite;

class UnqliteCtx : public DBCtx {
 public:
  static UnqliteCtx* Create(const DBCtxOptions& options);
  ~UnqliteCtx() override;

  Iterator* NewIterator() override;
  bool Contain(const Slice& key) override { return Get(key, nullptr); }
  bool Get(const Slice& key, Slice* value) override;
  bool Put(const Slice& key, const Slice& value, Flags flags = DEFAULT) override;
  bool Begin() override {return false;}
  bool Commit() override;
  u64 Size() override { return 0; }
  bool Error() const override;
  bool NotFound() const override;
  bool KeyExist() const override { return false; }
  
 private:
  explicit UnqliteCtx(const DBCtxOptions& options, unqlite* db);
  UnqliteCtx() = delete;

  unqlite* db_;
  std::string value_;
  int error_code_;

  friend class UnqliteIterator;
};

#endif // __AGENT_DATA_UNQLITE_DB_H__
