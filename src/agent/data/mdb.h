#ifndef __AGENT_DATA_MDB_H__
#define __AGENT_DATA_MDB_H__

#include "../../common/common.h"
#include "dbctx.h"
#include <lmdb.h>

class MDBCtx : public DBCtx {
 public:
  static MDBCtx* Create(const DBCtxOptions& options);
  ~MDBCtx() override;

  Iterator* NewIterator() override;
  bool Contain(const Slice& key) override;
  bool Get(const Slice& key, Slice* value) override;
  bool Put(const Slice& key, const Slice& value, Flags flags = DEFAULT) override;
  bool Begin() override;
  bool Commit() override;
  u64 Size() override;
  bool Error() const override {return error_code_;}
  bool NotFound() const override;
  bool KeyExist() const override;
  
 private:
  void CleanupEnv();
  const std::string& ErrorMsg();
  bool Init();

  int error_code_ = 0;
  std::string error_msg_;
  MDB_env* env_ = nullptr;
  MDB_txn* txn_ = nullptr;
  MDB_dbi dbi_ = 0;
};

#endif // __AGENT_DATA_MDB_H__
