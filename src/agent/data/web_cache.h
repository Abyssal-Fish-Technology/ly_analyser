#ifndef __AGENT_WEB_CACHE_H__
#define __AGENT_WEB_CACHE_H__

#include <memory>
#include "../../common/common.h"
#include "dbctx.h"
#include "tsdb.h"

namespace google {
namespace protobuf {
class Message;
}
}

class WebCache {
 public:
  WebCache(DBBuilder* builder, const std::string& prefix = std::string())
    : builder_(builder), prefix_(prefix) {}

  std::string Get(const std::string& key);
  std::string Get(u32 time, const std::string& key);
  bool Get(const google::protobuf::Message& key,
           google::protobuf::Message* value);
  bool Get(u32 time, const google::protobuf::Message& key,
           google::protobuf::Message* value);
  bool Update(const std::string& key, const std::string& value);
  bool Update(u32 time, const std::string& key, const std::string& value);
  bool Update(const google::protobuf::Message& key,
              const google::protobuf::Message& value);
  bool Update(u32 time, const google::protobuf::Message& key,
              const google::protobuf::Message& value);

 private:
  class TSDBCache {
   public:
    explicit TSDBCache(DBBuilder* builder)
      : tsdb_(new TSDB(builder, "web_cache")) {}
    std::string Get(u32 time, const std::string& key);
    bool Put(u32 time, const std::string& key, const std::string& value);

   private:
    std::unique_ptr<TSDB> tsdb_;
  };

  std::string InternalGet(const std::string& key);
  std::string InternalGet(u32 time, const std::string& key);
  bool InternalUpdate(const std::string& key, const std::string& value);
  bool InternalUpdate(u32 time, const std::string& key, const std::string& value);
  
  DBBuilder* builder_;
  std::string prefix_;
  std::unique_ptr<TSDBCache> tsdb_cache_;
};

#endif // __AGENT_WEB_CACHE_H__
