#ifndef __AGENT_COMM_H__
#define __AGENT_COMM_H__

#include "../common/common.h"
#include "../common/config.pb.h"

class ControllerStub {
 public:
  explicit ControllerStub(const Config& cfg);
  bool Call(const std::string& cmd, const std::string& req, std::string* rsp = NULL);
 private:
  const Config& cfg_;
};

#endif // __AGENT_COMM_H__
