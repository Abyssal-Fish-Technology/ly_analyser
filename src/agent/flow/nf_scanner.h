#ifndef __AGENT_NF_SCANNER_H
#define __AGENT_NF_SCANNER_H

#include "../../common/topn.pb.h"

using namespace std;
using topn::TopnRecord;
using topn::TopnReq;
using topn::TopnResponse;

struct cache_pair {
  TopnReq req;
  TopnResponse rsp;
};

class NFScanner {
 public:
  NFScanner(const std::string& flow_dir, const std::string& flow_file_prefix)
    : flow_dir_(flow_dir), flow_file_prefix_(flow_file_prefix) {}

  bool ScanFlowFiles(const topn::TopnReq& req, topn::TopnResponse* rsp,
                     std::string* error);
  struct cache_pair ScanFlowFilesCache(const TopnReq& req, TopnResponse& rsp, string* error);

 private:
  const std::string flow_dir_;
  const std::string flow_file_prefix_;
};

#endif // __AGENT_NF_SCANNER_H
