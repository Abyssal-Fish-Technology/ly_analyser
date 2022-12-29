#include "flow_file_util.h"

#include "../common/log.h"
#include "define.h"

using namespace std;
using config::Config;

////////////////////////////////////////////////////////////////////////////
string GetFlowDir(u32 devid) {
  return AGENT_FLOW_DIR"/" + to_string(devid);
}

////////////////////////////////////////////////////////////////////////////
string GetFlowFilePrefix(const Config& cfg, u32 devid) {
  for (const auto& dev : cfg.dev()) {
    if (dev.id() == devid) {
      const string& flowtype = dev.flowtype();
      if (flowtype == "netflow") {
        if (DEBUG) {
          log_info("Dev %u has flowtype:%s. Use flow file prefix \"%s\"\n",
                   devid, flowtype.c_str(), "nfcapd.");
        }
        return "nfcapd.";
      } else if (flowtype == "sflow") {
        if (DEBUG) {
          log_info("Dev %u has flowtype:%s. Use flow file prefix \"%s\"\n",
                   devid, flowtype.c_str(), "sfcapd.");
        }
        return "sfcapd.";
      } else {
        if (DEBUG) {
          log_info("Dev %u has unknow flowtype:%s. Use default flow file "
                   "prefix \"nfcapd.\"\n", devid, flowtype.c_str());
        }
        return "nfcapd.";
      }
    }
  }
  if (DEBUG) {
    log_info("Dev %u not found. Something is wrong. Use default flow file "
             "prefix \"nfcapd.\"\n", devid);
  }
  return "nfcapd.";
}

//
