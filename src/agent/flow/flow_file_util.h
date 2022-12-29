#ifndef AGENT_FLOW_FILE_UTIL_H
#define AGENT_FLOW_FILE_UTIL_H

#include <string>
#include "../common/common.h"
#include "../common/config.pb.h"

std::string GetFlowDir(u32 devid);
std::string GetFlowFilePrefix(const config::Config& cfg, u32 devid);

#endif // AGENT_FLOW_FILE_UTIL_H
