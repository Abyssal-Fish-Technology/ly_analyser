#ifndef __TOPN_PARAM_H__
#define __TOPN_PARAM_H__

#include "csv.hpp"
#include "common.h"
#include "config.h"
#include "log.h"
#include "config.pb.h"

#include <vector>
#include <string>

namespace config {
class Config;
}

std::vector<u32> getMoIds(const config::Config* cfg, u32 groupid, u32 devid);
std::string parse_include_exclude_params(const std::string& list, const config::Config* cfg, u32 groupid, u32 devid);

#endif
