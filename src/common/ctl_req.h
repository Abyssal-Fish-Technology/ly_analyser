#ifndef __COMMON_CTL_REQ_H__
#define __COMMON_CTL_REQ_H__

#include "common.h"
#include "ctl.pb.h"
#include <boost/algorithm/string.hpp>
#include <string>

namespace cgicc {
class Cgicc;
}

namespace ctl {
bool validate_request(CtlReq* req);
bool ParseCtlReqFromUrlParams(cgicc::Cgicc& cgi, CtlReq* req);
std::string GetReqTypeStr(CtlReq* req);
std::string GetReqOpStr(CtlReq* req);
}

#endif
