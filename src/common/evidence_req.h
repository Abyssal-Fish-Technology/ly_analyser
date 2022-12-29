#ifndef __COMMON_EVIDENCE_REQ_H__
#define __COMMON_EVIDENCE_REQ_H__

#include "common.h"
#include "evidence.pb.h"
#include <boost/algorithm/string.hpp>
#include <string>

namespace cgicc {
class Cgicc;
}

namespace evidence {
bool validate_request(EvidenceReq* req);
bool ParseEvidenceReqFromCmdline(int argc, char*argv[], EvidenceReq* req);
bool ParseEvidenceReqFromUrlParams(cgicc::Cgicc& cgi, EvidenceReq* req);
} // namespace evidence

#endif //__COMMON_EVIDENCE_REQ_H__

