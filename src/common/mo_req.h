#ifndef __COMMON_MO_REQ_H__
#define __COMMON_MO_REQ_H__

#include "common.h"
#include "mo.pb.h"
#include <string>
#include <vector>
#include <boost/algorithm/string.hpp>

namespace cgicc {
class Cgicc;
}

namespace cppdb {
class statement;
class session;
}

namespace mo {
bool validate_request(MoReq* req);
void ParseMoReqFromUrlParams(cgicc::Cgicc& cgi, MoReq* req);
void stAddUpdateSet(std::string& str, const std::string s);
void stAddWhere(std::string& str, const std::string s);
void composeWhereSt(std::string& str, MoReq* req);
void bindWhereSt(cppdb::statement& st, MoReq* req);
std::string ipAddSuffix(const std::string& ip); //add "/32" if ip is not net
std::string genMoFilter(MoReq* req);	//generate filter for mo
std::vector<u32> getMoIDs(cppdb::session*, MoReq*);
std::vector<u32> getMoIDs(cppdb::session* sql, const u32 groupid, u32 devid = 0);
std::string filterMoIDsWithDevid(cppdb::session* sql, std::string moid, u32 devid = 0);
} // namespace mo

#endif //__COMMON_MO_REQ_H__

