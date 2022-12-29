#ifndef __COMMON_IP_H__
#define __COMMON_IP_H__

#include "common.h"
#include <unordered_set>

using namespace std;

bool is_private_ip(const u32 ip);
std::string ipnum_to_ipstr(const u32 ipnum);
std::string ipnum_to_ipstr(const std::string& ipnum);
u32 ipstr_to_ipnum(const std::string& ipstr);
std::string proto_to_string(u16 proto);
bool valid_ip(string ipstr, string ip_segment);
std::string qtype_to_str(u16 qtype);
//ipv6
struct in6_addr ipstr_to_ipnum_v6(const string &ipstr);
std::string ipnum_to_ipstr_v6(struct in6_addr ipnum);
bool valid_ip_v6(string ipstr, string ip_segment);
std::string ipv6_zero_compress(const string &ipstr);

#endif // __COMMON_IP_H__
