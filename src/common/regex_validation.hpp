#ifndef _REGEX_VALIDATION_H_
#define _REGEX_VALIDATION_H_

// -lboost_regex
#include "boost/regex.hpp"

#define IP_PATTERN "^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}$"
#define CIDR_PATTERN "^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}(/(([12]?[0-9])|(3[0-2])))?$"

#define MO_X_PATTERN "^[Mm][Oo]_\\d+$"
#define IPV4 1
#define IPV6 2

////////////////////////////////////////////////////////////////////////////
/*static inline bool is_valid_cidr(const std::string& ip) {
  boost::regex pattern(CIDR_PATTERN, boost::regex::nosubs);
  boost::smatch m;
  return boost::regex_match(ip,m,pattern);
}*/

static inline bool is_valid_cidr(const std::string& ip) {
  boost::regex pattern(CIDR_PATTERN, boost::regex::nosubs);
  boost::smatch m;
  bool is_ipv4, is_ipv6;
  struct in6_addr in6;
  u32 slash;

  is_ipv4 = is_ipv6 = false;
  if ((is_ipv4 = boost::regex_match(ip, m, pattern))){
    is_ipv4 = true;
  } else {
    if ((slash = ip.find("/")) != std::string::npos){
      std::string ipv6 = ip.substr(0, slash);
      std::string mask_s = ip.substr(slash+1);
      u32 mask = atoi(mask_s.c_str());
      
      is_ipv6 = inet_pton(AF_INET6, ip.c_str(), (void *)&in6) ? ((mask < 0 || mask > 128) ? false : true) : false; 

    } else {
      is_ipv6 = inet_pton(AF_INET6, ip.c_str(), (void *)&in6) ? true : false;
    }
  }
  
  return (is_ipv4 | is_ipv6);
}

////////////////////////////////////////////////////////////////////////////
// static inline bool is_valid_ip(const std::string& ip) {
//   boost::regex pattern(IP_PATTERN, boost::regex::nosubs);
//   boost::smatch m;
//   return boost::regex_match(ip,m,pattern);
// }
static inline bool is_valid_ip(const std::string& ip) {
  boost::regex pattern(IP_PATTERN, boost::regex::nosubs);
  boost::smatch m;
  struct in6_addr in6;
  return boost::regex_match(ip,m,pattern) ? IPV4 : (inet_pton(AF_INET6, ip.c_str(), (void *)&in6) ? IPV6 : false);
}
////////////////////////////////////////////////////////////////////////////
static inline bool is_valid_mo_x(const std::string& str) {
  boost::regex pattern(MO_X_PATTERN, boost::regex::nosubs);
  boost::smatch m;
  return boost::regex_match(str,m,pattern);
}

#endif //_REGEX_VALIDATION_H_
