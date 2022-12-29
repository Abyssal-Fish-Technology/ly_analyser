#ifndef __COMMON_HTTP_H__
#define __COMMON_HTTP_H__

#include "common.h"

void http_get(const std::string& url, std::ostream* stream);
std::string http_get(const std::string& url);
void http_post(const std::string& url, const std::string& content, std::ostream* rsp = NULL);
void http_put(const std::string& url, const std::string& content, std::ostream* rsp = NULL);
void http_req(const std::string& url, const std::string& method, 
              const void* buf, size_t size, std::ostream* stream = NULL);

#endif // __COMMON_HTTP_H__
