#include "http.h"
#include "log.h"
#include <iostream>
#include <curl/curl.h>

using namespace std;

////////////////////////////////////////////////////////////////////////////
static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  ((ostream*)stream)->write((const char*)ptr, size*nmemb);
  return size*nmemb;
}

////////////////////////////////////////////////////////////////////////////
/*static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  ((istream*)stream)->read((char *)ptr, size*nmemb);
  return size*nmemb;
}*/

////////////////////////////////////////////////////////////////////////////
string http_get(const string& url)
{
  stringstream s;
  http_get(url, &s);
  return s.str();
}

////////////////////////////////////////////////////////////////////////////
void http_get(const string& url, ostream* stream)
{
  http_req(url, "GET", NULL, 0, stream);
}

////////////////////////////////////////////////////////////////////////////
void http_put(const string& url, const string& content, ostream* rsp)
{
  http_req(url, "PUT", content.c_str(), content.size(), rsp);
}

////////////////////////////////////////////////////////////////////////////
void http_post(const string& url, const string& content, ostream* rsp)
{
  http_req(url, "POST", content.c_str(), content.size(), rsp);
}

////////////////////////////////////////////////////////////////////////////
void http_req(const string& url, const string& method, const void* buf,
              size_t size, ostream* stream)
{
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    if (!curl) return;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    if (method == "GET") {
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    } else if (method == "PUT") {
      curl_easy_setopt(curl, CURLOPT_PUT, 1L);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, size);
    } else if (method == "POST") {
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, size);
    }
    if (stream) {
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, stream);
    }
    //curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    //curl_easy_setopt(curl, CURLOPT_READDATA, stream);
    //curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)size);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
       log_err("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
}

