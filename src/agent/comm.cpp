#include "comm.h"
#include "../common/http.h"
#include "../common/config.pb.h"

using namespace std;

ControllerStub::ControllerStub(const Config& cfg) : cfg_(cfg) {}

bool ControllerStub::Call(const string& cmd_path,  const std::string& req, std::string* rsp)
{
  string url("http://" + cfg_.controller().host() + ':' +
             cfg_.controller().port() + cmd_path);
  stringstream s;
  if (req.empty()) {
    http_get(url, (ostream *)&s);
  } else {
    http_post(url, req, &s);
  }
  if (rsp) *rsp = s.str();
  return true;
}
