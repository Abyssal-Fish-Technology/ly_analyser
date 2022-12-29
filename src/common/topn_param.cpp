#include "policy.hpp"
#include "policy.pb.h"
#include "topn_param.h"

using namespace std;
using namespace policy;


vector<u32> getMoIds(const config::Config* cfg, u32 groupid, u32 devid) {
  vector<u32> ids;
  for (auto mo_rec: cfg->mo() ) {
		if (groupid == 0) {
			if (devid > 0) {
    		if (mo_rec.devid() == devid || !mo_rec.has_devid()) {
      		ids.push_back(mo_rec.id());
    		}
			} else 
				ids.push_back(mo_rec.id());
		} else {
			if (devid > 0) {
				if ((mo_rec.devid() == devid || !mo_rec.has_devid()) && mo_rec.mogroupid() == groupid) {
					ids.push_back(mo_rec.id());
				}
			} else {
				if (mo_rec.mogroupid() == groupid) 
					ids.push_back(mo_rec.id());
			}
		}
  }
  return ids;
}

string parse_include_exclude_params(const string& list, const config::Config* cfg, u32 groupid, u32 devid) {
  vector<string> vec, res;
  vector<u32> mo_x;
  string s;
  csv::fill_vector_from_line(vec, list);
  for (vector<std::string>::iterator it = vec.begin(); it!=vec.end(); it++) {
    PolicyName pn = get_policy_name(*it);
    switch (pn) {
      case MO: {  // if 'mo' specified, get 'mo_x' from database and replace 'mo' with them
        if (mo_x.size()==0) {
          mo_x = getMoIds(cfg, groupid, devid);
          for (vector<u32>::iterator it = mo_x.begin(); it!=mo_x.end(); it++) {
            res.push_back("mo_" + to_string(*it));
          }
        }
       break;
      }
      default: res.push_back(*it);break;
    }
  }

  for (vector<string>::iterator it = res.begin(); it!=res.end(); it++){
    if (s.size()>0) {
      s += ",";
      s += *it;
    }
    else
      s = *it;
  }
  return s;
}

