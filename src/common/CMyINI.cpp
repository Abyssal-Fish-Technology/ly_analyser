#include "CMyINI.h"
#include "strings.h"

#define INIDEBUG

CMyINI::CMyINI() {} 
CMyINI::~CMyINI() {}

string &TrimString(string &str) {       
	string::size_type pos = 0;
  while (str.npos != (pos = str.find(" ")))
    str = str.replace(pos, pos + 1, "");
  return str;
}

bool CMyINI::ReadINI(string path) {       
	ifstream in_conf_file(path.c_str());
  if (!in_conf_file) return false;
  string str_line = "";
  string str_root = "";
  vector<ININode> vec_ini;
  while (getline(in_conf_file, str_line)) {       
 		string::size_type left_pos = 0;
    string::size_type right_pos = 0;
    string::size_type equal_div_pos = 0;
    string str_key = "";
    string str_value = "";
    if ((string::npos != (left_pos = str_line.find("["))) && (string::npos != (right_pos = str_line.find("]")))) {       
      str_root = str_line.substr(left_pos + 1, right_pos - left_pos - 1);
    }
                
    if (string::npos != (equal_div_pos = str_line.find("="))) {       
      str_key = str_line.substr(0, equal_div_pos);
      str_value = str_line.substr(equal_div_pos + 1, str_line.size() - equal_div_pos - 1);
      str_key = trim(str_key);
      str_value = trim(str_value);
    }
                
    if ((!str_root.empty()) && (!str_key.empty())) {       
      ININode ini_node(str_root, str_key, str_value);
      vec_ini.push_back(ini_node);
    }
  }
  in_conf_file.close();
  in_conf_file.clear();
        
  map<string, string> map_tmp;
  for (vector<ININode>::iterator itr = vec_ini.begin(); itr != vec_ini.end(); ++itr) {       
    map_tmp.insert(pair<string, string>(itr->root, ""));
 	}       //提取出根节点
  for (map<string, string>::iterator itr = map_tmp.begin(); itr != map_tmp.end(); ++itr) {
#ifdef INIDEBUG
   // cout << "根节点： " << itr->first << endl;
#endif  //INIDEBUG
    SubNode sn;
    for (vector<ININode>::iterator sub_itr = vec_ini.begin(); sub_itr != vec_ini.end(); ++sub_itr) {
      if (sub_itr->root == itr->first) {
#ifdef INIDEBUG
     //   cout << "键值对： " << sub_itr->key << "=" << sub_itr->value << endl;
#endif  //INIDEBUG
        sn.InsertElement(sub_itr->key, sub_itr->value);
      }
    }
    map_ini.insert(pair<string, SubNode>(itr->first, sn));
  }
  return true;
}

string CMyINI::GetValue(string root, string key) {
  map<string, SubNode>::iterator itr = map_ini.find(root);
  map<string, string>::iterator sub_itr = itr->second.sub_node.find(key);
 	if (!(sub_itr->second).empty())
    return sub_itr->second;
  return "";
}

