#ifndef __COMMON_ASSET_H__
#define __COMMON_ASSET_H__

#include <string>
#include <unordered_set>

using namespace std;

void LoadAssetFromFile(const string& file_name, std::unordered_set<string>* ips);

#endif 
