#include "common.h"
#include "ini.h"
#include "strings.h"
#include "log.h"

using namespace std;

bool Ini::LoadFromFile(const string& ini_file)
{
	ifstream in(ini_file, ios_base::in);
	if (in.fail())
	{
		log_err("Unable to read ini from %s\n", ini_file.c_str());
		return false;
	}
  ini_file_ = ini_file;

	while(!in.eof( ))
	{
    string line;
		std::getline(in, line);
    trim(line);
    
		// ignore blank lines and comments
		if (line.empty() || line[0] == '#') continue;
		auto pos = line.find("=");
		if (pos == string::npos) continue;
    auto key = line.substr(0, pos);
    key = trim(key);
    if (key.empty()) continue;
    auto value  = line.substr(pos + 1);
    map_[key] = trim(value);
	}
  return true;
}

bool Ini::SaveToFile() {
  if (ini_file_.empty()) {
    log_err("Ini file name is empty.");
    return false;
  }
  return SaveToFile(ini_file_);
}

bool Ini::SaveToFile(const string& ini_file)
{
	ofstream out(ini_file);
	if (out.fail())
	{
    log_err("Unable to write ini to %s\n", ini_file.c_str());
		return false;
	}
  if (ini_file_.empty()) ini_file_ = ini_file;
  for (auto it = map_.cbegin(); it != map_.cend(); ++it)
      out << it->first << '=' << it->second << '\n';
  out.flush();
  return true;
}

void Ini::Set(const string& key, s64 value) {
  Set(key, to_string(value));
}

void Ini::Set(const string& key, string value) {
  map_[key] = value;
}

s32 Ini::GetInt(const string& key, s32 default_value) {
  return GetInt64(key, default_value);
}

s32 Ini::GetInt(const string& key) {
  return GetInt64(key);
}

u32 Ini::GetUInt(const string& key, u32 default_value) {
  return GetUInt64(key, default_value);
}

u32 Ini::GetUInt(const string& key) {
  return GetUInt64(key);
}

s64 Ini::GetInt64(const string& key, s64 default_value) {
  auto it = map_.find(key);
  if (it == map_.end())
    return default_value;
  return GetInt64(key);
}

s64 Ini::GetInt64(const string& key) {
  s64 rv;
  istringstream(map_[key]) >> rv;
  return rv;
}

u64 Ini::GetUInt64(const string& key, u64 default_value) {
  auto it = map_.find(key);
  if (it == map_.end())
    return default_value;
  return GetUInt64(key);
}

u64 Ini::GetUInt64(const string& key) {
  u64 rv;
  istringstream(map_[key]) >> rv;
  return rv;
}

const string& Ini::Get(const string& key, const string& default_value) {
  auto it = map_.find(key);
  if (it == map_.end())
    return default_value;
  else 
    return map_[key];
}

const string& Ini::Get(const string& key) {
  return map_[key];
}

void Ini::Delete(const string& key)
{
	map_.erase(key);
}

void Ini::Clear() {
  map_.clear();
}

