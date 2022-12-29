#include "policy.h"

#include <memory>

using namespace std;
using config::Config;
using policy::PolicyData;
using policy::PolicyIndex;
using policy::PolicyName;

Policy* Policy::Create(const Config* config, const string& label) {
  if (!config || label.empty()) return nullptr;
  unique_ptr<Policy> policy(new Policy(config));
  policy->label_ = label;

  // Find policy index with exact label.
  for (const auto& index : config->policy_index()) {
    for (const auto& data_label : index.policy_data_label()) {
      if (data_label == label) {
        policy->index_ = &index;
        break;   // found
      }
    }
    if (policy->index_) break; // found
  }
  if (!policy->index_) return nullptr;

  // Find policy data with exact label.
  for (const auto& data : config->policy_data()) {
    if (data.label() == label) {
      policy->data_ = &data;
      break; // found
    }
  }
  return policy.release();
}

Policy* Policy::Create(const Config* config, const PolicyName type) {
  if (!config) return nullptr;
  unique_ptr<Policy> policy(new Policy(config));

  // Find policy index with exact type.
  for (const auto& index : config->policy_index()) {
    if (index.policy() == type) {
      if (index.policy_data_label_size() == 0) continue; // must have at least one label.
      policy->index_ = &index;  // Found first with matching type.
      policy->label_ = index.policy_data_label(0);
      break;
    }
  }
  if (!policy->index_) return nullptr;

  // Find policy data with exact type.
  for (const auto& data : config->policy_data()) {
    if (data.label() == policy->label_) {
      policy->data_ = &data;
      break; // found
    }
  }
  return policy.release();
}

