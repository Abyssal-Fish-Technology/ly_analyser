#ifndef _POLICY_HPP_
#define _POLICY_HPP_

#include "policy.pb.h"
#include <boost/algorithm/string.hpp>

namespace policy {

static inline PolicyName get_policy_name(const std::string& str) {
	std::string up = boost::to_upper_copy(str);

	if (up=="MO")
		return MO;
	if (up=="BLACK")
		return BLACK;
	if (up=="WHITE")
		return WHITE;
	if (up=="SCAN")
		return SCAN;
	if (up=="SRV")
		return SRV;
	if (up=="I_PORT_SCAN")
		return I_PORT_SCAN;
	if (up=="I_IP_SCAN")
		return I_IP_SCAN;
	if (up=="I_SRV")
		return I_SRV;
	if (up=="POP")
		return POP;
	if (up=="SUS")
		return SUS;
	if (up=="DNS_B")
		return DNS_B;
	if (up=="DNS_W")
		return DNS_W;
	if (up=="DNS_D")
		return DNS_D;
	if (up=="DNS_L")
		return DNS_L;

	return INVALID;
}

} // namespace policy

#endif // _POLICY_HPP_
