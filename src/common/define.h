#define TMP_DIR         "tmp"
#define IPLIST_FILE	"data/iplist"
#define MONHOSTSNMP_FILE        "data/monhostsnmp"
#define SERVER_WORK_DIR	"/Server"
#define CALL_ALERT_MAIL "bin/alert.php"
#define FN_ALERT_CONFIG "data/tmp_alert_config"
#define FN_HIS          "data/tmp_his"

#define AGENT_WORK_DIR	"/Agent"
#define AGENT_TMP_DIR   AGENT_WORK_DIR"/tmp"
#define AGENT_DATA_DIR	AGENT_WORK_DIR"/data"
#define AGENT_FLOW_DIR	AGENT_WORK_DIR"/flow"
#define DEV_FILE				AGENT_DATA_DIR"/device"
#define CC_FILE					AGENT_DATA_DIR"/cc"
#define MONHOST_FILE		AGENT_DATA_DIR"/monhost"

#ifndef AUTH_START_TIME
#	define AUTH_START_TIME 66600	// UTC 18:30, CST 02:30
#endif

#ifndef AUTH_VALID_TIME
#	define AUTH_VALID_TIME 86400 // 24 hours
#endif

#ifndef AUTH_TOLERANCE_TIME
#	define AUTH_TOLERANCE_TIME 180 // 3 minutes
#endif
