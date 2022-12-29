
int CreateRRDBs (char *path, time_t when);

int RRD_StoreDataRow(char *path, char *iso_time, data_row *row);

data_row *RRD_GetDataRow(char *path, time_t when);

time_t	RRD_LastUpdate(char *path);

time_t  RRD_First(char *path);

time_t ISO2UNIX(char *tstring);
