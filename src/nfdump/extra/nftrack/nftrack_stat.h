

typedef struct data_element_s {
	uint64_t		type[3];	// 0 - flows 1 - packets 2- bytes
} data_element;

typedef struct data_row_s {
	data_element	proto[2];	// 0 - tcp 1 - udp
} data_row;

// to be used as index
enum { tcp = 0, udp };
enum { flows = 0, packets, bytes };

int InitStat(char *path);

int CloseStat(void);

int InitStatFile(void);

data_row *GetStat(void);

void ClearStat(void);

int UpdateStat(data_row *row, time_t when);

void Generate_TopN(data_row *row, int n, int scale, time_t when, int output_mode, char *wfile);

int Lister(data_row *row);
