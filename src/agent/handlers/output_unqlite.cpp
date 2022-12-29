#include <stdio.h>  /* puts() */
#include <stdlib.h> /* exit() */
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* Make sure this header file is available.*/
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "asset_key_value.h"
#include "../define.h"
#include "../data/unqlite.h"
#include "../../common/datetime.h"
/* Assume UNIX */
#include <unistd.h>

using namespace std;

#define TYPE_ASSET_IP    1
#define TYPE_ASSET_URL   2
#define TYPE_ASSET_HOST  3
#define TYPE_ASSET_SRV   4

#ifndef STDOUT_FILENO
#define STDOUT_FILENO   1
#endif

ofstream outfile;

/*
 * Extract the database error log and exit.
 */
static void Fatal(unqlite *pDb,const char *zMsg){
    if( pDb ){
        const char *zErr;
        int iLen = 0; /* Stupid cc warning */

        /* Extract the database error log */
        unqlite_config(pDb,UNQLITE_CONFIG_ERR_LOG,&zErr,&iLen);
        if( iLen > 0 ){
            /* Output the DB error log */
            puts(zErr); /* Always null termniated */
        }
    }else{
        if( zMsg ){
            puts(zMsg);
        }
    }
    /* Manually shutdown the library */
    unqlite_lib_shutdown();
    /* Exit immediately */
    exit(0);
}

static int TypeTransfer(const char* str){
    if (!strcasecmp(str,"asset_ip"))
        return TYPE_ASSET_IP;
    else if (!strcasecmp(str,"asset_url"))
        return TYPE_ASSET_URL;
    else if (!strcasecmp(str,"asset_host"))
        return TYPE_ASSET_HOST;
    else if (!strcasecmp(str,"asset_srv"))
        return TYPE_ASSET_SRV;
    else
        return 0;
}

static char* IPTransfer(const u32* ipnum){

    if (ipnum[1]==0 && ipnum[2]==0 && ipnum[3]==0){//ipv4
        struct sockaddr_in in;
        char *ipstr = (char *)malloc(20);
        in.sin_addr.s_addr = htonl(ipnum[0]);
        ipstr = inet_ntoa(in.sin_addr);
        return ipstr;
    } else {//ipv6
        struct in6_addr *ipnum6 = (struct in6_addr *)ipnum;
        char *ipstr = (char *)malloc(50);
        int i = 0;
        for (; i < 4; i++)
            ipnum6->s6_addr32[i] = htonl(ipnum6->s6_addr32[i]);
        inet_ntop(AF_INET6, ipnum6, ipstr, 50);
        return ipstr;
    }
}



static int KeyConsumerCallback(const void *pData,unsigned int nDatalen,void *pUserData /* Unused */){

    u32 *asset_type = (u32 *)pUserData;

    switch(*asset_type){
        case TYPE_ASSET_IP:{
            IPKey_t *asset_key = (IPKey_t *)pData;

            outfile<<IPTransfer(asset_key->ip)<<",";
            break;
        }
        case TYPE_ASSET_URL:{
            UrlKey_t *asset_key = (UrlKey_t *)pData;

            outfile<<IPTransfer(asset_key->ip)<<","
                    <<asset_key->port<<","
                    <<asset_key->url<<","
                    <<asset_key->retcode<<",";
            break;
        }
        case TYPE_ASSET_HOST:{
            HostKey_t *asset_key = (HostKey_t *)pData;

            outfile<<IPTransfer(asset_key->ip)<<","
                    <<asset_key->port<<","
                    <<asset_key->host<<",";
            break;
        }
        case TYPE_ASSET_SRV:{
            SrvKey_t *asset_key = (SrvKey_t *)pData;

            outfile<<IPTransfer(asset_key->ip)<<","
                    <<asset_key->proto<<","
                    <<asset_key->port<<","
                    <<asset_key->srv_mark<<",";
            break;
        }
        default:
            return UNQLITE_ABORT;
    }
    return UNQLITE_OK;
}

static int DataConsumerCallback(const void *pData,unsigned int nDatalen,void *pUserData /* Unused */){
    u32 *asset_type = (u32 *)pUserData;

    switch(*asset_type){
        case TYPE_ASSET_IP:
        case TYPE_ASSET_URL:
        case TYPE_ASSET_HOST:{
            IPValue_t *asset_value = (IPValue_t *)pData;

            outfile<<asset_value->first<<","
                    <<asset_value->last<<","
                    <<asset_value->flows<<","
                    <<asset_value->pkts<<","
                    <<asset_value->bytes;
            break;
        }
        case TYPE_ASSET_SRV:{
            SrvValue_t *asset_value = (SrvValue_t *)pData;

            // outfile<<",\"app_proto\":\""<<asset_value->app_proto<<"\""
            //         <<",\"first\":"<<asset_value->first
            //         <<",\"last\":"<<asset_value->last
            //         <<",\"flows\":"<<asset_value->flows
            //         <<",\"pkts\":"<<asset_value->pkts
            //         <<",\"bytes\":"<<asset_value->bytes<<"}";

            outfile<<asset_value->app_proto<<","
                    <<asset_value->srv_type<<","
                    <<asset_value->srv_name<<","
                    <<asset_value->srv_info1<<","
                    <<asset_value->srv_info2<<","
                    <<asset_value->first<<","
                    <<asset_value->last<<","
                    <<asset_value->flows<<","
                    <<asset_value->pkts<<","
                    <<asset_value->bytes;

            break;
        }
        default:
            return UNQLITE_ABORT;
    }
    return UNQLITE_OK;
}

int main(int argc,char *argv[]){
    unqlite *pDb;               /* Database handle */
    unqlite_kv_cursor *pCur;    /* Cursor handle */
    int rc;

    string file_path, input_file_path, output_file_path;
    u32 start_time = 0, end_time = 0;
    string asset_type_str;
    u32 asset_type = 0, devid = 0;
    char c;
    while ((c = getopt(argc, argv, "i:s:e:t:o:")) != -1){
        if (optarg==NULL)
            continue;

        switch (c){
            case 'i':
                devid = atoi(optarg);
                break;
            case 's':{
                start_time = atoi(optarg);
                break;
            }
            case 'e':{
                end_time = atoi(optarg);
                break;
            }
            case 't':
                asset_type_str = optarg;//asset_ip,asset_srv,asset_host,asset_url
                asset_type = TypeTransfer(optarg);
                break;
            case 'o':
                output_file_path = optarg;
                break;
            default:
                printf("arguments fault.\n");
                return 0;
        } // switch
    } // while getopt()

    if(!output_file_path.length()){
        output_file_path = "/root/middle_data_"+asset_type_str+".json";
    }

    outfile.open(output_file_path);

    switch(asset_type){
        case TYPE_ASSET_IP:{
            outfile<<"ip,first,last,flows,pkts,bytes\n";
            break;
        }
        case TYPE_ASSET_URL:{
            outfile<<"ip,port,url,retcode,first,last,flows,pkts,bytes\n";
            break;
        }
        case TYPE_ASSET_HOST:{
            outfile<<"ip,port,host,first,last,flows,pkts,bytes\n";
            break;
        }
        case TYPE_ASSET_SRV:{
            outfile<<"ip,proto,port,srv_mark,app_proto,srv_type,srv_name,srv_info1,srv_info2,first,last,flows,pkts,bytes\n";
            break;
        }
    }

    while( (start_time/3600) <= (end_time/3600) ){
        u32 timestamp = start_time;

        std::ostringstream buffer;
        buffer<<AGENT_DB_ROOT<<"/"<<datetime::format_date(timestamp)<<"/"
            <<datetime::format_timestamp(timestamp)<<"_"<<devid<<"_"<<asset_type_str;
        file_path =  buffer.str();

        /* Open our database */
        rc = unqlite_open(&pDb,file_path.c_str(),UNQLITE_OPEN_READONLY);
        if( rc != UNQLITE_OK ){
            Fatal(0,"Out of memory");
        }
        
        /* Allocate a new cursor instance */
        rc = unqlite_kv_cursor_init(pDb,&pCur);
        if( rc != UNQLITE_OK ){
            Fatal(0,"Out of memory");
        }
        /* Point to the first record */
        unqlite_kv_cursor_first_entry(pCur);
        /* To point to the last record instead of the first, simply call [unqlite_kv_cursor_last_entry()] as follows */
        
        /* unqlite_kv_cursor_last_entry(pCur); */
        // u32 first_entry = 1;
            
        /* Iterate over the entries */
        while( unqlite_kv_cursor_valid_entry(pCur) ){
            // if(first_entry){
            //     first_entry = 0;
            // } else {
            //     outfile<<",\n";
            // }

            int nKeyLen;
            unqlite_int64 nDataLen; 
            
            /* Consume the key */
            unqlite_kv_cursor_key(pCur,0,&nKeyLen); /* Extract key length */
            // printf("\nKey(%u):",nKeyLen);
            // unqlite_kv_cursor_key_callback(pCur,KeyConsumerCallback,asset_type);argc > 1 ? argv[1]
            unqlite_kv_cursor_key_callback(pCur,KeyConsumerCallback,(void *)&asset_type);
                
            /* Consume the data */
            unqlite_kv_cursor_data(pCur,0,&nDataLen);
            // printf("\t==>\tData(%lld):",nDataLen);

            unqlite_kv_cursor_data_callback(pCur,DataConsumerCallback,(void *)&asset_type);

            outfile<<"\n";
            /* Point to the next entry */
            unqlite_kv_cursor_next_entry(pCur);

            /*unqlite_kv_cursor_prev_entry(pCur); //If [unqlite_kv_cursor_last_entry(pCur)] instead of [unqlite_kv_cursor_first_entry(pCur)] */
        }
        /* Finally, Release our cursor */
        unqlite_kv_cursor_release(pDb,pCur);
        
        /* Auto-commit the transaction and close our database */
        unqlite_close(pDb);
        start_time += 3600;
    }

    return 0;
}
