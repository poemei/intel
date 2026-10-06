#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sync.h"
#define SYNC_JSON_MAX 32768

typedef struct
{
    char body[2048];
    size_t length;
} sync_response_t;

static long g_last_http_status = 0;
static CURLcode g_last_curl_code = CURLE_OK;
static char g_last_response_body[2048];

static size_t capture_response(char *p,size_t s,size_t n,void *u)
{
    sync_response_t *response=(sync_response_t *)u;
    size_t bytes=s*n;
    size_t available;

    if(!response||!p)return bytes;
    if(response->length>=sizeof(response->body)-1)return bytes;

    available=(sizeof(response->body)-1)-response->length;
    if(bytes>available)bytes=available;
    memcpy(response->body+response->length,p,bytes);
    response->length+=bytes;
    response->body[response->length]='\0';
    return s*n;
}
static int escape_json(const char *in,char *out,size_t cap){size_t i=0,o=0;if(!in||!out||!cap)return 0;while(in[i]){unsigned char ch=(unsigned char)in[i++];const char *e=NULL;if(ch=='"')e="\\\"";else if(ch=='\\')e="\\\\";else if(ch=='\n')e="\\n";else if(ch=='\r')e="\\r";else if(ch=='\t')e="\\t";if(e){size_t n=strlen(e);if(o+n>=cap)return 0;memcpy(out+o,e,n);o+=n;}else{if(ch<0x20||o+1>=cap)return 0;out[o++]=(char)ch;}}out[o]='\0';return 1;}
static int post_json(const char *url,const char *json)
{
    CURL *curl;
    struct curl_slist *headers=NULL;
    CURLcode rc;
    long status=0;
    sync_response_t response;

    memset(&response,0,sizeof(response));
    g_last_http_status=0;
    g_last_curl_code=CURLE_OK;
    g_last_response_body[0]='\0';

    curl=curl_easy_init();
    if(!curl)
    {
        g_last_curl_code=CURLE_FAILED_INIT;
        return 0;
    }

    headers=curl_slist_append(headers,"Content-Type: application/json");
    curl_easy_setopt(curl,CURLOPT_URL,url);
    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
    curl_easy_setopt(curl,CURLOPT_POSTFIELDS,json);
    curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,(long)strlen(json));
    curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,10L);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,20L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,capture_response);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,&response);
    curl_easy_setopt(curl,CURLOPT_USERAGENT,"Rictus-Intelligence/0.18");

    rc=curl_easy_perform(curl);
    if(rc==CURLE_OK)curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);

    g_last_curl_code=rc;
    g_last_http_status=status;
    snprintf(g_last_response_body,sizeof(g_last_response_body),"%s",response.body);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return rc==CURLE_OK&&status>=200&&status<300;
}

static int get_url(const char *url,sync_response_t *response)
{
    CURL *curl;
    CURLcode rc;
    long status=0;
    if(!url||!response)return 0;
    memset(response,0,sizeof(*response));
    g_last_http_status=0;g_last_curl_code=CURLE_OK;g_last_response_body[0]='\0';
    curl=curl_easy_init();
    if(!curl){g_last_curl_code=CURLE_FAILED_INIT;return 0;}
    curl_easy_setopt(curl,CURLOPT_URL,url);
    curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,10L);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,20L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,capture_response);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,response);
    curl_easy_setopt(curl,CURLOPT_USERAGENT,"Rictus-Intelligence/0.18");
    rc=curl_easy_perform(curl);
    if(rc==CURLE_OK)curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    g_last_curl_code=rc;g_last_http_status=status;
    snprintf(g_last_response_body,sizeof(g_last_response_body),"%s",response->body);
    curl_easy_cleanup(curl);
    return rc==CURLE_OK&&status>=200&&status<300;
}

static int json_string_after(const char *start,const char *key,char *out,size_t cap,const char **next)
{
    char needle[96];const char *p;size_t o=0;
    if(!start||!key||!out||cap<2)return 0;
    if(snprintf(needle,sizeof(needle),"\"%s\"",key)>=(int)sizeof(needle))return 0;
    p=strstr(start,needle);if(!p)return 0;p+=strlen(needle);
    while(*p&&(*p==' '||*p=='\t'||*p=='\r'||*p=='\n'))++p;
    if(*p++!=':')return 0;while(*p&&(*p==' '||*p=='\t'||*p=='\r'||*p=='\n'))++p;
    if(*p++!='\"')return 0;
    while(*p&&*p!='\"'){
        if(*p=='\\\\'&&p[1]){++p;if(*p=='n')out[o++]=' ';else if(*p=='r'||*p=='t')out[o++]=' ';else out[o++]=*p++;}
        else out[o++]=*p++;
        if(o+1>=cap)return 0;
    }
    if(*p!='\"')return 0;out[o]='\0';if(next)*next=p+1;return 1;
}

static int spool_has(const char *path,const char *assignment_id)
{
    FILE *f;char line[512],id[128];f=fopen(path,"r");if(!f)return 0;
    while(fgets(line,sizeof(line),f))if(sscanf(line,"%127[^\t]",id)==1&&strcmp(id,assignment_id)==0){fclose(f);return 1;}
    fclose(f);return 0;
}

static int assignment_status(rictus_intelligence_sync_t *s,const char *id,const char *status)
{
    char url[768],json[512],eid[192],estatus[64];
    if(!s||!id||!status||!escape_json(id,eid,sizeof(eid))||!escape_json(status,estatus,sizeof(estatus)))return 0;
    if(snprintf(url,sizeof(url),"%s/intelligence/assignment",s->endpoint)>=(int)sizeof(url))return 0;
    if(snprintf(json,sizeof(json),"{\"assignment_id\":\"%s\",\"status\":\"%s\"}",eid,estatus)>=(int)sizeof(json))return 0;
    return post_json(url,json);
}

int rictus_intelligence_sync_assignments(rictus_intelligence_sync_t *s,const char *spool_path)
{
    char url[768];sync_response_t response;const char *p;unsigned int accepted=0;
    if(!s||!s->endpoint[0]||!spool_path||!spool_path[0])return 0;
    if(snprintf(url,sizeof(url),"%s/intelligence/assignments?status=PENDING",s->endpoint)>=(int)sizeof(url))return 0;
    if(!get_url(url,&response))return 0;
    p=response.body;
    while((p=strstr(p,"\"assignment_id\""))!=NULL){
        char id[128],intel[128],type[64];const char *n=NULL;FILE *out;
        if(!json_string_after(p,"assignment_id",id,sizeof(id),&n))break;
        if(!json_string_after(n,"intelligence_id",intel,sizeof(intel),&n)){p+=15;continue;}
        if(!json_string_after(n,"assignment_type",type,sizeof(type),&n)){p+=15;continue;}
        if(strncmp(id,"ASN-",4)!=0||strncmp(intel,"INT-",4)!=0||(strcmp(type,"WATCH")!=0&&strcmp(type,"INVESTIGATE")!=0)){p=n;continue;}
        if(!spool_has(spool_path,id)){
            out=fopen(spool_path,"a");if(!out)return 0;
            if(fprintf(out,"%s\t%s\t%s\n",id,type,intel)<0||fflush(out)!=0||fclose(out)!=0)return 0;
        }
        if(assignment_status(s,id,"ACKNOWLEDGED"))++accepted;
        p=n;
    }
    (void)accepted;
    return 1;
}

int rictus_intelligence_sync_assignment_results(rictus_intelligence_sync_t *s,const char *results_path)
{
    FILE *in,*out;char temp[320],line[512],id[128],status[64];int ok=1;
    if(!s||!results_path||!results_path[0])return 0;
    in=fopen(results_path,"r");if(!in)return 1;
    if(snprintf(temp,sizeof(temp),"%s.tmp",results_path)>=(int)sizeof(temp)){fclose(in);return 0;}
    out=fopen(temp,"w");if(!out){fclose(in);return 0;}
    while(fgets(line,sizeof(line),in)){
        if(sscanf(line,"%127[^\t]\t%63[^\r\n]",id,status)!=2)continue;
        if(!assignment_status(s,id,status)){if(fputs(line,out)==EOF)ok=0;}
    }
    if(fflush(out)!=0)ok=0;fclose(in);if(fclose(out)!=0)ok=0;
    if(ok&&rename(temp,results_path)!=0)ok=0;if(!ok)remove(temp);return ok;
}

static int build_json(const rictus_intelligence_record_t *r,char *json,size_t cap){char id[128],title[2048],content[24576],source[512];int n;if(!r||!escape_json(r->id,id,sizeof(id))||!escape_json(r->item.title,title,sizeof(title))||!escape_json(r->item.content[0]?r->item.content:r->item.summary,content,sizeof(content))||!escape_json(r->item.source,source,sizeof(source)))return 0;n=snprintf(json,cap,"{\"intelligence_id\":\"%s\",\"title\":\"%s\",\"content\":\"%s\",\"source\":\"%s\",\"status\":\"ACTIVE\"}",id,title,content,source);return n>0&&(size_t)n<cap;}
static int queued(const char *path,const char *id){FILE *f;char line[128];f=fopen(path,"r");if(!f)return 0;while(fgets(line,sizeof(line),f)){line[strcspn(line,"\r\n")]='\0';if(strcmp(line,id)==0){fclose(f);return 1;}}fclose(f);return 0;}
static int queue_add(const char *path,const char *id){FILE *f;if(queued(path,id))return 1;f=fopen(path,"a");if(!f)return 0;if(fprintf(f,"%s\n",id)<0||fflush(f)!=0){fclose(f);return 0;}return fclose(f)==0;}
void rictus_intelligence_sync_init(rictus_intelligence_sync_t *s,const char *endpoint,const char *pending){if(!s)return;memset(s,0,sizeof(*s));if(endpoint)snprintf(s->endpoint,sizeof(s->endpoint),"%s",endpoint);if(pending)snprintf(s->pending_path,sizeof(s->pending_path),"%s",pending);}
static int send_record(rictus_intelligence_sync_t *s,const rictus_intelligence_record_t *r){char url[768],json[SYNC_JSON_MAX];if(snprintf(url,sizeof(url),"%s/intelligence/report",s->endpoint)>=(int)sizeof(url)||!build_json(r,json,sizeof(json)))return 0;return post_json(url,json);}
int rictus_intelligence_sync_report(rictus_intelligence_sync_t *s,const rictus_intelligence_record_t *r){if(!s||!r||!s->endpoint[0]||!s->pending_path[0])return 0;if(send_record(s,r))return 1;return queue_add(s->pending_path,r->id);}
int rictus_intelligence_sync_retry(rictus_intelligence_sync_t *s,const rictus_intelligence_record_store_t *store){FILE *in,*out;char temp[300],id[128];int ok=1;if(!s||!store||!s->pending_path[0])return 0;in=fopen(s->pending_path,"r");if(!in)return 1;if(snprintf(temp,sizeof(temp),"%s.tmp",s->pending_path)>=(int)sizeof(temp)){fclose(in);return 0;}out=fopen(temp,"w");if(!out){fclose(in);return 0;}while(fgets(id,sizeof(id),in)){const rictus_intelligence_record_t *r;id[strcspn(id,"\r\n")]='\0';if(!id[0])continue;r=rictus_intelligence_record_store_find(store,id);if(!r||!send_record(s,r)){if(fprintf(out,"%s\n",id)<0)ok=0;}}if(fflush(out)!=0)ok=0;fclose(in);if(fclose(out)!=0)ok=0;if(ok&&rename(temp,s->pending_path)!=0)ok=0;if(!ok)remove(temp);return ok;}


void rictus_intelligence_sync_last_error(long *http_status,int *curl_code,char *body,size_t body_size)
{
    if(http_status)*http_status=g_last_http_status;
    if(curl_code)*curl_code=(int)g_last_curl_code;
    if(body&&body_size)snprintf(body,body_size,"%s",g_last_response_body);
}

int rictus_intelligence_sync_all(rictus_intelligence_sync_t *s,const rictus_intelligence_record_store_t *store,size_t *sent,size_t *failed)
{
    size_t i;
    size_t sent_count=0;
    size_t failed_count=0;

    if(sent)*sent=0;
    if(failed)*failed=0;
    if(!s||!store||!s->endpoint[0]||!s->pending_path[0])return 0;

    for(i=0;i<store->count;i++)
    {
        const rictus_intelligence_record_t *r=&store->records[i];

        if(send_record(s,r))
        {
            sent_count++;
        }
        else
        {
            failed_count++;
            if(!queue_add(s->pending_path,r->id))
            {
                if(sent)*sent=sent_count;
                if(failed)*failed=failed_count;
                return 0;
            }
        }
    }

    if(sent)*sent=sent_count;
    if(failed)*failed=failed_count;
    return failed_count==0;
}
