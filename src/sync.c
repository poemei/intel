#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sync.h"
#define SYNC_JSON_MAX 32768

static size_t discard_response(char *p,size_t s,size_t n,void *u){(void)p;(void)u;return s*n;}
static int escape_json(const char *in,char *out,size_t cap){size_t i=0,o=0;if(!in||!out||!cap)return 0;while(in[i]){unsigned char ch=(unsigned char)in[i++];const char *e=NULL;if(ch=='"')e="\\\"";else if(ch=='\\')e="\\\\";else if(ch=='\n')e="\\n";else if(ch=='\r')e="\\r";else if(ch=='\t')e="\\t";if(e){size_t n=strlen(e);if(o+n>=cap)return 0;memcpy(out+o,e,n);o+=n;}else{if(ch<0x20||o+1>=cap)return 0;out[o++]=(char)ch;}}out[o]='\0';return 1;}
static int post_json(const char *url,const char *json){CURL *curl;struct curl_slist *headers=NULL;CURLcode rc;long status=0;curl=curl_easy_init();if(!curl)return 0;headers=curl_slist_append(headers,"Content-Type: application/json");curl_easy_setopt(curl,CURLOPT_URL,url);curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);curl_easy_setopt(curl,CURLOPT_POSTFIELDS,json);curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,(long)strlen(json));curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,10L);curl_easy_setopt(curl,CURLOPT_TIMEOUT,20L);curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,discard_response);curl_easy_setopt(curl,CURLOPT_USERAGENT,"Rictus-Intelligence/0.18");rc=curl_easy_perform(curl);if(rc==CURLE_OK)curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);curl_slist_free_all(headers);curl_easy_cleanup(curl);return rc==CURLE_OK&&status>=200&&status<300;}
static int build_json(const rictus_intelligence_record_t *r,char *json,size_t cap){char id[128],title[2048],content[24576],source[512];int n;if(!r||!escape_json(r->id,id,sizeof(id))||!escape_json(r->item.title,title,sizeof(title))||!escape_json(r->item.content[0]?r->item.content:r->item.summary,content,sizeof(content))||!escape_json(r->item.source,source,sizeof(source)))return 0;n=snprintf(json,cap,"{\"intelligence_id\":\"%s\",\"title\":\"%s\",\"content\":\"%s\",\"source\":\"%s\",\"status\":\"ACTIVE\"}",id,title,content,source);return n>0&&(size_t)n<cap;}
static int queued(const char *path,const char *id){FILE *f;char line[128];f=fopen(path,"r");if(!f)return 0;while(fgets(line,sizeof(line),f)){line[strcspn(line,"\r\n")]='\0';if(strcmp(line,id)==0){fclose(f);return 1;}}fclose(f);return 0;}
static int queue_add(const char *path,const char *id){FILE *f;if(queued(path,id))return 1;f=fopen(path,"a");if(!f)return 0;if(fprintf(f,"%s\n",id)<0||fflush(f)!=0){fclose(f);return 0;}return fclose(f)==0;}
void rictus_intelligence_sync_init(rictus_intelligence_sync_t *s,const char *endpoint,const char *pending){if(!s)return;memset(s,0,sizeof(*s));if(endpoint)snprintf(s->endpoint,sizeof(s->endpoint),"%s",endpoint);if(pending)snprintf(s->pending_path,sizeof(s->pending_path),"%s",pending);}
static int send_record(rictus_intelligence_sync_t *s,const rictus_intelligence_record_t *r){char url[768],json[SYNC_JSON_MAX];if(snprintf(url,sizeof(url),"%s/intelligence/report",s->endpoint)>=(int)sizeof(url)||!build_json(r,json,sizeof(json)))return 0;return post_json(url,json);}
int rictus_intelligence_sync_report(rictus_intelligence_sync_t *s,const rictus_intelligence_record_t *r){if(!s||!r||!s->endpoint[0]||!s->pending_path[0])return 0;if(send_record(s,r))return 1;return queue_add(s->pending_path,r->id);}
int rictus_intelligence_sync_retry(rictus_intelligence_sync_t *s,const rictus_intelligence_record_store_t *store){FILE *in,*out;char temp[300],id[128];int ok=1;if(!s||!store||!s->pending_path[0])return 0;in=fopen(s->pending_path,"r");if(!in)return 1;if(snprintf(temp,sizeof(temp),"%s.tmp",s->pending_path)>=(int)sizeof(temp)){fclose(in);return 0;}out=fopen(temp,"w");if(!out){fclose(in);return 0;}while(fgets(id,sizeof(id),in)){const rictus_intelligence_record_t *r;id[strcspn(id,"\r\n")]='\0';if(!id[0])continue;r=rictus_intelligence_record_store_find(store,id);if(!r||!send_record(s,r)){if(fprintf(out,"%s\n",id)<0)ok=0;}}if(fflush(out)!=0)ok=0;fclose(in);if(fclose(out)!=0)ok=0;if(ok&&rename(temp,s->pending_path)!=0)ok=0;if(!ok)remove(temp);return ok;}


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
