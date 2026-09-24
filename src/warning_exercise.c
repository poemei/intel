#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include "win_compat_posix.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "warning_exercise.h"
#define EXERCISES "intelligence.warning-exercises"
#define PRIVATE_DELIVERED "intelligence.warning-exercises.private-delivered"
#define CHANNEL_DELIVERED "intelligence.warning-exercises.channel-delivered"
#define ACKS "intelligence.warning-exercises.ack"
static unsigned long hash_text(const char *s){unsigned long h=2166136261UL;while(s&&*s){h^=(unsigned char)*s++;h*=16777619UL;}return h;}
static void timestamp(char out[32]){SYSTEMTIME t;GetSystemTime(&t);sprintf_s(out,32,"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);}
static int listed(const char *path,const char *id){FILE *f=NULL;char line[160],found[32];if(fopen_s(&f,path,"r")!=0||!f)return 0;while(fgets(line,sizeof(line),f))if(sscanf(line,"%31s",found)==1&&_stricmp(found,id)==0){fclose(f);return 1;}fclose(f);return 0;}
const rictus_warning_exercise_t *rictus_warning_exercise_find(const rictus_warning_exercise_store_t *s,const char *id){size_t i;if(!s||!id)return NULL;for(i=0;i<s->count;++i)if(_stricmp(s->records[i].id,id)==0)return &s->records[i];return NULL;}
int rictus_warning_exercise_load(rictus_warning_exercise_store_t *s){FILE *f=NULL;char line[256],severity[16];if(!s)return 0;memset(s,0,sizeof(*s));if(fopen_s(&f,EXERCISES,"r")!=0||!f)return 1;while(s->count<RICTUS_WARNING_EXERCISE_MAX&&fgets(line,sizeof(line),f)){rictus_warning_exercise_t *r=&s->records[s->count];if(sscanf(line,"%31s\t%15s\t%31s\t%63s",r->id,severity,r->created,r->created_by)==4){r->severity=_stricmp(severity,"CRITICAL")==0?RICTUS_EXERCISE_CRITICAL:RICTUS_EXERCISE_HIGH;r->private_delivered=listed(PRIVATE_DELIVERED,r->id);r->channel_delivered=listed(CHANNEL_DELIVERED,r->id);r->delivered=r->private_delivered&&(r->severity==RICTUS_EXERCISE_HIGH||r->channel_delivered);r->acknowledged=listed(ACKS,r->id);++s->count;}}fclose(f);return 1;}
int rictus_warning_exercise_create(rictus_warning_exercise_store_t *s,rictus_exercise_severity_t severity,const char *name,char id[32]){FILE *f=NULL;rictus_warning_exercise_t *r;char key[128];if(!s||!name||!id||(severity!=RICTUS_EXERCISE_HIGH&&severity!=RICTUS_EXERCISE_CRITICAL)||s->count>=RICTUS_WARNING_EXERCISE_MAX)return 0;r=&s->records[s->count];timestamp(r->created);sprintf_s(key,sizeof(key),"%s|%s|%u",r->created,name,(unsigned)severity);sprintf_s(r->id,sizeof(r->id),"EXWARN-%08lX",hash_text(key));strcpy_s(r->created_by,sizeof(r->created_by),name);r->severity=severity;if(fopen_s(&f,EXERCISES,"a")!=0||!f)return 0;fprintf(f,"%s\t%s\t%s\t%s\n",r->id,severity==RICTUS_EXERCISE_CRITICAL?"CRITICAL":"HIGH",r->created,r->created_by);fclose(f);strcpy_s(id,32,r->id);++s->count;return 1;}
void rictus_warning_exercise_deliver(rictus_warning_exercise_store_t *s,rictus_module_send_message_fn send){size_t i;FILE *f=NULL;char message[390];if(!s||!send)return;for(i=0;i<s->count;++i){rictus_warning_exercise_t *r=&s->records[i];if(r->delivered)continue;if(!r->private_delivered){sprintf_s(message,sizeof(message),"PM STN_Boss :[EXERCISE] %s | %s | delivery test only | no production evidence | !warn exercise show %s",r->severity==RICTUS_EXERCISE_CRITICAL?"CRITICAL":"HIGH",r->id,r->id);if(!send(message))return;if(fopen_s(&f,PRIVATE_DELIVERED,"a")!=0||!f)return;fprintf(f,"%s\n",r->id);fclose(f);r->private_delivered=1;}if(r->severity==RICTUS_EXERCISE_CRITICAL&&!r->channel_delivered){sprintf_s(message,sizeof(message),"[EXERCISE] CRITICAL | %s | ACK TEST REQUIRED | NO PRODUCTION EVENT | !warn exercise ack %s",r->id,r->id);if(!send(message))return;if(fopen_s(&f,CHANNEL_DELIVERED,"a")!=0||!f)return;fprintf(f,"%s\n",r->id);fclose(f);r->channel_delivered=1;}r->delivered=r->private_delivered&&(r->severity==RICTUS_EXERCISE_HIGH||r->channel_delivered);}}
int rictus_warning_exercise_ack(rictus_warning_exercise_store_t *s,const char *id,const char *name){size_t i;FILE *f=NULL;char when[32];if(!s||!id||!name)return 0;for(i=0;i<s->count;++i)if(_stricmp(s->records[i].id,id)==0){if(s->records[i].acknowledged)return 1;timestamp(when);if(fopen_s(&f,ACKS,"a")!=0||!f)return 0;fprintf(f,"%s\t%s\t%s\n",id,name,when);fclose(f);s->records[i].acknowledged=1;strcpy_s(s->records[i].ack_by,sizeof(s->records[i].ack_by),name);return 1;}return 0;}
