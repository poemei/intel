#ifndef RICTUS_INTELLIGENCE_SYNC_H
#define RICTUS_INTELLIGENCE_SYNC_H
#include "record.h"
#define RICTUS_INTELLIGENCE_SYNC_ENDPOINT_MAX 512
typedef struct { char endpoint[RICTUS_INTELLIGENCE_SYNC_ENDPOINT_MAX]; char pending_path[256]; } rictus_intelligence_sync_t;
void rictus_intelligence_sync_init(rictus_intelligence_sync_t *sync,const char *endpoint,const char *pending_path);
int rictus_intelligence_sync_report(rictus_intelligence_sync_t *sync,const rictus_intelligence_record_t *record);
int rictus_intelligence_sync_retry(rictus_intelligence_sync_t *sync,const rictus_intelligence_record_store_t *store);
int rictus_intelligence_sync_all(rictus_intelligence_sync_t *sync,const rictus_intelligence_record_store_t *store,size_t *sent,size_t *failed);
void rictus_intelligence_sync_last_error(long *http_status,int *curl_code,char *body,size_t body_size);
int rictus_intelligence_sync_assignments(rictus_intelligence_sync_t *sync,const char *spool_path);
int rictus_intelligence_sync_assignment_results(rictus_intelligence_sync_t *sync,const char *results_path);
#endif
