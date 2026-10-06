#ifndef RICTUS_INTELLIGENCE_SYNC_H
#define RICTUS_INTELLIGENCE_SYNC_H
#include "record.h"
#define RICTUS_INTELLIGENCE_SYNC_ENDPOINT_MAX 512
typedef struct { char endpoint[RICTUS_INTELLIGENCE_SYNC_ENDPOINT_MAX]; char pending_path[256]; } rictus_intelligence_sync_t;
void rictus_intelligence_sync_init(rictus_intelligence_sync_t *sync,const char *endpoint,const char *pending_path);
int rictus_intelligence_sync_report(rictus_intelligence_sync_t *sync,const rictus_intelligence_record_t *record);
int rictus_intelligence_sync_retry(rictus_intelligence_sync_t *sync,const rictus_intelligence_record_store_t *store);
#endif
