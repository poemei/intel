/* STN-LABZ Rictus Intelligence: deterministic engineering relevance gate. */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "relevance.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const char *const systems[] = {"architecture","reliability","safety","validation","verification","qualification","fault","failure","autonomous","autonomy"};
static const char *const software[] = {"software","compiler","toolchain","library","api","abi","windows","linux","kernel","runtime","dependency","php","wordpress","joomla","drupal","nginx","apache","mariadb","mysql","http server","webservice"};
static const char *const cyber[] = {"cybersecurity","security","vulnerability","exploit","authentication","authorization","access control","acl","cors","csrf","cross-site","xss","sql injection","ssrf","object injection","deserialization","file upload","path traversal","request processing","session","privilege","memory safety","malware","attack","breach","pattern match","probe","blocked","supply chain","cve"};
static const char *const space[] = {"spacecraft","satellite","rendezvous","proximity operations","servicing","orbital","guidance","navigation","space communications","launch vehicle","flight software","mission operations"};
static const char *const consequence[] = {"failure","failed","fault","anomaly","incident","vulnerability","exploit","attack","breach","compromise","risk","authorization","authentication","access control","security release","security fix","pattern match","probe","blocked","cve","qualification","validation","verification","standard","finalized","revision","revised","requirement","mitigation","patch","update","deprecation","breaking change","supply chain","compatibility","advisory","design","architecture","demonstration","test","research"};
static const char *const comments[] = {"request for comment","request for comments","seeking comment","seeking comments","public comment","public comments","comment period","draft for comment","draft for comments"};
static const char *const substantive[] = {"failure","fault","anomaly","incident","vulnerability","exploit","attack","breach","compromise","authorization","authentication","mitigation","breaking change","deprecation","patch"};

/* Generic platform words such as software, Windows, VPN, and server are
 * deliberately absent from the explicit STN-LABZ technology boundary. */
static const char *const stn_technology[] = {"stn-labz","chaos mvc","rictus","sentinel","digit","php","wordpress","joomla","drupal","nginx","apache http server","httpd","mariadb","mysql"};
static const char *const approved_product_sources[] = {"PHP Releases","WordPress Security Releases","Joomla Security Centre","Drupal Core Security Advisories","nginx Security Advisories","Apache HTTP Server Security","MariaDB Security"};

static int contains_ci(const char *text,const char *needle){size_t n;const char *p;if(!text||!needle||!*needle)return 0;n=strlen(needle);for(p=text;*p;++p)if(strncasecmp(p,needle,n)==0)return 1;return 0;}
static int item_has(const rictus_intelligence_item_t *i,const char *t){return contains_ci(i->title,t)||contains_ci(i->summary,t)||contains_ci(i->content,t);}
static int any(const rictus_intelligence_item_t *i,const char *const *terms,size_t count){size_t x;for(x=0;x<count;++x)if(item_has(i,terms[x]))return 1;return 0;}
static int source_is(const rictus_intelligence_item_t *i,const char *const *sources,size_t count){size_t x;for(x=0;x<count;++x)if(strcasecmp(i->source,sources[x])==0)return 1;return 0;}

int rictus_intelligence_relevance_evaluate(const rictus_intelligence_item_t *i,rictus_intelligence_relevance_result_t *r)
{
    int material,generic,cyber_related,explicit_boundary,product_source,first_party;
    if(!i||!r)return 0;
    memset(r,0,sizeof(*r));
    if(any(i,systems,COUNT(systems)))r->domain_flags|=RICTUS_INTELLIGENCE_DOMAIN_SYSTEMS_ENGINEERING;
    if(any(i,software,COUNT(software)))r->domain_flags|=RICTUS_INTELLIGENCE_DOMAIN_SOFTWARE_ENGINEERING;
    if(any(i,cyber,COUNT(cyber)))r->domain_flags|=RICTUS_INTELLIGENCE_DOMAIN_CYBER_SECURITY;
    if(any(i,space,COUNT(space)))r->domain_flags|=RICTUS_INTELLIGENCE_DOMAIN_SPACE_DEVELOPMENT;
    material=any(i,consequence,COUNT(consequence));
    generic=any(i,comments,COUNT(comments));
    cyber_related=(r->domain_flags&RICTUS_INTELLIGENCE_DOMAIN_CYBER_SECURITY)!=0;
    explicit_boundary=any(i,stn_technology,COUNT(stn_technology));
    product_source=source_is(i,approved_product_sources,COUNT(approved_product_sources));
    first_party=strcasecmp(i->source,"STN-LABZ Threat API")==0;
    if(!r->domain_flags||!material){r->relevance=RICTUS_INTELLIGENCE_RELEVANCE_NONE;snprintf(r->reason, sizeof(r->reason), "%s", !r->domain_flags?"No STN-LABZ engineering-domain consequence was established by retained source evidence.":"Engineering-domain vocabulary was present, but no material engineering consequence was established.");return 1;}
    if(generic&&!any(i,substantive,COUNT(substantive))){r->relevance=RICTUS_INTELLIGENCE_RELEVANCE_NONE;snprintf(r->reason, sizeof(r->reason), "%s", "Generic comment activity did not independently establish a material STN-LABZ engineering consequence.");return 1;}
    if(cyber_related&&!first_party&&!product_source&&!explicit_boundary){r->relevance=RICTUS_INTELLIGENCE_RELEVANCE_NONE;snprintf(r->reason, sizeof(r->reason), "%s", "Cybersecurity reporting named no explicit STN-LABZ technology, dependency, product, or owned-service boundary; generic vulnerability language is insufficient.");return 1;}
    r->relevance=RICTUS_INTELLIGENCE_RELEVANCE_RELEVANT;
    if(first_party)snprintf(r->reason, sizeof(r->reason), "%s", "First-party Sentinel evidence concerns an STN-LABZ-managed service; severity depends on the exact observed path and outcome.");
    else if(product_source||explicit_boundary)snprintf(r->reason, sizeof(r->reason), "%s", "The retained evidence explicitly intersects an approved STN-LABZ technology or product boundary; applicability beyond the cited evidence remains analytical.");
    else snprintf(r->reason, sizeof(r->reason), "%s", "The retained evidence identifies a material systems-engineering or mission condition within an STN-LABZ analytical domain.");
    return 1;
}
