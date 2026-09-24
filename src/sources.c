/*
 * STN-LABZ
 * Rictus Intelligence Module
 *
 * sources.c
 *
 * Approved Intelligence source definitions.
 *
 * The registry contains authoritative/root sources plus explicitly marked
 * discovery/corroboration sources.  Source presence never bypasses the
 * module relevance gate.
 *
 * Source configuration is deterministic and
 * module-owned.
 */

#include <string.h>

#include "sources.h"


/*
 * ------------------------------------------------
 * APPROVED SOURCES
 * ------------------------------------------------
 *
 * HTTPS is mandatory.
 *
 * NASA:
 * Official NASA RSS content.
 *
 * SpaceX:
 * Official SpaceX Updates page.
 *
 * CISA:
 * Official CISA Cybersecurity Advisories feed.
 *
 * STN-LABZ:
 * First-party raw threat observations.
 */

static const
rictus_intelligence_source_definition_t
g_sources[] =
{
    {
        "nasa_news",

        "NASA",

        "www.nasa.gov",

        "/rss/dyn/breaking_news.rss",

        RICTUS_INTELLIGENCE_TRANSPORT_RSS,

        1
    },

    {
        "spacex_updates",

        "SpaceX",

        "www.spacex.com",

        "/updates",

        RICTUS_INTELLIGENCE_TRANSPORT_HTML,

        1
    },

    {
        "nist_csrc",

        "NIST CSRC",

        "csrc.nist.gov",

        "/news?ipp-sm=100&sortBy-sm=NewsDateTime+DESC&topicsMatch-sm=ANY",

        RICTUS_INTELLIGENCE_TRANSPORT_HTML,

        1
    },

    {
        "cisa_cybersecurity_advisories",

        "CISA Cybersecurity Advisories",

        "www.cisa.gov",

        "/cybersecurity-advisories/all.xml",

        RICTUS_INTELLIGENCE_TRANSPORT_RSS,

        1
    },

    {
        "stn_labz_threats",

        "STN-LABZ Threat API",

        "api.stn-labz.com",

        "/threats",

        RICTUS_INTELLIGENCE_TRANSPORT_JSON,

        1
    },

    {
        "php_releases", "PHP Releases", "www.php.net",
        "/releases/feed.php", RICTUS_INTELLIGENCE_TRANSPORT_RSS, 1
    },
    {
        "wordpress_security", "WordPress Security Releases", "wordpress.org",
        "/news/category/security/feed/", RICTUS_INTELLIGENCE_TRANSPORT_RSS, 1
    },
    {
        "joomla_security", "Joomla Security Centre", "developer.joomla.org",
        "/security-centre.feed?type=rss", RICTUS_INTELLIGENCE_TRANSPORT_RSS, 1
    },
    {
        "drupal_core_security", "Drupal Core Security Advisories", "www.drupal.org",
        "/security/rss.xml", RICTUS_INTELLIGENCE_TRANSPORT_RSS, 1
    },
    {
        "nginx_security", "nginx Security Advisories", "nginx.org",
        "/en/security_advisories.html", RICTUS_INTELLIGENCE_TRANSPORT_HTML, 1
    },
    {
        "apache_httpd_security", "Apache HTTP Server Security", "httpd.apache.org",
        "/security/vulnerabilities_24.html", RICTUS_INTELLIGENCE_TRANSPORT_HTML, 1
    },
    {
        "mariadb_security", "MariaDB Security", "mariadb.org",
        "/category/security/feed/", RICTUS_INTELLIGENCE_TRANSPORT_RSS, 1
    },
    {
        "cert_cc_vulnerability_notes", "CERT/CC Vulnerability Notes", "kb.cert.org",
        "/vuls/atomfeed/", RICTUS_INTELLIGENCE_TRANSPORT_RSS, 0
    }
};


size_t
rictus_intelligence_source_count(void)
{
    return
        sizeof(g_sources) /
        sizeof(g_sources[0]);
}


const rictus_intelligence_source_definition_t *
rictus_intelligence_source_get(
    size_t index
)
{
    if (
        index >=
        rictus_intelligence_source_count()
    )
    {
        return NULL;
    }


    return
        &g_sources[index];
}


const rictus_intelligence_source_definition_t *
rictus_intelligence_source_find(
    const char *id
)
{
    size_t index;


    if (
        id == NULL ||
        id[0] == '\0'
    )
    {
        return NULL;
    }


    for (
        index = 0;
        index <
            rictus_intelligence_source_count();
        ++index
    )
    {
        if (
            strcmp(
                g_sources[index].id,
                id
            ) == 0
        )
        {
            return
                &g_sources[index];
        }
    }


    return NULL;
}
