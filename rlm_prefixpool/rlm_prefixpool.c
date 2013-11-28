/*
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id: 463647aecc57c1c3ee225da9f711cd8d9ed2d6dd $
 * @file rlm_prefixpool.c
 * @brief Allocatas an IPv6 address from a pool stored in a GDBM database.
 *
 * @copyright 2013 Istvan Ruzman <Istvan.Ruzman@gmail.com>
 */
RCSID("$Id: 463647aecc57c1c3ee225da9f711cd8d9ed2d6dd $")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include "config.h"
#include <ctype.h>

#include <freeradius-devel/md5.h>

#include <gdbm.h>

#ifdef NEEDS_GDBM_SYNC
#define GDBM_SYNCOPT GDBM_SYNC
#else
#define GDBM_SYNCOPT 0
#endif

#ifdef GDBM_NOLOCK
#define GDBM_IP6POOL_OPTS (GDBM_SYNCOPT | GDBM_NOLOCK)
#else
#define GDBM_IP6POOL_OPTS (GDBM_SYNCOPT)
#endif

#define MAX_NAS_NAME_SIZE 64
#define PW_DELEGATED_IPV6_PREFIX 123

/*
 * Define a structure for our module configuration.
 *
 * These variables do not need to be in a structure, but it's
 * a lot cleaner to do so, and a pointer to the structure can
 * be used as the instance handle.
 */

typedef struct rlm_prefixpool_t {
	char *filename;
	char *ip_index;
	char *pool_name;
	char *name;
	char *key;
	value_data_t prefix_start;
	value_data_t prefix_stop;
	char *prefix_type;
	int attribute;
	time_t max_timeout;
	int cache_size;
	int override;
	int append;
	GDBM_FILE gdbm;
	GDBM_FILE ip;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t op_mutex;
#endif
} rlm_prefixpool_t;

#ifndef HAVE_PTHREAD_H
/*
 * This is easier than ifdef's throughout the code.
 */
#define pthread_mutex_init(_x, _y)
#define pthread_mutex_destroy(_x)
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif

typedef struct prefixpool_key {
	char key[32];
} prefixpool_key;

typedef struct prefixpool_info {
	value_data_t	prefix;
	uint8_t		nasid[16];
	char		active;
	char		cli[32];
	char		extra;
	time_t		timestamp;
	time_t		timeout;
} prefixpool_info;

static const CONF_PARSER module_config[] = {
	{ "filename", PW_TYPE_FILE_OUTPUT | PW_TYPE_REQUIRED, offsetof(rlm_prefixpool_t,filename), NULL, NULL },

	{ "key", PW_TYPE_STRING_PTR | PW_TYPE_REQUIRED,
	  offsetof(rlm_prefixpool_t,key), NULL, "%{NAS-IP-Address} %{NAS-Port}" },

	{ "prefix_start", PW_TYPE_IPV6PREFIX | PW_TYPE_REQUIRED, offsetof(rlm_prefixpool_t,prefix_start), NULL, "0" },

	{ "prefix_stop", PW_TYPE_IPV6PREFIX | PW_TYPE_REQUIRED, offsetof(rlm_prefixpool_t,prefix_stop), NULL, "0" },

	{ "prefix_type", PW_TYPE_STRING_PTR | PW_TYPE_REQUIRED,
	  offsetof(rlm_prefixpool_t,prefix_type), NULL, "Framed"},

	{ "cache_size", PW_TYPE_INTEGER, offsetof(rlm_prefixpool_t,cache_size), NULL, "1000" },

	{ "ip_index", PW_TYPE_STRING_PTR | PW_TYPE_REQUIRED, offsetof(rlm_prefixpool_t,ip_index), NULL, NULL},

	{ "override", PW_TYPE_BOOLEAN, offsetof(rlm_prefixpool_t,override), NULL, "no" },

	{ "append", PW_TYPE_BOOLEAN, offsetof(rlm_prefixpool_t,append), NULL, "yes"},

	{ "pool_name", PW_TYPE_STRING_PTR | PW_TYPE_REQUIRED, offsetof(rlm_prefixpool_t,pool_name), NULL, NULL},

	{NULL, -1, 0, NULL, NULL }
};

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	uint64_t i;
	rlm_prefixpool_t *inst = instance;
	int cache_size;
	char init_str[32];
	prefixpool_key key;
	prefixpool_info entry;
	datum key_datum;
	datum data_datum;
	char const *cli = "0";
	char const *pool_name = NULL;
	uint8_t *start = (uint8_t *)&inst->prefix_start.ipv6prefix[2];
	uint8_t *stop = (uint8_t *)&inst->prefix_stop.ipv6prefix[2];
	uint8_t const prefix = *(uint8_t *)&inst->prefix_start.ipv6prefix[1];

	cache_size = inst->cache_size;

	rad_assert(inst->filename && *inst->filename);
	rad_assert(inst->ip_index && *inst->ip_index);
	rad_assert(inst->pool_name && *inst->pool_name);

	char *tmp;
	for (tmp = inst->prefix_type ; *tmp; ++tmp)
		*tmp = tolower(*tmp);

	if (strstr(inst->prefix_type, "delegated")) {
		inst->attribute = PW_DELEGATED_IPV6_PREFIX;
		inst->prefix_type = strdup("Delegated");
	} else { /* Standard */
		inst->attribute = PW_FRAMED_IPV6_PREFIX;
	}

	if (inst->override && inst->append) {
		ERROR("rlm_prefixpool: append and overrride can't be true at the same time");
		return -1;
	}

	if (inst->prefix_start.ipv6prefix[1] != inst->prefix_stop.ipv6prefix[1]) {
		ERROR("rlm_prefixpool: Prefix lengths don't match");
		return -1;
	}

	inst->gdbm = gdbm_open(inst->filename, sizeof(int),
			GDBM_WRCREAT | GDBM_IP6POOL_OPTS, 0600, NULL);
	if (!inst->gdbm) {
		ERROR("rlm_prefixpool: Failed to open file %s: %s",
				inst->filename, fr_syserror(errno));
		return -1;
	}

	inst->ip = gdbm_open(inst->ip_index, sizeof(int),
			GDBM_WRCREAT | GDBM_IP6POOL_OPTS, 0600, NULL);
	if (!inst->ip) {
		ERROR("rlm_prefixpool: Failed to open file %s: %s",
				inst->ip_index, fr_syserror(errno));
		return -1;
	}

	if (gdbm_setopt(inst->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
		ERROR("rlm_prefixpool: Failed to set cache size");
	if (gdbm_setopt(inst->ip, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
		ERROR("rlm_prefixpool: Failed to set cache size");

	key_datum = gdbm_firstkey(inst->gdbm);
	if (!key_datum.dptr) {
			/*
			 * If the database does not exist, initialize it.
			 * We set the nas/port pairs to not existent values and
			 * active 0
			 */
		int rcode;
		char ipbuf[INET6_ADDRSTRLEN];

		DEBUG("rlm_prefixpool: Initializing database");

		uint32_t const pos = (prefix-1) / 64 * ((prefix-64) / 8);
		uint64_t range_start = htonl((uint32_t)((*(uint64_t*)&start[pos]) >> 32))
			| ((uint64_t)htonl(*(uint32_t*)&start[pos])) << 32;
		uint64_t range_stop = htonl((uint32_t)((*(uint64_t*)&stop[pos]) >> 32))
			| ((uint64_t)htonl(*(uint32_t*)&stop[pos])) << 32;

		if (prefix/16 < 4) {
			range_start >>= 64 - prefix;
			range_stop >>= 64 - prefix;
		}

		*(uint8_t*)(char*)entry.prefix.ipv6prefix = 0;
		*(uint8_t*)((char*)entry.prefix.ipv6prefix+1) = prefix;

		unsigned int j;
		for (i = range_start, j = ~0; i <= range_stop; ++i, j--) {
			sprintf(init_str, "%X", j);
			memcpy(key.key, init_str, sizeof(init_str));
			key_datum.dptr = (char *) &key;
			key_datum.dsize = sizeof(prefixpool_key);

			memcpy(&entry.prefix.ipv6prefix[2], start, 16);
			*(uint64_t*)&entry.prefix.ipv6prefix[2+pos] =
				ntohl((uint32_t)((uint64_t)i >> 32)) | ((uint64_t)ntohl(i)) << 32;
			entry.active = 0;
			entry.extra = 0;
			entry.timestamp = 0;
			entry.timeout = 0;
			strcpy(entry.cli,cli);
			DEBUG("rlm_prefixpool: Initialized bucket: %s (%s), %s", init_str,
					inet_ntop(AF_INET6, &entry.prefix.ipv6prefix[2],
						ipbuf, sizeof(ipbuf)),
					key.key);

			data_datum.dptr = (char *) &entry;
			data_datum.dsize = sizeof(prefixpool_info);

			rcode = gdbm_store(inst->gdbm, key_datum, data_datum, GDBM_REPLACE);
			if (rcode < 0) {
				ERROR("rlm_prefixpool: Failed storing data to %s: %s",
						inst->filename, gdbm_strerror(gdbm_errno));
				gdbm_close(inst->gdbm);
				gdbm_close(inst->ip);
				return -1;
			}
		}
	} else {
		free(key_datum.dptr);
	}

	inst->name = NULL;
	pool_name = cf_section_name2(conf);
	if (pool_name != NULL)
		inst->name = strdup(pool_name);

	pthread_mutex_init(&inst->op_mutex, NULL);

	return 0;
}

static rlm_rcode_t mod_accounting(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

static rlm_rcode_t mod_post_auth(void *instance, REQUEST *request)
{
	rlm_prefixpool_t *inst = instance;
	int delete = 0;
	int found = 0;
	int mppp = 0;
	int extra = 0;
	int rcode = 0;
	int num = 0;
	datum key_datum;
	datum nextkey;
	datum data_datum;
	datum save_datum;
	prefixpool_key key;
	prefixpool_info entry;
	VALUE_PAIR *vp;
	char const *cli = NULL;
	char str[32];
	uint8_t key_str[17];
	char hex_str[33];
	char xlat_str[MAX_STRING_LEN];
	FR_MD5_CTX md5_context;
	int attr_type = inst->attribute;
	int vendor_ipaddr = 0;

	if ((vp = pairfind(request->config_items, PW_POOL_NAME, 0, TAG_ANY)) != NULL) {
		if (!inst->pool_name || (strcmp(inst->pool_name, vp->vp_strvalue) && strcmp(vp->vp_strvalue,"DEFAULT")))
			return RLM_MODULE_NOOP;
	} else {
		RDEBUG("Could not find Pool-Name attribute");
		return RLM_MODULE_NOOP;
	}

	/*
	 *Find the caller id
	 */
	if ((vp = pairfind(request->packet->vps, PW_CALLING_STATION_ID, 0, TAG_ANY)) != NULL)
		cli = vp->vp_strvalue;

	if (radius_xlat(xlat_str, sizeof(xlat_str), request, inst->key, NULL, NULL) < 0)
		return RLM_MODULE_NOOP;

	fr_MD5Init(&md5_context);
	fr_MD5Update(&md5_context, (uint8_t *) xlat_str, strlen(xlat_str));
	fr_MD5Final(key_str, &md5_context);
	key_str[16] = '\0';
	fr_bin2hex(hex_str, key_str, 16);
	hex_str[32] = '\0';
	RDEBUG("MD5 on 'key' directive maps to: %s", hex_str);
	memcpy(key.key,key_str,16);

	RDEBUG("Searching for an entry for key: '%s'", hex_str);
	key_datum.dptr = (char *) &key;
	key_datum.dsize = sizeof(prefixpool_key);

	pthread_mutex_lock(&inst->op_mutex);
	data_datum = gdbm_fetch(inst->gdbm, key_datum);
	if (data_datum.dptr != NULL) {
		/*
		 * If there is a corresponding entry in the database with active=1 it is stale.
		 * Set active to zero
		 */
		found = 1;
		memcpy(&entry, data_datum.dptr, sizeof(prefixpool_info));
		free(data_datum.dptr);
		if (entry.active) {
			RDEBUG("Found a stale entry for prefix: %s",
					inet_ntop(AF_INET6,(struct in6_addr*) (&entry.prefix.ipv6prefix[2]), str, sizeof(str)));
			entry.active = 0;
			entry.timestamp = 0;
			entry.timeout = 0;

			/*
			 * Save the reference to the entry
			 */
			save_datum.dptr = key_datum.dptr;
			save_datum.dsize = key_datum.dsize;

			data_datum.dptr = (char *) &entry;
			data_datum.dsize = sizeof(prefixpool_info);

			rcode = gdbm_store(inst->gdbm, key_datum, data_datum, GDBM_REPLACE);
			if (rcode < 0) {
				ERROR("rlm_ipv6pool: Failed storing data to %s: %s",
						inst->filename, gdbm_strerror(gdbm_errno));
				pthread_mutex_unlock(&inst->op_mutex);
				return RLM_MODULE_FAIL;
			}

			/* Decrease the allocated count from the ip index */
			key_datum.dptr = (char *) &entry.prefix;
			key_datum.dsize = sizeof(value_data_t);
			data_datum = gdbm_fetch(inst->ip, key_datum);
			if (data_datum.dptr != NULL) {
				memcpy(&num, data_datum.dptr, sizeof(int));
				free(data_datum.dptr);
				if (num > 0) {
					num--;
					RDEBUG("num: %d", &num);
					data_datum.dptr = (char *) &num;
					data_datum.dsize = sizeof(int);
					rcode = gdbm_store(inst->ip, key_datum, data_datum, GDBM_REPLACE);
					if (rcode < 0) {
						ERROR("rlm_prefixpool: Failed storing data to %s: %s",
								inst->ip_index, gdbm_strerror(gdbm_errno));
						pthread_mutex_unlock(&inst->op_mutex);
						return RLM_MODULE_FAIL;
					}
					if (num > 0 && entry.extra == 1) {
						/*
						 * We are doing MPPP and we still have nas/port entries referencing
						 * this ip. Delete this entry so that eventually we only keep one 
						 * reference to this ip.
						 */
						gdbm_delete(inst->gdbm, save_datum);
					}
				}
			}
		}
	}

	pthread_mutex_unlock(&inst->op_mutex);

	/*
	 * If there is a *-IPv6-Prefix attribute in the reply,
	 * check to override
	 */
	if (pairfind(request->reply->vps, attr_type, vendor_ipaddr, TAG_ANY) != NULL) {
		RDEBUG("Found %s-IPv6-Prefix in reply attribute list", inst->prefix_type);
		if (inst->override) {
			RDEBUG("Override supplied %s-IPv6-Prefix", inst->prefix_type);
			pairdelete(&request->reply->vps, attr_type, vendor_ipaddr, TAG_ANY);
		}
		if (!inst->append) {
			return RLM_MODULE_NOOP;
		}
	}

	/*
	 * Walk through the database searching for an active=0 entry.
	 * We search twice. Once to see if we have an active entry with the same caller_id
	 * so that MPPP can work ok and then once again to find a free entry.
	 */
	pthread_mutex_lock(&inst->op_mutex);

	key_datum.dptr = NULL;
	if (cli != NULL) {
		key_datum = gdbm_firstkey(inst->gdbm);
		while (key_datum.dptr) {
			data_datum = gdbm_fetch(inst->gdbm, key_datum);
			if (data_datum.dptr) {
				memcpy(&entry, data_datum.dptr, sizeof(prefixpool_info));
				free(data_datum.dptr);
				/*
				 * If we find an entry for the same caller-id with active=1
				 * then we use that for multilink (MPPP) to work properly
				 */
				if (strcmp(entry.cli,cli) == 0 && entry.active) {
					mppp = 1;
					break;
				}
			}
			nextkey = gdbm_nextkey(inst->gdbm, key_datum);
			free(key_datum.dptr);
			key_datum = nextkey;
		}
	}

	if (!key_datum.dptr) {
		key_datum = gdbm_firstkey(inst->gdbm);
		while (key_datum.dptr) {
			data_datum = gdbm_fetch(inst->gdbm, key_datum);
			if (data_datum.dptr) {
				memcpy(&entry, data_datum.dptr, sizeof(prefixpool_info));
				free(data_datum.dptr);
				/*
				 * Find an entry with active == 0
				 * or an entry that has expired
				 */
				if (entry.active == 0 || (entry.timestamp && ((entry.timeout &&
					request->timestamp >= (entry.timestamp + entry.timeout)) ||
					(inst->max_timeout && request->timestamp >= (entry.timestamp +
					inst->max_timeout))))) {

					datum tmp;

					tmp.dptr = (char *) &entry.prefix;
					tmp.dsize = sizeof(value_data_t);
					data_datum = gdbm_fetch(inst->ip, tmp);

					/*
					 * If we find an entry in the ip index and the number is zero (meaning
					 * that we haven't allocated the same ip address to another nas/port pair)
					 * or if we don't find an entry then delete the session entry so
					 * that we can change the key.
					 * Else we don't delete the session entry since we haven't yet deallocated the
					 * corresponding ip address and we continue our search.
					 */
					if (data_datum.dptr) {
						memcpy(&num, data_datum.dptr, sizeof(int));
						free(data_datum.dptr);
						if (num == 0) {
							delete = 1;
							break;
						}
					} else {
						delete = 1;
						break;
					}
				}
			}
			nextkey = gdbm_nextkey(inst->gdbm, key_datum);
			free(key_datum.dptr);
			key_datum = nextkey;
		}
	}
			
	/*
	 * If we have found a free entry set active to 1 then add a *-IPv6-Prefix attribute to
	 * the reply
	 * We keep the operation mutex locked until after we have set the corresponding entry active
	 */
	if (key_datum.dptr) {
		if (found == !mppp) {
			datum key_datum_tmp;
			datum data_datum_tmp;
			prefixpool_key key_tmp;

			memcpy(key_tmp.key, key_str, 16);
			key_datum_tmp.dptr = (char *) &key_tmp;
			key_datum_tmp.dsize = sizeof(prefixpool_key);

			data_datum_tmp = gdbm_fetch(inst->gdbm, key_datum_tmp);
			if (data_datum_tmp.dptr != NULL) {
				rcode = gdbm_store(inst->gdbm, key_datum, data_datum_tmp, GDBM_REPLACE);
				free(data_datum_tmp.dptr);
				if(rcode < 0) {
					ERROR("rlm_prefixpool: Failed storing data to %s: %s",
							inst->filename, gdbm_strerror(gdbm_errno));
					pthread_mutex_unlock(&inst->op_mutex);
					return RLM_MODULE_FAIL;
				}
			}
		} else {
			/*
			 * We have not found the nas/port combination
			 */
			if (delete) {
				/*
				 * Delete the entry so that we can change the key
				 * All is well. We delet one entry and we add one entry
				 */
				gdbm_delete(inst->gdbm, key_datum);
			} else {
				/*
				 * We are doing MPPP. (mppp should be 1)
				 * We don't do anything.
				 * We will create an extra not needed entry in the database in this case
				 * but we don't really care since we always also use the ip_index database
				 * when we search for a free entry.
				 * We will also delete that entry on the accounting section so that we only 
				 * have one nas/port entry referencing each ip
				 */
				RDEBUG("MPPP");
				if (mppp)
					extra = 1;
				if (!mppp)
					ERROR("rlm_prefixpool: mppp is not one. Please report this behaviour");
			}
		}
		free(key_datum.dptr);
		entry.active = 1;
		entry.timestamp = request->timestamp;
		if ((vp = pairfind(request->reply->vps, PW_SESSION_TIMEOUT, 0, TAG_ANY)) != NULL) {
			entry.timeout = (time_t) vp->vp_integer;
		} else {
			entry.timeout = 0;
		}

		/* Write a NAS to the prefixpool_info */
		char *attribute;
		if ((vp = pairfind(request->packet->vps, PW_NAS_IDENTIFIER, 0, TAG_ANY)) != NULL)
			attribute = strdup("%{NAS-Identifier}");
		else if ((vp = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS, 0, TAG_ANY)) != NULL)
			attribute = strdup("%{NAS-IP-Address}");
		else if ((vp = pairfind(request->packet->vps, PW_NAS_IPV6_ADDRESS, 0, TAG_ANY)) != NULL)
			attribute = strdup("%{NAS-IPv6-Address}");
		else {
			DEBUG("Can't find any NAS Identifier or NAS IP Address Attribute in request");
			DEBUG("Using default value");
			attribute = strdup("%{NoAttribute}");
		}

		if (radius_xlat(xlat_str, sizeof(xlat_str), request, attribute, NULL, NULL) < 0) {
			strncpy(xlat_str, "DefaultNAS", sizeof(xlat_str));
		}

		fr_MD5Init(&md5_context);
		fr_MD5Update(&md5_context, (uint8_t *)xlat_str, strlen(xlat_str));
		fr_MD5Final(entry.nasid, &md5_context);

		free(attribute);

		if (extra)
			entry.extra = 1;
		data_datum.dptr = (char *) &entry;
		data_datum.dsize = sizeof(prefixpool_info);
		memcpy(key.key, key_str, 16);
		key_datum.dptr = (char *) &key;
		key_datum.dsize = sizeof(prefixpool_key);

		DEBUG2("rlm_prefixpool: Allocationg ip to key '%s'", hex_str);
		rcode = gdbm_store(inst->gdbm, key_datum, data_datum, GDBM_REPLACE);
		if (rcode < 0) {
			ERROR("rlm_prefixpool: Failed storing data to %s: %s",
					inst->filename, gdbm_strerror(gdbm_errno));
			pthread_mutex_unlock(&inst->op_mutex);
			return RLM_MODULE_FAIL;
		}

		/* Increase the ip index count */
		key_datum.dptr = (char *) &entry.prefix;
		key_datum.dsize = sizeof(value_data_t);
		data_datum = gdbm_fetch(inst->ip, key_datum);
		if (data_datum.dptr) {
			memcpy(&num, data_datum.dptr, sizeof(int));
			free(data_datum.dptr);
		} else {
			num = 0;
		}
		++num;
		RDEBUG("num: %d", num);
		data_datum.dptr = (char *) &num;
		data_datum.dsize = sizeof(int);
		rcode = gdbm_store(inst->ip, key_datum, data_datum, GDBM_REPLACE);
		if (rcode < 0) {
			ERROR("rlm_prefixpool: Failed storing data to %s: %s",
					inst->ip_index, gdbm_strerror(gdbm_errno));
			pthread_mutex_unlock(&inst->op_mutex);
			return RLM_MODULE_FAIL;
		}
		pthread_mutex_unlock(&inst->op_mutex);

		/* RDBUG("Allocated prefix %s to client key: %s", ip_ntoa(TODO), hex_str); */
		vp = radius_paircreate(request, &request->reply->vps,
				attr_type, vendor_ipaddr);

		memcpy(vp->vp_ipv6prefix,&entry.prefix, 18);
		vp->length = 18;
		
	} else {
		pthread_mutex_unlock(&inst->op_mutex);
		RDEBUG("No available ip prefixes in pool");
		return RLM_MODULE_NOTFOUND;
	}

	return RLM_MODULE_OK;
}

static int mod_detach(void *instance)
{
	rlm_prefixpool_t *inst = instance;

	if (inst->attribute == 123)
		free(inst->prefix_type);

	gdbm_close(inst->gdbm);
	gdbm_close(inst->ip);
	pthread_mutex_destroy(&inst->op_mutex);
	return 0;
}

module_t rlm_prefixpool = {
	RLM_MODULE_INIT,
	"prefixpool",
	RLM_TYPE_THREAD_SAFE,
	sizeof(rlm_prefixpool_t),
	module_config,
	mod_instantiate,	/* instantiation */
	mod_detach,			/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		mod_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		mod_post_auth	/* post-auth */
	},
};
