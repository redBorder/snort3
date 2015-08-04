//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// Chris Green <cmg@sourcefire.com>

#include "tag.h"

#include <sys/types.h>
#include <stdlib.h>
#include <rpc/types.h>
#include <string.h>
#include <ctype.h>

#include "rules.h"
#include "treenodes.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "log/log.h"
#include "parser/parser.h"
#include "events/event.h"
#include "hash/sfxhash.h"
#include "sfip/sfip_t.h"
#include "sfip/sf_ip.h"

/*  D E F I N E S  **************************************************/
#define MAX_TAG_NODES   256

/* by default we'll set a 5 minute timeout if we see no activity
 * on a tag with a 'count' metric so that we prune dead sessions
 * periodically since we're not doing TCP state tracking
 */
#define TAG_PRUNE_QUANTUM   300
#define TAG_MEMCAP          4194304  /* 4MB */

#define GENERATOR_TAG       2
#define TAG_LOG_PKT         1

/*  D A T A   S T R U C T U R E S  **********************************/
/**Key used for identifying a session or host.
 */
struct tTagFlowKey
{
    sfip_t sip;  ///source IP address
    sfip_t dip;  ///destination IP address

    /* ports */
    uint16_t sp; ///source port
    uint16_t dp; ///destination port
};

/**Node identifying a session or host based tagging.
 */
struct TagNode
{
    /**key identifying a session or host. */
    tTagFlowKey key;

    /** number of packets/seconds/bytes to tag for */
    int seconds;
    int packets;
    int bytes;

    /** counters of number of packets tagged and max to
     * prevent Eventing DOS */
    int pkt_count;

    /** packets/seconds selector */
    int metric;

    /** session or host mode */
    int mode;

    /** last UNIX second that this node had a successful match */
    uint32_t last_access;

    /** event id number for correlation with trigger events */
    uint16_t event_id;
    struct timeval event_time;

    void* log_list;  // retain custom logging if any from triggering alert
};

/*  G L O B A L S  **************************************************/
static THREAD_LOCAL SFXHASH* host_tag_cache_ptr = nullptr;

// FIXIT-M utilize Flow instead of separate cache
static THREAD_LOCAL SFXHASH* ssn_tag_cache_ptr = nullptr;

static THREAD_LOCAL uint32_t last_prune_time = 0;
static THREAD_LOCAL uint32_t tag_alloc_faults = 0;
static THREAD_LOCAL uint32_t tag_memory_usage = 0;

static THREAD_LOCAL bool s_exclusive = false;
static THREAD_LOCAL unsigned s_sessions = 0;

// TBD when tags leverage sessions, tag nodes can be freed at end
// of session.  then we can configure this to allow multiple
// (consecutive) sessions to be captured.
static const unsigned s_max_sessions = 1;

/*  P R O T O T Y P E S  ********************************************/
static TagNode* TagAlloc(SFXHASH*);
static void TagFree(SFXHASH*, TagNode*);
static int TagFreeSessionNodeFunc(void* key, void* data);
static int TagFreeHostNodeFunc(void* key, void* data);
static int PruneTagCache(uint32_t, int);
static int PruneTime(SFXHASH* tree, uint32_t thetime);
static void TagSession(Packet*, TagData*, uint32_t, uint16_t, void*);
static void TagHost(Packet*, TagData*, uint32_t, uint16_t, void*);
static void AddTagNode(Packet*, TagData*, int, uint32_t, uint16_t, void*);
static inline void SwapTag(TagNode*);

/**Calculated memory needed per node insertion into respective cache. Its includes
 * memory needed for allocating TagNode, SFXHASH_NODE, and key size.
 *
 * @param hash - pointer to SFXHASH that should point to either ssn_tag_cache_ptr
 * or host_tag_cache_ptr.
 *
 * @returns number of bytes needed
 */
static inline unsigned int memory_per_node(
    SFXHASH* hash
    )
{
    if (hash == ssn_tag_cache_ptr)
    {
        return sizeof(tTagFlowKey)+sizeof(SFXHASH_NODE)+sizeof(TagNode);
    }
    else if (hash == host_tag_cache_ptr)
    {
        return sizeof(sfip_t)+sizeof(SFXHASH_NODE)+sizeof(TagNode);
    }

    return 0;
}

/** Allocate a TagNode
 *
 * Alocates a TagNode while guaranteeing that total memory usage remains within TAG_MEMCAP.
 * Least used nodes may be deleted from ssn_tag_cache and host_tag_cache to make space if
 * the limit is being exceeded.
 *
 * @param hash - pointer to SFXHASH that should point to either ssn_tag_cache_ptr
 * or host_tag_cache_ptr.
 *
 * @returns a pointer to new TagNode or NULL if memory couldn't * be allocated
 */
static TagNode* TagAlloc(
    SFXHASH* hash
    )
{
    TagNode* tag_node = NULL;

    if (tag_memory_usage + memory_per_node(hash) > TAG_MEMCAP)
    {
        /* aggressively prune */
        struct timeval tv;
        struct timezone tz;
        int pruned_nodes = 0;

        tag_alloc_faults++;

        gettimeofday(&tv, &tz);

        pruned_nodes = PruneTagCache((uint32_t)tv.tv_sec, 0);

        if (pruned_nodes == 0)
        {
            /* if we can't prune due to time, just try to nuke
             * 5 not so recently used nodes */
            pruned_nodes = PruneTagCache(0, 5);

            /* unlikely to happen since memcap has been reached */
            if (pruned_nodes == 0)
                return NULL;
        }
    }

    tag_node = (TagNode*)calloc(1, sizeof(TagNode));

    if (tag_node != NULL)
        tag_memory_usage += memory_per_node(hash);

    return tag_node;
}

/**Frees allocated TagNode.
 *
 * @param hash - pointer to SFXHASH that should point to either ssn_tag_cache_ptr
 * or host_tag_cache_ptr.
 * @param node - pointer to node to be freed
 */
static void TagFree(
    SFXHASH* hash,
    TagNode* node
    )
{
    if (node == NULL)
        return;

    if ( node->metric & TAG_METRIC_SESSION )
        s_exclusive = false;

    free((void*)node);
    tag_memory_usage -= memory_per_node(hash);
}

/**Callback from session tag cache to free user data.
 * @param key - pointer to key to session tag
 * @param data - pointer to user data, to be freed.
 * @returns 0
 */
static int TagFreeSessionNodeFunc(void*, void* data)
{
    TagFree(ssn_tag_cache_ptr, (TagNode*)data);
    return 0;
}

/**Callback from host tag cache to free user data.
 * @param key - pointer to key to session tag
 * @param data - pointer to user data, to be freed.
 * @returns 0
 */
static int TagFreeHostNodeFunc(void*, void* data)
{
    TagFree(host_tag_cache_ptr, (TagNode*)data);
    return 0;
}

/**Reset all data structures and free all memory.
 */
void TagCacheReset(void)
{
    sfxhash_make_empty(ssn_tag_cache_ptr);
    sfxhash_make_empty(host_tag_cache_ptr);
}

/**
 * swap the sips and dips, dp's and sp's
 *
 * @param np TagNode ptr
 */
static inline void SwapTag(TagNode* np)
{
    sfip_t tip;
    uint16_t tport;

    tip = np->key.sip;
    np->key.sip = np->key.dip;
    np->key.dip = tip;

    tport = np->key.sp;
    np->key.sp = np->key.dp;
    np->key.dp = tport;
}

void InitTag(void)
{
    unsigned int hashTableSize = TAG_MEMCAP/sizeof(TagNode);

    ssn_tag_cache_ptr = sfxhash_new(
        hashTableSize,                      /* number of hash buckets */
        sizeof(tTagFlowKey),             /* size of the key we're going to use */
        0,                                  /* size of the storage node */
        0,                                  /* disable memcap*/
        0,                                  /* use auto node recovery */
        NULL,                               /* anr free function */
        TagFreeSessionNodeFunc,             /* user free function */
        0);                                 /* recycle node flag */

    host_tag_cache_ptr = sfxhash_new(
        hashTableSize,               /* number of hash buckets */
        sizeof(sfip_t),            /* size of the key we're going to use */
        0,                           /* size of the storage node */
        0,                           /* disable memcap*/
        0,                           /* use auto node recovery */
        NULL,                        /* anr free function */
        TagFreeHostNodeFunc,         /* user free function */
        0);                          /* recycle node flag */
}

void CleanupTag(void)
{
    if (ssn_tag_cache_ptr)
    {
        sfxhash_delete(ssn_tag_cache_ptr);
    }

    if (host_tag_cache_ptr)
    {
        sfxhash_delete(host_tag_cache_ptr);
    }
}

static void TagSession(Packet* p, TagData* tag, uint32_t time, uint16_t event_id, void* log_list)
{
    DebugMessage(DEBUG_FLOW, "TAGGING SESSION\n");

    AddTagNode(p, tag, TAG_SESSION, time, event_id, log_list);
}

static void TagHost(Packet* p, TagData* tag, uint32_t time, uint16_t event_id, void* log_list)
{
    int mode;

    DebugMessage(DEBUG_FLOW, "TAGGING HOST\n");

    switch (tag->tag_direction)
    {
    case TAG_HOST_DST:
        mode = TAG_HOST_DST;
        break;
    case TAG_HOST_SRC:
        mode = TAG_HOST_SRC;
        break;
    default:
        mode = TAG_HOST_SRC;
        break;
    }

    AddTagNode(p, tag, mode, time, event_id, log_list);
}

static void AddTagNode(Packet* p, TagData* tag, int mode, uint32_t now,
    uint16_t event_id, void* log_list)
{
    TagNode* idx;  /* index pointer */
    TagNode* returned;
    SFXHASH* tag_cache_ptr = NULL;

    DebugMessage(DEBUG_FLOW, "Adding new Tag Head\n");

    if ( tag->tag_metric & TAG_METRIC_SESSION )
    {
        if ( s_exclusive )
            return;

        if ( s_sessions >= s_max_sessions )
            return;

        s_exclusive = true;
        ++s_sessions;
    }
    if (mode == TAG_SESSION)
    {
        DebugMessage(DEBUG_FLOW,"Session Tag!\n");
        tag_cache_ptr = ssn_tag_cache_ptr;
    }
    else
    {
        DebugMessage(DEBUG_FLOW,"Host Tag!\n");
        tag_cache_ptr = host_tag_cache_ptr;
    }
    idx = TagAlloc(tag_cache_ptr);

    /* If a TagNode couldn't be allocated, just write an error message
     * and return - won't be able to track this one. */
    if (idx == NULL)
    {
        ErrorMessage("AddTagNode(): Unable to allocate %u bytes of memory for new TagNode\n",
            (unsigned)sizeof(TagNode));
        return;
    }

    sfip_copy(idx->key.sip, p->ptrs.ip_api.get_src());
    sfip_copy(idx->key.dip, p->ptrs.ip_api.get_dst());
    idx->key.sp = p->ptrs.sp;
    idx->key.dp = p->ptrs.dp;
    idx->metric = tag->tag_metric;
    idx->last_access = now;
    idx->event_id = event_id;
    idx->event_time.tv_sec = p->pkth->ts.tv_sec;
    idx->event_time.tv_usec = p->pkth->ts.tv_usec;
    idx->mode = mode;
    idx->pkt_count = 0;
    idx->log_list = log_list;

    if (idx->metric & TAG_METRIC_SECONDS)
    {
        /* set the expiration time for this tag */
        idx->seconds = now + tag->tag_seconds;
    }

    if (idx->metric & TAG_METRIC_BYTES)
    {
        /* set the expiration time for this tag */
        idx->bytes = tag->tag_bytes;
    }

    if (idx->metric & TAG_METRIC_PACKETS)
    {
        /* set the expiration time for this tag */
        idx->packets = tag->tag_packets;
    }

    /* check for duplicates */
    returned = (TagNode*)sfxhash_find(tag_cache_ptr, idx);

    if (returned == NULL)
    {
        DebugMessage(DEBUG_FLOW,"Looking the other way!!\n");
        SwapTag(idx);
        returned = (TagNode*)sfxhash_find(tag_cache_ptr, idx);
        SwapTag(idx);
    }

    if (returned == NULL)
    {
        DebugMessage(DEBUG_FLOW,"Inserting a New Tag!\n");

        /* if we're supposed to be tagging the other side, swap it
           around -- Lawrence Reed */
        if (mode == TAG_HOST_DST)
        {
            SwapTag(idx);
        }

        if (sfxhash_add(tag_cache_ptr, idx, idx) != SFXHASH_OK)
        {
            DebugMessage(DEBUG_FLOW,
                "sfxhash_add failed, that's going to "
                "make life difficult\n");
            TagFree(tag_cache_ptr, idx);
            return;
        }
    }
    else
    {
        DebugMessage(DEBUG_FLOW,"Existing Tag found!\n");

        if (idx->metric & TAG_METRIC_SECONDS)
            returned->seconds = idx->seconds;
        else
            returned->seconds += idx->seconds;

        /* get rid of the new tag since we are using an existing one */
        TagFree(tag_cache_ptr, idx);
    }
}

int CheckTagList(Packet* p, Event* event, void** log_list)
{
    TagNode idx;
    TagNode* returned = NULL;
    SFXHASH* taglist = NULL;
    char create_event = 1;

    /* check for active tags */
    if (!sfxhash_count(host_tag_cache_ptr) && !sfxhash_count(ssn_tag_cache_ptr))
    {
        return 0;
    }

    if(p == NULL || !p->ptrs.ip_api.is_ip())
    {
        DebugMessage(DEBUG_FLOW, "bailing from CheckTagList, p->iph == NULL\n");
        return 0;
    }

    DebugFormat(DEBUG_FLOW,"Host Tags Active: %d   Session Tags Active: %d\n",
        sfxhash_count(host_tag_cache_ptr), sfxhash_count(ssn_tag_cache_ptr));

    DebugMessage(DEBUG_FLOW, "[*] Checking session tag list (forward)...\n");

    sfip_copy(idx.key.sip, p->ptrs.ip_api.get_src());
    sfip_copy(idx.key.dip, p->ptrs.ip_api.get_dst());
    idx.key.sp = p->ptrs.sp;
    idx.key.dp = p->ptrs.dp;

    /* check for session tags... */
    returned = (TagNode*)sfxhash_find(ssn_tag_cache_ptr, &idx);

    if (returned == NULL)
    {
        sfip_copy(idx.key.dip, p->ptrs.ip_api.get_src());
        sfip_copy(idx.key.sip, p->ptrs.ip_api.get_dst());
        idx.key.dp = p->ptrs.sp;
        idx.key.sp = p->ptrs.dp;

        DebugMessage(DEBUG_FLOW, "   Checking session tag list (reverse)...\n");
        returned = (TagNode*)sfxhash_find(ssn_tag_cache_ptr, &idx);

        if (returned == NULL)
        {
            DebugMessage(DEBUG_FLOW, "   Checking host tag list "
                "(forward)...\n");

            returned = (TagNode*)sfxhash_find(host_tag_cache_ptr, &idx);

            if (returned == NULL)
            {
                /*
                **  Only switch sip, because that's all we check for
                **  the host tags.
                */
                sfip_copy(idx.key.sip, p->ptrs.ip_api.get_src());

                returned = (TagNode*)sfxhash_find(host_tag_cache_ptr, &idx);
            }

            if (returned != NULL)
            {
                DebugMessage(DEBUG_FLOW,"   [*!*] Found host node\n");
                taglist = host_tag_cache_ptr;
            }
        }
        else
        {
            DebugMessage(DEBUG_FLOW,"   [*!*] Found session node\n");
            taglist = ssn_tag_cache_ptr;
        }
    }
    else
    {
        DebugMessage(DEBUG_FLOW,"   [*!*] Found session node\n");
        taglist = ssn_tag_cache_ptr;
    }

    if (returned != NULL)
    {
        DebugMessage(DEBUG_FLOW, "    ! Found tag node !\n");

        returned->last_access = p->pkth->ts.tv_sec;
        returned->pkt_count++;

        if ( returned->metric & TAG_METRIC_SECONDS )
        {
            if (p->pkth->ts.tv_sec > returned->seconds)
            {
                returned->metric = 0;
                create_event = 0;
            }
        }

        if ( returned->metric & TAG_METRIC_BYTES )
        {
            int n = p->pkth->caplen;
            if ( n < returned->bytes )
                returned->bytes -= n;
            else
                returned->metric = 0;
        }

        if ( returned->metric & TAG_METRIC_PACKETS )
        {
            if ( returned->packets > 1 )
                returned->packets--;
            else
                returned->metric = 0;
        }

        if ( !(returned->metric & TAG_METRIC_UNLIMITED) )
        {
            /* Check whether or not to actually log an event.
             * This is used to prevent a poorly written tag rule
             * from DOSing a backend event processors on high
             * bandwidth sensors. */
            /* Use the global max.
               If its non-0, check count for this tag node */
            if ( SnortConfig::get_tagged_packet_limit() &&
                returned->pkt_count >= SnortConfig::get_tagged_packet_limit() )
            {
                returned->metric = 0;
            }
        }

        if ( create_event )
        {
            /* set the event info */
            SetEvent(event, GENERATOR_TAG, TAG_LOG_PKT, 1, 1, 1,
                returned->event_id);
            /* set event reference details */
            event->ref_time.tv_sec = returned->event_time.tv_sec;
            event->ref_time.tv_usec = returned->event_time.tv_usec;
            event->event_reference = returned->event_id | SnortConfig::get_event_log_id();
            *log_list = returned->log_list;
        }

        if ( !returned->metric )
        {
            DebugMessage(DEBUG_FLOW,
                "    Prune condition met for tag, removing from list\n");

            if (sfxhash_remove(taglist, returned) != SFXHASH_OK)
            {
                LogMessage("WARNING: failed to remove tagNode from hash.\n");
            }
        }
    }

    if ( (u_int)(p->pkth->ts.tv_sec) > last_prune_time + TAG_PRUNE_QUANTUM )
    {
        DebugMessage(DEBUG_FLOW,
            "Exceeded Prune Quantum, pruning tag trees\n");
        PruneTagCache(p->pkth->ts.tv_sec, 0);
        last_prune_time = p->pkth->ts.tv_sec;
    }

    if ( returned && create_event )
        return 1;

    return 0;
}

static int PruneTagCache(uint32_t thetime, int mustdie)
{
    int pruned = 0;

    if (mustdie == 0)
    {
        if (sfxhash_count(ssn_tag_cache_ptr) != 0)
        {
            pruned = PruneTime(ssn_tag_cache_ptr, thetime);
        }

        if (sfxhash_count(host_tag_cache_ptr) != 0)
        {
            pruned += PruneTime(host_tag_cache_ptr, thetime);
        }
    }
    else
    {
        TagNode* lru_node = NULL;

        while (pruned < mustdie &&
            (sfxhash_count(ssn_tag_cache_ptr) > 0 || sfxhash_count(host_tag_cache_ptr) > 0))
        {
            if ((lru_node = (TagNode*)sfxhash_lru(ssn_tag_cache_ptr)) != NULL)
            {
                if (sfxhash_remove(ssn_tag_cache_ptr, lru_node) != SFXHASH_OK)
                {
                    LogMessage("WARNING: failed to remove tagNode from hash.\n");
                }
                pruned++;
            }
            if ((lru_node = (TagNode*)sfxhash_lru(host_tag_cache_ptr)) != NULL)
            {
                if (sfxhash_remove(host_tag_cache_ptr, lru_node) != SFXHASH_OK)
                {
                    LogMessage("WARNING: failed to remove tagNode from hash.\n");
                }
                pruned++;
            }
        }
    }

    return pruned;
}

static int PruneTime(SFXHASH* tree, uint32_t thetime)
{
    int pruned = 0;
    TagNode* lru_node = NULL;

    while ((lru_node = (TagNode*)sfxhash_lru(tree)) != NULL)
    {
        if ((lru_node->last_access + TAG_PRUNE_QUANTUM) < thetime)
        {
            if (sfxhash_remove(tree, lru_node) != SFXHASH_OK)
            {
                LogMessage("WARNING: failed to remove tagNode from hash.\n");
            }
            pruned++;
        }
        else
        {
            break;
        }
    }

    return pruned;
}

void SetTags(Packet* p, OptTreeNode* otn, uint16_t event_id)
{
    DebugMessage(DEBUG_FLOW, "Setting tags\n");

    if (otn != NULL && otn->tag != NULL)
    {
        if (otn->tag->tag_type != 0)
        {
            RuleTreeNode* rtn = getRuntimeRtnFromOtn(otn);
            void* log_list = rtn ? rtn->listhead : NULL;

            switch (otn->tag->tag_type)
            {
            case TAG_SESSION:
                DebugMessage(DEBUG_FLOW,"Setting session tag:\n");
                DebugFormat(DEBUG_FLOW,"SIP: %s  SP: %d   ",
                    sfip_ntoa(p->ptrs.ip_api.get_src()), p->ptrs.sp);
                DebugFormat(DEBUG_FLOW,"DIP: %s  DP: %d\n",
                    sfip_ntoa(p->ptrs.ip_api.get_dst()),p->ptrs.dp);
                TagSession(p, otn->tag, p->pkth->ts.tv_sec, event_id, log_list);
                break;
            case TAG_HOST:
                DebugMessage(DEBUG_FLOW,"Setting host tag:\n");
                DebugFormat(DEBUG_FLOW,"SIP: %s  SP: %d   ",
                    sfip_ntoa(p->ptrs.ip_api.get_src()),p->ptrs.sp);
                DebugFormat(DEBUG_FLOW, "DIP: %s  DP: %d\n",
                    sfip_ntoa(p->ptrs.ip_api.get_dst()),p->ptrs.dp);
                TagHost(p, otn->tag, p->pkth->ts.tv_sec, event_id, log_list);
                break;

            default:
                LogMessage("WARNING: Trying to tag with unknown "
                    "tag type.\n");
                break;
            }
        }
    }
}

