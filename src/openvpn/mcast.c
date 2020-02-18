/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "mcast.h"
#include "proto.h"
#include "list.h"
#include "mroute.h"

struct mcast_recipient_list
{
  struct mroute_addr rcpt;
  struct multi_instance *mi;
  struct mcast_recipient_list *next;
};

struct mcast_timeout_list
{
  struct mroute_addr * rcpt;
  uint32_t group;
  struct timeval timeout;
  struct mcast_timeout_list * next;
};

/** mcast hashing functions */
uint32_t mcast_addr_hash(const void *key, uint32_t iv)
{
  return (*(const int32_t *)key) % iv;
}

bool mcast_addr_compare(const void *key1, const void *key2)
{
  return (*(const int32_t *)key1) == (*(const int32_t *)key2);
}

/** initialization-stuff */
void mcast_init(struct multi_context *m)
{
  m->mcast_group_map = hash_init(4096, mcast_addr_hash, mcast_addr_compare);
  msg (D_MCAST_LOW, "MCAST: initialized multicast maps");
}

/** debug_output_functions */
void mcast_print_group_list(const struct multi_context *m, struct gc_arena *gc, uint32_t group)
{
  struct mcast_recipient_list * current_list;

  msg (D_MCAST_DEBUG, "MCAST: current recipients for group %s", print_in_addr_t (group, IA_EMPTY_IF_UNDEF, gc));

  for (current_list = (struct mcast_recipient_list *)hash_lookup(m->mcast_group_map, &group); current_list; current_list = current_list->next)
    msg (D_MCAST_DEBUG, "MCAST:   %s through %s", mroute_addr_print(&current_list->rcpt, gc), multi_instance_string(current_list->mi, false, gc));
}

void mcast_print_timeout_list(const struct multi_instance *mi, struct gc_arena *gc)
{
  struct mcast_timeout_list * current_list;

  msg (D_MCAST_DEBUG, "MCAST: current timeouts for multi-instance. (now = %s)", tv_string_abs(&((struct timeval){now,0}), gc));

  for (current_list = mi->mcast_timeouts; current_list; current_list = current_list->next)
    msg (D_MCAST_DEBUG, "MCAST:   (%s, %s) -> %s", mroute_addr_print(current_list->rcpt, gc), print_in_addr_t (current_list->group, IA_EMPTY_IF_UNDEF, gc), tv_string_abs(&current_list->timeout, gc));
}

/** functions to manipulate mcast-receiver-lists */
inline struct mcast_recipient_list * mcast__create_recv_list_item(struct multi_instance * mi, const struct mroute_addr * rcpt)
{
  struct mcast_recipient_list *list;
  ALLOC_OBJ(list, struct mcast_recipient_list);
  list->next = NULL;
  list->mi = mi;
  memcpy(&list->rcpt, rcpt, sizeof(struct mroute_addr));
  
  return list;
}

struct mcast_timeout_list * mcast__create_timeout_list_item(const uint32_t group, struct mroute_addr * rcpt)
{
  struct mcast_timeout_list * timeout;
  ALLOC_OBJ(timeout, struct mcast_timeout_list);
  timeout->group = group;
  timeout->rcpt = rcpt;
  timeout->timeout = (struct timeval){now + MCAST_TIMEOUT_INTERVAL,0};
  return timeout;
}

void mcast__update_time_for_recipient(struct multi_instance * mi, const uint32_t group, struct mroute_addr * rcpt)
{
  struct mcast_timeout_list **current_list;
  struct mcast_timeout_list * tmp_list;
  struct mcast_timeout_list * new_list_item = mcast__create_timeout_list_item(group, rcpt);

  mutex_lock(mi->mutex);

  current_list = &mi->mcast_timeouts; // Start with a pointer to the pointer to the first item.

  while ((*current_list) && tv_ge(&new_list_item->timeout, &(*current_list)->timeout))  // Continue while there exist a next item, and the next item is scheduled for removal later than the current. */
  {
    if (mroute_addr_equal((*current_list)->rcpt, rcpt) && ((*current_list)->group == group)) // If old item exist, remove it.
    {
      tmp_list = (*current_list)->next;
      free(*current_list);
      *current_list = tmp_list;
    }
    else
      current_list = &(*current_list)->next; // Bring up the next item in list
  }
  // We should now be positioned at the right spot in the list, just insert the new item.
  new_list_item->next = (*current_list);
  *current_list = new_list_item;

  mutex_unlock(mi->mutex);
}

void mcast__clean_times_for_recipient(struct multi_instance * mi, const uint32_t group, struct mroute_addr * rcpt)
{
  struct mcast_timeout_list **current_list;
  struct mcast_timeout_list * tmp_list;

  mutex_lock(mi->mutex);

  current_list = &mi->mcast_timeouts;  // Start with a pointer to the pointer to the first item.

  while (*current_list)  // Continue while there exist a next item
  {
    if (mroute_addr_equal((*current_list)->rcpt, rcpt) && (*current_list)->group == group) // If old item exist, remove it.
    {
      tmp_list = (*current_list)->next;
      free(*current_list);
      *current_list = tmp_list;
    }
    else
      current_list = &(*current_list)->next; // Bring up the next item in list
  }
  mutex_unlock(mi->mutex);
}

void mcast_add_rcpt(struct multi_context *m, const uint32_t group, const struct mroute_addr *rcpt, struct multi_instance * mi)
{
  struct gc_arena gc = gc_new ();
  struct mcast_recipient_list **list_item_ptr;

  mutex_lock(m->mutex);

  list_item_ptr = (struct mcast_recipient_list **)hash_lookup_ptr(m->mcast_group_map, &group);

  if (list_item_ptr) // Recipient list for this group already exist
  {
    while ((*list_item_ptr) && !mroute_addr_equal(rcpt, &(*list_item_ptr)->rcpt))
      list_item_ptr = &(*list_item_ptr)->next;

    if (*list_item_ptr)
    {
      /* TODO: Add timers and updates. */
      msg (D_MCAST_LOW, "MCAST: refreshed %s in group-list %s", mroute_addr_print(rcpt, &gc), print_in_addr_t (group, IA_EMPTY_IF_UNDEF, &gc));
    }
    else
    {
      *list_item_ptr = mcast__create_recv_list_item(mi, rcpt);
      msg (D_MCAST_LOW, "MCAST: added %s to group-list %s", mroute_addr_print(rcpt, &gc), print_in_addr_t (group, IA_EMPTY_IF_UNDEF, &gc));
    }
  }
  else // Create new mcast_recipient_list
  {
    struct mcast_recipient_list * new_list_item = mcast__create_recv_list_item(mi, rcpt);;
    uint32_t *group_cpy;
    ALLOC_OBJ(group_cpy, uint32_t)
    *group_cpy = group;
    list_item_ptr = &new_list_item;
    hash_add(m->mcast_group_map, group_cpy, new_list_item, false);
    msg (D_MCAST_LOW, "MCAST: created group-list %s for %s", print_in_addr_t (group, IA_EMPTY_IF_UNDEF, &gc), mroute_addr_print(rcpt, &gc));
  }
  mcast__update_time_for_recipient(mi, group, &(*list_item_ptr)->rcpt);
  mcast_print_group_list(m, &gc, group);

  mutex_unlock(m->mutex);
  gc_free(&gc);
}

void mcast_remove_rcpt(struct multi_context *m, const uint32_t group, const struct mroute_addr *rcpt, struct multi_instance * mi, bool clean_timeouts)
{
  struct gc_arena gc = gc_new();
  struct mcast_recipient_list ** list_item_ptr;
  struct mcast_recipient_list * next_item;
  struct mroute_addr rcpt_copy = *rcpt;

  mutex_lock(m->mutex);

  list_item_ptr = (struct mcast_recipient_list **)hash_lookup_ptr(m->mcast_group_map, &group);

  while (list_item_ptr && (*list_item_ptr) && !mroute_addr_equal(rcpt, &(*list_item_ptr)->rcpt))
    list_item_ptr = &(*list_item_ptr)->next;
  
  if (list_item_ptr && *list_item_ptr) // We found something
  {
    if (clean_timeouts)
      mcast__clean_times_for_recipient(mi, group, &(*list_item_ptr)->rcpt);

    next_item = (*list_item_ptr)->next;
    free(*list_item_ptr);
    *list_item_ptr = next_item;
  }

  msg (D_MCAST_LOW, "MCAST: removed %s from group %s", mroute_addr_print(&rcpt_copy, &gc), print_in_addr_t (group, IA_EMPTY_IF_UNDEF, &gc));

  mcast_print_group_list(m, &gc, group);

  mutex_unlock(m->mutex);

  gc_free(&gc);
}

void mcast_clean_old_groups(struct multi_context *m, struct multi_instance *mi, bool drop_all)
{
  struct mcast_timeout_list **current_list;
  struct mcast_timeout_list * tmp_list;
  struct timeval timeval_now = (struct timeval){now, 0};
  struct gc_arena gc = gc_new();

  update_time();

  mutex_lock(mi->mutex);

  current_list = &mi->mcast_timeouts; // Start with a pointer to the pointer to the first item.

  msg (D_MCAST_DEBUG, "Cleaning old groups for multi_instance");

  while ((*current_list) && (tv_ge(&timeval_now, &(*current_list)->timeout) || drop_all))  // Continue while there exist a next item, and either the next item is scheduled for removal before now, or we're due to clean out all joined groups*/
  {
    msg (D_MCAST_LOW, "MCAST: detected stale recipient %s in group %s", mroute_addr_print((*current_list)->rcpt, &gc), print_in_addr_t ((*current_list)->group, IA_EMPTY_IF_UNDEF, &gc));
    mcast_remove_rcpt(m, (*current_list)->group, (*current_list)->rcpt, mi, false); // If old item exist, remove it.

    tmp_list = (*current_list)->next;
    free(*current_list);
    *current_list = tmp_list;
  }
  mcast_print_timeout_list(mi, &gc);
  mutex_unlock(mi->mutex);
  gc_free(&gc);
}

/** functions to parse possible IGMP-headers */
void mcast_igmp_snoop(struct multi_context *m, struct multi_instance * mi, const struct openvpn_igmpv3hdr *igmp, const void * buf_end, const struct mroute_addr *src_addr)
{
  uint16_t i;
  struct openvpn_igmpv3_record_hdr * record;

  update_time();

  if (mi)
    mcast_clean_old_groups(m, mi, false);

  switch (igmp->type)
  {
    case OPENVPN_IGMP_QUERY:
      msg(D_MCAST_DEBUG, "MCAST: saw IGMP query message");
      break;
    case OPENVPN_IGMP_REPORT_V2:
      mcast_add_rcpt(m, ntohl(igmp->data.igmpv2_group_addr), src_addr, mi);
      break;
    case OPENVPN_IGMP_LEAVE_V2:
      mcast_remove_rcpt(m, ntohl(igmp->data.igmpv2_group_addr), src_addr, mi, true);
      break;
    case OPENVPN_IGMP_REPORT_V3:
      record = (struct openvpn_igmpv3_record_hdr*)((void *)igmp + sizeof(struct openvpn_igmpv3hdr));
      for (i = 0; (i < ntohs(igmp->data.igmpv3_num_records)) && ((((void *)record) + sizeof(struct openvpn_igmpv3_record_hdr)) <= buf_end); i++)
      {
        switch (record->type)
        {
          case OPENVPN_IGMPV3_FILTER_CHANGE_TO_INCLUDE:
            mcast_remove_rcpt(m, ntohl(record->group_address), src_addr, mi, true);
            break;
          case OPENVPN_IGMPV3_FILTER_CHANGE_TO_EXCLUDE:
            mcast_add_rcpt(m, ntohl(record->group_address), src_addr, mi);
            break;
        }
        record = ((void *)record) + sizeof(struct openvpn_igmpv3hdr) + 4*(record->aux_len + record->num_sources);
      }
      break;
  }
}

/** functions to quickly filter out IGMP-packets **/
const struct openvpn_iphdr * mcast_pkt_is_ip(const struct buffer *buf)
{
  if (BLEN(buf) >= sizeof(struct openvpn_ethhdr) + sizeof(struct openvpn_iphdr))
  {
    if (ntohs(((struct openvpn_ethhdr *)BPTR(buf))->proto) == OPENVPN_ETH_P_IPV4)
      return (const struct openvpn_iphdr *)(BPTR(buf) + sizeof(struct openvpn_ethhdr));
  }
  return NULL;
}

const struct openvpn_igmpv3hdr* mcast_pkt_is_igmp(const struct buffer *buf)
{
  const struct openvpn_iphdr *ip;
  if (ip = mcast_pkt_is_ip(buf))
  {
    if ((ip->protocol == OPENVPN_IPPROTO_IGMP) && (BLEN(buf) >= (sizeof(struct openvpn_ethhdr) + ntohs(ip->tot_len))))
      return (const struct openvpn_igmpv3hdr *)openvpn_ip_payload(ip);
  }
  return NULL;
}

/** functions hash multi_instances */
uint32_t multi_instance_hash(const void *key, uint32_t iv)
{
  return (uint32_t)key % iv;
}

bool multi_instance_compare(const void *key1, const void *key2)
{
  return key1 == key2;
}

/** functions to actually use the learnt mcast-forward-lists */
void mcast_send(struct multi_context *m,
		  const struct buffer *buf,
		  struct multi_instance *omit)
{
  struct multi_instance *mi;
  struct mbuf_buffer *mb;
  struct hash *output_instances;
  const struct openvpn_iphdr *ip;
  uint32_t group_address;
  struct mcast_recipient_list * rcpt_list;
  struct gc_arena gc = gc_new ();

  if (ip = mcast_pkt_is_ip(buf))
    {
      group_address = ntohl(ip->daddr);

      msg (D_MULTI_DEBUG, "MCAST: sending packet to group %s", print_in_addr_t (group_address, IA_EMPTY_IF_UNDEF, &gc));

      mutex_lock(m->mutex);

      rcpt_list = (struct mcast_recipient_list *)hash_lookup(m->mcast_group_map, &group_address);
      if (rcpt_list)
      {
        perf_push (PERF_MULTI_MCAST);
#ifdef MULTI_DEBUG_EVENT_LOOP
        printf ("MCAST len=%d\n", BLEN (buf));
#endif
        mb = mbuf_alloc_buf (buf);
        output_instances = hash_init(16, multi_instance_hash, multi_instance_compare);
  
  
        while (rcpt_list)
        {
          mi = rcpt_list->mi;
          if (mi != omit && !mi->halt && hash_add(output_instances, mi, mi, false)) // Should send here
            multi_add_mbuf (m, mi, mb);
          rcpt_list = rcpt_list->next;
        }
  
        hash_free(output_instances);
        mbuf_free_buf (mb);
        perf_pop ();
  
        mutex_unlock(m->mutex);
      }
    }

    gc_free(&gc);
}

void mcast_disconnect(struct multi_context *m, struct multi_instance *mi)
{
  struct gc_arena gc = gc_new ();

  // Free dangling multicast-groups
  mcast_clean_old_groups(m, mi, true);

  msg (D_MCAST_DEBUG, "MCAST: Disconnect: %s has left the building.", multi_instance_string(mi, false, &gc));

  gc_free(&gc);
}
