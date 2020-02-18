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

#ifndef MCAST_H
#define MCAST_H

#include "buffer.h"
#include "list.h"
#include "multi.h"

#define MCAST_TIMEOUT_INTERVAL 80  // The timeout interval in seconds, when a member of a group is considered dead. (Should really be aquired by following the IGMP query-pulses from the Designated Router)

void mcast_init();

const struct openvpn_igmpv3hdr * mcast_pkt_is_igmp(const struct buffer *buf);

void mcast_igmp_snoop(struct multi_context *m, struct multi_instance * mi, const struct openvpn_igmpv3hdr *igmp, const void * buf_end, const struct mroute_addr *src_addr);

void mcast_send(struct multi_context *m,
		  const struct buffer *buf,
		  struct multi_instance *omit);

void mcast_clean_old_groups(struct multi_context *m, struct multi_instance *mi, bool drop_all);

void mcast_disconnect(struct multi_context *m, struct multi_instance *mi);

#endif /* MCAST_H */
