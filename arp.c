/* parprouted: ProxyARP routing daemon. 
 * (C) 2008 Vladimir Ivaschenko <vi@maks.net>
 *
 * This application is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

#include "parprouted.h"

typedef struct _ether_arp_frame { 
	struct ether_header ether_hdr;
	struct ether_arp arp;
} __attribute__ ((packed)) ether_arp_frame;

typedef struct _req_struct {
	ether_arp_frame req_frame;
	struct sockaddr_ll req_if;
	struct _req_struct *next;
} RQ_ENTRY;

RQ_ENTRY *req_queue = NULL;
RQ_ENTRY *req_queue_tail = NULL;
int req_queue_len = 0;
pthread_mutex_t req_queue_mutex;

/* Check if the IP address exists in the arptab */

int ipaddr_known(ARPTAB_ENTRY *list, struct in_addr addr, char *ifname) 
{
	while (list != NULL) {
		/* If we have this address in the table and ARP request comes from a
       different interface, then we can reply */
		if ( addr.s_addr == list->ipaddr_ia.s_addr &&
				strcmp(ifname, list->ifname) &&
				list->incomplete == 0) {
			return 1;
		}
		list = list->next;
	}

	if (debug)
		printf ("Did not find match for %s(%s)\n", inet_ntoa(addr), ifname);

	return 0;
}

/* Wait for an ARP packet */

int arp_recv(int sock, ether_arp_frame *frame) 
{
	char packet[4096];
	int nread;

	nread=recv(sock, &packet, sizeof(packet), 0);

	if (nread > (int)sizeof(ether_arp_frame)) {
		nread=sizeof(ether_arp_frame);
	}

	memcpy(frame, &packet, nread);

	if (nread < (int)sizeof(ether_arp_frame)) {
		memset(((char*)frame) + nread, 0, sizeof(ether_arp_frame) - nread);
	}

	return nread;
}

/* Send ARP is-at reply */

void arp_reply(ether_arp_frame *reqframe, struct sockaddr_ll *ifs) 
{
	struct ether_arp *arp = &reqframe->arp;
	unsigned char ip[4];
	int sock;

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

	if (bind(sock, (struct sockaddr *) ifs, sizeof(struct sockaddr_ll)) < 0) {
		fprintf(stderr, "arp_reply() bind: %s\n", strerror(errno));
		abort();
	}
	
	memcpy(reqframe->ether_hdr.ether_dhost, arp->arp_sha, ETH_ALEN);
	memcpy(reqframe->ether_hdr.ether_shost, ifs->sll_addr, ETH_ALEN);

	memcpy(arp->arp_tha, arp->arp_sha, ETH_ALEN);
	memcpy(arp->arp_sha, ifs->sll_addr, ETH_ALEN);

	memcpy(ip, arp->arp_spa, 4);
	memcpy(arp->arp_spa, arp->arp_tpa, 4);
	memcpy(arp->arp_tpa, ip, 4);

	arp->arp_op = htons(ARPOP_REPLY);

	if (debug) {
		struct in_addr sia = {	.s_addr =  *((in_addr_t *)arp->arp_spa) };
		struct in_addr dia = {	.s_addr =  *((in_addr_t *)arp->arp_tpa) };
		struct ifreq ifr = { .ifr_ifindex = ifs->sll_ifindex };
		if (ioctl(sock, SIOCGIFNAME, &ifr) < 0) {
			syslog(LOG_ERR, "%s() error: %s %s for %d: %s", __FUNCTION__, "ioctl", "SIOCGIFNAME",
					ifs->sll_ifindex, strerror(errno));
		} else {
			char *str = strdup(inet_ntoa(dia)); 
			printf("Replying to %s(%s) faking %s\n", str, ifr.ifr_name, inet_ntoa(sia));
			free(str);
		}
	}

	sendto(sock, reqframe, sizeof(ether_arp_frame), 0,
			(struct sockaddr *)ifs, sizeof(struct sockaddr_ll));

	close(sock);
}

/* Send ARP who-has request */

void arp_req(char *ifname, struct in_addr remaddr, int gratuitous)
{
	ether_arp_frame frame;
	struct ether_arp *arp = &frame.arp;
	int sock, i;
	struct sockaddr_ll ifs;
	struct ifreq ifr;
	unsigned long ifaddr;
	struct sockaddr_in *sin;

	/* Get the hwaddr of the interface */
	for (i=0; i <= last_iface_idx; i++) {
		if (strcmp(ifaces[i], ifname) == 0) {
			memcpy(ifs.sll_addr, iface_addrs[i], ETH_ALEN);
			break;
		}
	}
	if (i > last_iface_idx) {
		syslog(LOG_WARNING, "%s() error: %s %s for %s: %s", __FUNCTION__, "interface not found", "", ifname, "");
		syslog(LOG_INFO, "%s(): %d ifaces", __FUNCTION__, last_iface_idx + 1);
		for (i=0; i <= last_iface_idx; i++)
			syslog(LOG_INFO, "%s() %d: %s", __FUNCTION__, i, ifaces[i]);
		abort();
	}

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

	/* Get the ifindex of the interface */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		syslog(LOG_ERR, "%s() error: %s %s for %s: %s", __FUNCTION__, "ioctl", "SIOCGIFINDEX",
				ifname, strerror(errno));
		abort();
	}

	ifs.sll_family = AF_PACKET;
	ifs.sll_protocol = htons(ETH_P_ARP);
	ifs.sll_ifindex = ifr.ifr_ifindex;
	ifs.sll_hatype = ARPHRD_ETHER;
	ifs.sll_pkttype = PACKET_BROADCAST;
	ifs.sll_halen = ETH_ALEN;

	if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
		sin = (struct sockaddr_in *) &ifr.ifr_addr;
		ifaddr = sin->sin_addr.s_addr;
	} else {
		syslog(LOG_ERR, "%s() error: %s %s for %s: %s", __FUNCTION__, "ioctl", "SIOCGIFADDR",
				ifname, strerror(errno));
		abort();
	}

	memset(frame.ether_hdr.ether_dhost, 0xFF, ETH_ALEN);
	memcpy(frame.ether_hdr.ether_shost, ifs.sll_addr, ETH_ALEN);
	frame.ether_hdr.ether_type = htons(ETHERTYPE_ARP);

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = 6;
	arp->arp_pln = 4;
	memset(arp->arp_tha, 0, ETH_ALEN);
	memcpy(arp->arp_sha, ifs.sll_addr, ETH_ALEN);

	memcpy(arp->arp_tpa, &remaddr.s_addr, 4);
	if (gratuitous)
		memcpy(arp->arp_spa, &remaddr.s_addr, 4);
	else
		memcpy(arp->arp_spa, &ifaddr, 4);

	arp->arp_op = htons(ARPOP_REQUEST);

	if (debug)
		printf("Sending ARP request for %s to %s\n", inet_ntoa(remaddr), ifname);
	sendto(sock, &frame, sizeof(ether_arp_frame), 0,
			(struct sockaddr *) &ifs, sizeof(struct sockaddr_ll));
	close(sock);

}

/* ARP ping all entries in the table */

void refresharp(ARPTAB_ENTRY *list)
{
	if (debug)
		printf("Refreshing ARP entries.\n");

	while (list != NULL) {
		list->removed_due_to_conflict = false;
		arp_req(list->ifname, list->ipaddr_ia, 0);
		list = list->next;
	}
}


int rq_add(ether_arp_frame *req_frame, struct sockaddr_ll *req_if)
{
	RQ_ENTRY *new_entry;

	if ((new_entry = (RQ_ENTRY *) malloc(sizeof(RQ_ENTRY))) == NULL) {
		syslog(LOG_INFO, "No memory: %s", strerror(errno));
		return 0;
	}

	pthread_mutex_lock(&req_queue_mutex);

	req_queue_len++;

	/* Check if the list has more entries than MAX_RQ_SIZE,
	 * and delete the oldest entry */
	if (req_queue_len > MAX_RQ_SIZE) {
		RQ_ENTRY *temp;

		if (debug)
			printf("Request queue has grown too large, deleting last element\n");
		temp = req_queue;
		req_queue = req_queue->next;
		req_queue_len--;

		free(temp);
	}

	/* Add entry to the list */

	if (req_queue != NULL)
		req_queue_tail->next = new_entry;
	else
		req_queue = new_entry;

	req_queue_tail = new_entry;

	new_entry->next = NULL;

	memcpy(&new_entry->req_frame, req_frame, sizeof(ether_arp_frame));
	memcpy(&new_entry->req_if, req_if, sizeof(struct sockaddr_ll));

	pthread_mutex_unlock(&req_queue_mutex);

	return 1;
}

void rq_process(struct in_addr ipaddr, int ifindex) 
{
	RQ_ENTRY *cur_entry;
	RQ_ENTRY *prev_entry = NULL;

	pthread_mutex_lock(&arptab_mutex);
	parseproc();
	processarp(0);
	pthread_mutex_unlock(&arptab_mutex);

	pthread_mutex_lock(&req_queue_mutex);

	cur_entry = req_queue;

	/* Walk through the list */

	while (cur_entry != NULL) {
		if (memcmp(&ipaddr, cur_entry->req_frame.arp.arp_tpa, sizeof(ipaddr)) == 0 && ifindex != cur_entry->req_if.sll_ifindex) {

			if (debug)
				printf("Found %s in request queue\n", inet_ntoa(ipaddr));
			arp_reply(&cur_entry->req_frame, &cur_entry->req_if);

			/* Delete entry from the linked list */

			if (cur_entry == req_queue_tail)
				req_queue_tail = prev_entry;

			if (prev_entry != NULL)
				prev_entry->next = cur_entry->next;
			else
				req_queue = cur_entry->next;

			free(cur_entry);
			cur_entry = prev_entry;

			req_queue_len--;
		}

		if (cur_entry != NULL) {
			prev_entry = cur_entry;
			cur_entry = cur_entry->next;
		} else if (prev_entry == NULL) {
			cur_entry = req_queue;
		}
	}

	pthread_mutex_unlock(&req_queue_mutex);
}

void remove_arp(struct in_addr ipaddr, const char* ifname)
{
	int arpsock;
	struct arpreq k_arpreq = { .arp_flags = ATF_PERM };				
	struct sockaddr_in *sin = ((struct sockaddr_in *) &k_arpreq.arp_pa);
	if ((arpsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "%s() error: %s %s for %s: %s", __FUNCTION__, "socket", "",
				ifname, strerror(errno));
	} else {
		strncpy(k_arpreq.arp_dev, ifname, IFNAMSIZ);
		k_arpreq.arp_pa.sa_family = AF_INET;
		memcpy(&sin->sin_addr, &ipaddr, sizeof(ipaddr));
		if (ioctl(arpsock, SIOCDARP, &k_arpreq) < 0) {
			if (debug)
				printf("%s() error: %s %s for %s(%s): %s", __FUNCTION__, "ioctl", "SIOCDARP",
					inet_ntoa(ipaddr), ifname, strerror(errno));
		}
	}
	close(arpsock);
}

void *arp(char *ifname) 
{
	int sock,i;
	struct sockaddr_ll ifs;
	struct ifreq ifr;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

	/* Get the hwaddr and ifindex of the interface */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		syslog(LOG_ERR, "%s() error: %s %s for %s: %s", __FUNCTION__, "ioctl", "SIOCGIFHWADDR",
				ifname, strerror(errno));
		abort();
	}

	memcpy(ifs.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	for (i=0; i <= last_iface_idx; i++) {
		if (ifaces[i] == ifname) {
			memcpy(iface_addrs[i], ifr.ifr_hwaddr.sa_data, ETH_ALEN);
			break;
		}
	}

	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		syslog(LOG_ERR, "%s() error: %s %s for %s: %s", __FUNCTION__, "ioctl", "SIOCGIFINDEX",
				ifname, strerror(errno));
		abort();
	}

	ifs.sll_family = AF_PACKET;
	ifs.sll_protocol = htons(ETH_P_ARP);
	ifs.sll_ifindex = ifr.ifr_ifindex;
	ifs.sll_hatype = ARPHRD_ETHER;
	ifs.sll_pkttype = PACKET_BROADCAST;
	ifs.sll_halen = ETH_ALEN;

	if (bind(sock, (struct sockaddr *)&ifs, sizeof(struct sockaddr_ll)) < 0) {
		fprintf(stderr, "Bind %s: %d\n", ifname, errno);
		abort();
	}

	while (1) {
		ether_arp_frame frame;
		unsigned long src;
		unsigned long dst;
		struct in_addr sia;
		struct in_addr dia;

		do {
			pthread_testcancel();
			/* Sleep a bit in order not to overload the system */
			usleep(300);

			if (arp_recv(sock, &frame) <= 0)
				continue;

			/* Fail upon receiving messages from other interfaces of this device */
			for (i=0; i <= last_iface_idx; i++) {
				if (memcmp(iface_addrs[i], frame.ether_hdr.ether_shost, ETH_ALEN) == 0) {
					syslog(LOG_ERR, "%s() error: %s %s for %s: %s", __FUNCTION__, "Received message that was generated locally", "",
							ifname, "Shutdown to avoid ARP/IP conflict catastrophe");
					perform_shutdown=1;
					frame.arp.arp_op = 0;
					break;
				}
			}

			/* Insert all the replies into ARP table */
			if (frame.arp.arp_op == ntohs(ARPOP_REPLY)) {

				/* Received frame is an ARP reply */

				struct arpreq k_arpreq;
				int arpsock;
				struct sockaddr_in *sin;

				if ((arpsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
					syslog(LOG_ERR, "%s() error: %s %s for %s: %s", __FUNCTION__, "socket", "",
							ifname, strerror(errno));
					continue;
				}

				k_arpreq.arp_ha.sa_family = ARPHRD_ETHER;
				memcpy(k_arpreq.arp_ha.sa_data, frame.arp.arp_sha, ETH_ALEN);
				k_arpreq.arp_flags = ATF_COM;
				if (option_arpperm)
					k_arpreq.arp_flags = k_arpreq.arp_flags | ATF_PERM;
				strncpy(k_arpreq.arp_dev, ifname, IFNAMSIZ);

				k_arpreq.arp_pa.sa_family = AF_INET;
				sin = (struct sockaddr_in *) &k_arpreq.arp_pa;
				memcpy(&sin->sin_addr.s_addr, &frame.arp.arp_spa, sizeof(sin->sin_addr));

				/* Update kernel ARP table with the data from reply */
				if (debug)
					printf("Received reply: updating kernel ARP table for %s(%s).\n", inet_ntoa(sin->sin_addr), ifname);
				if (ioctl(arpsock, SIOCSARP, &k_arpreq) < 0) {
					syslog(LOG_ERR, "%s() error: %s %s for %s(%s): %s", __FUNCTION__, "ioctl", "SIOCSARP",
							inet_ntoa(sin->sin_addr), ifname, strerror(errno));
					close(arpsock);
					continue;
				}
				close(arpsock);

				/* Check if reply is for one of the requests in request queue */
				rq_process(sin->sin_addr, ifs.sll_ifindex);

				/* send gratuitous arp request to all other interfaces to let them
				 * update their ARP tables quickly */
				for (i=0; i <= last_iface_idx; i++) {
					if (ifaces[i] != ifname) {
						arp_req(ifaces[i], sin->sin_addr, 1);
					}
				}
			}
		} while (frame.arp.arp_op != htons(ARPOP_REQUEST));

		/* Received frame is an ARP request */

		memcpy(&src,(char *)frame.arp.arp_spa,4);
		memcpy(&dst,(char *)frame.arp.arp_tpa,4);

		dia.s_addr = dst;
		sia.s_addr = src;

		if (debug)
			printf("Received ARP request for %s on iface %s from sender %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", inet_ntoa(dia), ifname, frame.arp.arp_sha[0], frame.arp.arp_sha[1], frame.arp.arp_sha[2], frame.arp.arp_sha[3], frame.arp.arp_sha[4], frame.arp.arp_sha[5]);

		if (memcmp(ifs.sll_addr, frame.arp.arp_sha, ETH_ALEN) == 0) {
			if (debug) printf("Ignoring ARP request which has the iface mac address as the sender\n");
		} else if (memcmp(&dia, &sia, sizeof(dia)) && dia.s_addr != 0) {
			pthread_mutex_lock(&arptab_mutex);
			/* Relay the ARP request to all other interfaces */
			for (i=0; i <= last_iface_idx; i++) {
				if (ifaces[i] != ifname) {
					arp_req(ifaces[i], dia, 0);
				}
			}
			/* Add the request to the request queue */
			if (debug)
				printf("Adding %s to request queue\n", inet_ntoa(sia));
			rq_add(&frame, &ifs);
			pthread_mutex_unlock(&arptab_mutex);
		}
	}
}
