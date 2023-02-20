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
 *
 */

#include <getopt.h>
#include "parprouted.h"

char *progname;
int debug=0;
int verbose=0;
int option_arpperm=0;
int perform_shutdown=0;
int exit_code = EXIT_SUCCESS;

pthread_t my_threads[MAX_IFACES+1];
int last_thread_idx=-1;

char * ifaces[MAX_IFACES];
char iface_addrs[MAX_IFACES][ETH_ALEN];
int last_iface_idx=-1;

ARPTAB_ENTRY **arptab;
pthread_mutex_t arptab_mutex;

ARPTAB_ENTRY * replace_entry(struct in_addr ipaddr, char *dev) 
{
	ARPTAB_ENTRY * cur_entry=*arptab;
	ARPTAB_ENTRY * prev_entry=NULL;

	while (cur_entry != NULL && (ipaddr.s_addr != cur_entry->ipaddr_ia.s_addr || (strcmp(dev, cur_entry->ifname) != 0))) {
		prev_entry = cur_entry;
		cur_entry = cur_entry->next;
	}

	if (cur_entry == NULL) {
		if (debug) printf("Creating new ARP table entry %s(%s)\n", inet_ntoa(ipaddr), dev);

		if ((cur_entry = (ARPTAB_ENTRY *) calloc(1, sizeof(ARPTAB_ENTRY))) == NULL) {
			syslog(LOG_INFO, "No memory: %s", strerror(errno));
			abort();
		} else {
			if (prev_entry == NULL) { *arptab=cur_entry; }
			else { prev_entry->next = cur_entry; }
			cur_entry->want_route = true;
		}
	}

	return cur_entry;
}

bool findentry(struct in_addr ipaddr)
{
	ARPTAB_ENTRY * cur_entry=*arptab;

	while (cur_entry != NULL && ipaddr.s_addr != cur_entry->ipaddr_ia.s_addr) {
		cur_entry = cur_entry->next;
	}

	return cur_entry != NULL;
}

/* Remove all other entries in arptab using the same ipaddr */
int remove_other_routes(ARPTAB_ENTRY * entry)
{
	ARPTAB_ENTRY * other_entry;
	int removed = 0;
	bool conflicted = false;
	for (other_entry=*arptab; other_entry != NULL; other_entry = other_entry->next) {
		if (entry != other_entry && entry->ipaddr_ia.s_addr == other_entry->ipaddr_ia.s_addr) {
			if (debug) printf("Marking entry %s(%s) for removal %s\n", inet_ntoa(other_entry->ipaddr_ia), other_entry->ifname, other_entry->want_route ? "want_route" : "");
			other_entry->want_route = 0;
			++removed;
			conflicted |= !other_entry->incomplete;
			remove_arp(other_entry->ipaddr_ia, other_entry->ifname);
		}
	}
	if (conflicted) {
		if (!entry->removed_due_to_conflict) {
			//Reset to false again in refresharp()
			if (debug) printf("ARP entry %s(%s) had conflicting entries\n", inet_ntoa(entry->ipaddr_ia), entry->ifname);
			entry->removed_due_to_conflict = true;
		} else {
			//If the address is found on multiple network interfaces then running parprouted can result in chaos,
			//so it is better to exit instead.
			syslog(LOG_ERR, "Exiting due to potential clash with %s(%s)", inet_ntoa(entry->ipaddr_ia), entry->ifname);
			exit_code = EXIT_FAILURE;
			perform_shutdown=1;
		}
	}
	return removed;
}


/* Remove route from kernel */
bool route_remove(ARPTAB_ENTRY* cur_entry)
{
	char routecmd_str[ROUTE_CMD_LEN];
	bool success = false;

	if (snprintf(routecmd_str, ROUTE_CMD_LEN-1,
			"/sbin/ip route del %s/32 metric 50 dev %s scope link",
			inet_ntoa(cur_entry->ipaddr_ia), cur_entry->ifname) <= ROUTE_CMD_LEN-1) {
		if (system(routecmd_str) != 0) {
			syslog(LOG_INFO, "'%s' unsuccessful!", routecmd_str);
			if (debug) printf("%s failed\n", routecmd_str);
		} else {
			if (debug) printf("%s success\n", routecmd_str);
			success = true;
			cur_entry->route_added = false;
		}
	}
	return success;
}

/* Add route into kernel */
bool route_add(ARPTAB_ENTRY* cur_entry)
{
	char routecmd_str[ROUTE_CMD_LEN];
	bool success = false;

	if (snprintf(routecmd_str, ROUTE_CMD_LEN-1,
			"/sbin/ip route add %s/32 metric 50 dev %s scope link",
			inet_ntoa(cur_entry->ipaddr_ia), cur_entry->ifname) <= ROUTE_CMD_LEN-1) {
		if (system(routecmd_str) != 0) {
			syslog(LOG_INFO, "'%s' unsuccessful, will try to remove!", routecmd_str);
			if (debug) printf("%s failed\n", routecmd_str);
			route_remove(cur_entry);
		} else {
			if (debug) printf("%s success\n", routecmd_str);
			success = true;
			cur_entry->route_added = true;
		}
	}
	return success;
}

void processarp(int in_cleanup) 
{
	ARPTAB_ENTRY *cur_entry=*arptab, *prev_entry=NULL;

	/* First loop to remove unwanted routes */
	while (cur_entry != NULL) {
		if (debug && verbose) printf("Working on ARP entry %s(%s) tstamp %u %s\n", inet_ntoa(cur_entry->ipaddr_ia), cur_entry->ifname, (int) cur_entry->tstamp, cur_entry->want_route ? "want_route" : "");

		if (!cur_entry->want_route || in_cleanup || time(NULL) - cur_entry->tstamp > ARP_TABLE_ENTRY_TIMEOUT) {

			if (cur_entry->route_added)
				route_remove(cur_entry);

			/* remove from arp list */
			if (debug) printf("Remove %sARP entry %s(%s)\n", cur_entry->incomplete ? "incomplete " : "", inet_ntoa(cur_entry->ipaddr_ia), cur_entry->ifname);
			if (cur_entry->incomplete)
				remove_arp(cur_entry->ipaddr_ia, cur_entry->ifname);
			
			if (prev_entry != NULL) {
				prev_entry->next = cur_entry->next;
				free(cur_entry);
				cur_entry=prev_entry->next;
			} else {
				*arptab = cur_entry->next;
				free(cur_entry);
				cur_entry=*arptab;
			}
		} else {
			prev_entry = cur_entry;
			cur_entry = cur_entry->next;
		}
	} /* while loop */

	/* Now loop to add new routes */
	cur_entry=*arptab;
	while (cur_entry != NULL) {
		if (cur_entry->want_route && !cur_entry->route_added && !in_cleanup 
			&& time(NULL) - cur_entry->tstamp <= ARP_TABLE_ENTRY_TIMEOUT)
		{
			/* add route to the kernel */
			route_add(cur_entry);
		}
		cur_entry = cur_entry->next;
	} /* while loop */

}	

void parseproc()
{
	FILE *arpf;
	bool firstline = true;
	ARPTAB_ENTRY *entry;
	char line[ARP_LINE_LEN];
	struct in_addr ipaddr;
	bool incomplete = false;
	int i;
	char *ip, *mac, *dev;
	__attribute__((unused)) char *hw, *flags, *mask;

	/* Parse /proc/net/arp table */

	if ((arpf = fopen(PROC_ARP, "r")) == NULL)
		syslog(LOG_INFO, "Error during ARP table open: %s", strerror(errno));

	while (!feof(arpf)) {

		if (fgets(line, ARP_LINE_LEN, arpf) == NULL) {
			if (!ferror(arpf))
				break;
			else
				syslog(LOG_INFO, "Error during ARP table open: %s", strerror(errno));
		} else {
			if (firstline) { firstline=false; continue; }
			if (debug && verbose) printf("ARP line: %s", line);
			
			/* IP address */
			ip=strtok(line, " ");
			if ((inet_aton(ip, &ipaddr)) == -1)
				syslog(LOG_INFO, "Error parsing IP address %s", ip);
			
			/* HW type */
			hw=strtok(NULL, " ");

			/* Flags */
			flags=strtok(NULL, " ");

			/* HW address */
			mac=strtok(NULL, " ");

			/* Mask */
			mask=strtok(NULL, " ");

			/* Device */
			dev=strtok(NULL, " ");
			if (dev[strlen(dev)-1] == '\n') { dev[strlen(dev)-1] = '\0'; }
			
			/* Incomplete ARP entries with MAC 00:00:00:00:00:00
			 * Incomplete entries having flag 0x0 */
			incomplete = strcmp(mac, "00:00:00:00:00:00") == 0 || strcmp(flags, "0x0") == 0;
			
			/* Ignore ARP entries for unhandled ifaces */
			for (i=0; i <= last_iface_idx; i++)
				if (strcmp(ifaces[i], dev) == 0)
					break;
			if (i>last_iface_idx) {
				if (debug && verbose) printf("Ignoring interface %s\n", dev);
				continue;
			}
			
			/* if the IP address is marked as undiscovered and does not exist in arptab then
			 * send an ARP request to all ifaces */
			if (incomplete && !findentry(ipaddr)) {
				if (debug) printf("ARP entry %s(%s) is incomplete, requesting on all interfaces\n", ip, dev);
				for (i=0; i <= last_iface_idx; i++)
					arp_req(ifaces[i], ipaddr, 0);
			}

			entry=replace_entry(ipaddr, dev);

			if (entry->incomplete != incomplete && debug)
				printf("ARP entry %s(%s) now %scomplete\n", ip, dev, incomplete ? "in" : "");

			entry->ipaddr_ia.s_addr = ipaddr.s_addr;
			entry->incomplete = incomplete;

			if (strlen(mac) < ARP_TABLE_ENTRY_LEN)
				strncpy(entry->hwaddr, mac, ARP_TABLE_ENTRY_LEN);
			else
				syslog(LOG_INFO, "Error during ARP table parsing");

			if (strlen(dev) < ARP_TABLE_ENTRY_LEN)
				strncpy(entry->ifname, dev, ARP_TABLE_ENTRY_LEN);
			else
				syslog(LOG_INFO, "Error during ARP table parsing");

			/* do not add routes for incomplete entries */
			if (debug && entry->want_route != !incomplete)
				printf("%s(%s): set want_route %d\n", inet_ntoa(entry->ipaddr_ia), entry->ifname, !incomplete);
			entry->want_route = !incomplete;

			/* Remove route from kernel if it already exists through a different interface */
			if (entry->want_route) {
				if (remove_other_routes(entry) > 0) {
					if (debug) printf("Complete ARP entry for %s(%s) - entries via other interfaces removed\n", inet_ntoa(entry->ipaddr_ia), entry->ifname);
				}
			}

			time(&entry->tstamp);

			if (debug && !entry->route_added && entry->want_route) {
				printf("ARP entry: '%s' HWAddr: '%s' Dev: '%s' !route_added want_route\n",
						inet_ntoa(entry->ipaddr_ia), entry->hwaddr, entry->ifname);
			}
		}
	}

	if (fclose(arpf))
		syslog(LOG_INFO, "Error during ARP table open: %s", strerror(errno));
}

void cleanup() 
{
	syslog(LOG_INFO, "Received signal; cleaning up.");
//	for (i=0; i <= last_thread_idx; i++) {
//		pthread_cancel(my_threads[i]);
//	}
	pthread_mutex_trylock(&arptab_mutex);
	processarp(1);
	syslog(LOG_INFO, "Terminating.");
	exit(exit_code);
}

void sighandler()
{
	perform_shutdown=1;
}

void *main_thread()
{
	time_t last_refresh;

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGHUP, sighandler);

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	pthread_cleanup_push(cleanup, NULL);
	usleep(SLEEPTIME);
	while (1) {
		if (perform_shutdown) {
			pthread_exit(0);
		}
		pthread_testcancel();
		pthread_mutex_lock(&arptab_mutex);
		parseproc();
		processarp(0);
		pthread_mutex_unlock(&arptab_mutex);
		usleep(SLEEPTIME);
		if (!option_arpperm && time(NULL)-last_refresh > REFRESHTIME) {
			pthread_mutex_lock(&arptab_mutex);
			refresharp(*arptab);
			pthread_mutex_unlock(&arptab_mutex);
			time(&last_refresh);
		}
	}
	/* required since pthread_cleanup_* are implemented as macros */
	pthread_cleanup_pop(0);
}

int main (int argc, char **argv)
{
	pid_t child_pid;
	int i;
	bool help = false, foreground = false;

	progname = (char *) basename(argv[0]);

	static struct option long_options[] = {
		{ "debug", 0, 0, 'd' },
		{ "foreground", 0, 0, 'f' },
		{ "help", 0, 0, 0 },
		{ "permanent", 0, 0, 'p' },
		{ NULL, 0, 0, 0 },
	};
	for (int ch; (ch = getopt_long(argc, argv, "dfhp", long_options, NULL)) != -1 && !help;) {
		switch (ch) {
			case 'd':
				debug=1;
				//no break
			case 'f':
				foreground = true;
				break;
			case 'p':
				option_arpperm=1;
				break;
			default:
				help = true;
				break;
		}
	}
	while (optind < argc)
		ifaces[++last_iface_idx] = argv[optind++];

	if (help || last_iface_idx <= -1) {
		printf("parprouted: proxy ARP routing daemon, version %s.\n", VERSION);
		printf("(C) 2007 Vladimir Ivaschenko <vi@maks.net>, GPL2 license.\n");
		printf("Usage: parprouted [--debug -d] [--foreground -f] [--permanent -p] interfaces ...\n");
		exit(0);
	}

	if (!foreground) {
		/* fork to go into the background */
		if ((child_pid = fork()) < 0) {
			fprintf(stderr, "could not fork(): %s", strerror(errno));
			exit(1);
		} else if (child_pid > 0) {
			/* fork was ok, wait for child to exit */
			if (waitpid(child_pid, NULL, 0) != child_pid) {
				perror(progname);
				exit(1);
			}
			/* and exit myself */
			exit(0);
		}
		/* and fork again to make sure we inherit all rights from init */
		if ((child_pid = fork()) < 0) {
			perror(progname);
			exit(1);
		} else if (child_pid > 0)
			exit(0);

		/* create our own session */
		setsid();

		/* close stdin/stdout/stderr */
		close(0);
		close(1);
		close(2);
	}

	openlog(progname, LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "Starting.");

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGHUP, sighandler);

	if ((arptab = (ARPTAB_ENTRY **) malloc(sizeof(ARPTAB_ENTRY **))) == NULL) {
		syslog(LOG_INFO, "No memory: %s", strerror(errno));
		abort();
	}

	*arptab = NULL;

	pthread_mutex_init(&arptab_mutex, NULL);
	pthread_mutex_init(&req_queue_mutex, NULL);

	if (pthread_create(&my_threads[++last_thread_idx], NULL, main_thread, NULL)) {
		syslog(LOG_ERR, "Error creating main thread.");
		abort();
	}

	for (i=0; i <= last_iface_idx; i++) {
		if (pthread_create(&my_threads[++last_thread_idx], NULL, (void *) arp, (void *) ifaces[i])) {
			syslog(LOG_ERR, "Error creating ARP thread for %s.", ifaces[i]);
			abort();
		}
		if (debug) printf("Created ARP thread for %s.\n", ifaces[i]);
	}

	if (pthread_join(my_threads[0], NULL)) {
		syslog(LOG_ERR, "Error joining thread.");
		abort();
	}

	while (waitpid(-1, NULL, WNOHANG)) { }
	exit(1);
}
