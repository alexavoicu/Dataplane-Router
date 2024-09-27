#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>


uint8_t broadcast_mac_addr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry arp_table[10];
int arp_table_len;

queue package_queue;


struct route_table_entry* get_best_route(uint32_t ip_dest) {

	int left = 0;
	int right = rtable_len - 1;
    struct route_table_entry* dest = NULL;

    while (left <= right) {
        int mid = (left + right) / 2;

        if ((ntohl(ip_dest) & ntohl(rtable[mid].mask)) == ntohl(rtable[mid].prefix)) {
            // if we found a match, we look to the right, for a longer match
            dest = rtable + mid;
            left = mid + 1;
        } else if (ntohl(rtable[mid].prefix) > (ntohl(ip_dest) & ntohl(rtable[mid].mask))) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return dest;
}


struct arp_table_entry* get_arp_entry(uint32_t given_ip) {	// iterate through the arp table to find the matching arp entry

    for (int i = 0; i < arp_table_len; i++) {

        if (arp_table[i].ip == given_ip) {
            return arp_table + i;
        }
    }
    return NULL;
}

int cmpfunc(const void* a, const void* b) {	// function used to sort the route entries to make the search more efficient
    struct route_table_entry* first = (struct route_table_entry*)a;
    struct route_table_entry* second = (struct route_table_entry*)b;

	if (ntohl(second->mask) == ntohl(first->mask)) {
		return (ntohl(first->prefix) - ntohl(second->prefix));
	}
	return ntohl(second->mask) - ntohl(first->mask);
}

queue send_queued_packages(void) {
	queue updated_queue = queue_create();

	// iterate throught the queue of packages, extract the length
	// verify if the arp entry is found in the table and send the package
	// otherwise increase the new queue and update it

	while (queue_empty(package_queue) != 0) {
		void *buf;
		void *initial_package;
		buf = queue_deq(package_queue);
		initial_package = buf;
		size_t len = *((size_t*)buf);
		buf = buf + sizeof(size_t);

		struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
		if (get_arp_entry((get_best_route(ip_hdr->daddr))->next_hop) != NULL) {
			get_interface_mac(get_best_route(ip_hdr->daddr)->interface, ((struct ether_header *) buf)->ether_shost);
        	memcpy(((struct ether_header *) buf)->ether_dhost, get_arp_entry((get_best_route(ip_hdr->daddr))->next_hop)->mac, 6);

        	send_to_link(get_best_route(ip_hdr->daddr)->interface, buf, len);
		} else {
			queue_enq(updated_queue, (void*) initial_package);
		}
	}
	return updated_queue;
}

void send_icmp_echo(char *buf, int len, int interface) {
    struct ether_header *eth_hdr = (struct ether_header *)buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)((uint8_t *)ip_hdr + ip_hdr->ihl * 4);

	// update the icmp header with the echo response values and update the checksum
    icmp_hdr->type = 0;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum((uint16_t *) &icmp_hdr, sizeof(struct icmphdr));

	// update the ipv4 header, source, destination and checksum
    ip_hdr->protocol = 1;
    uint32_t tmp_s_addr = ip_hdr->saddr;
    ip_hdr->saddr = ip_hdr->daddr;
    ip_hdr->daddr = tmp_s_addr;
    ip_hdr->check = 0;
    ip_hdr->check = checksum((uint16_t *) &ip_hdr, sizeof(struct iphdr));

	// update the ethernet header, source, destination
    uint8_t tmp_s_host[6];
    memcpy(tmp_s_host, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
    memcpy(eth_hdr->ether_dhost, tmp_s_host, 6);

    send_to_link(interface, buf, len);
}


void send_icmp(char *buf, int len, int interface, uint8_t type, uint8_t code) {
    
    struct ether_header *eth_hdr = (struct ether_header *)buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));


    // create the new icmp package to be sent, with the updated size and extract the pointers to the headers
    char icmp_package[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8];
    struct ether_header *new_eth_hdr = (struct ether_header *)icmp_package;
    struct iphdr *new_ip_hdr = (struct iphdr *)(icmp_package + sizeof(struct ether_header));
    struct icmphdr *new_icmp_hdr = (struct icmphdr *)(icmp_package + sizeof(struct ether_header) + sizeof(struct iphdr));
    
	// copy the info into the new header and update the destination and source mac adress
    memcpy(new_eth_hdr, eth_hdr, sizeof(struct ether_header));
    memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
    get_interface_mac(interface, new_eth_hdr->ether_dhost);


	// copy the info into the new ipv4 header and update the protocol for icmp, adresses and checksum
    memcpy(new_ip_hdr, ip_hdr, sizeof(struct iphdr));
    new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
    new_ip_hdr->ttl = 64;
    new_ip_hdr->protocol = 1;
    uint32_t tmp_addr = new_ip_hdr->saddr;
    new_ip_hdr->saddr = new_ip_hdr->daddr;
    new_ip_hdr->daddr = tmp_addr;
    new_ip_hdr->check = 0;
    new_ip_hdr->check = htons(checksum((void *) new_ip_hdr, sizeof(struct iphdr)));

	// initialise the icmp header
    new_icmp_hdr->type = type;
    new_icmp_hdr->code = code;
    new_icmp_hdr->checksum = 0;
	new_icmp_hdr->checksum = htons(checksum((uint16_t *) new_icmp_hdr, sizeof(struct icmphdr)));

    // copy the dropped ipv4 header and 64 bits into the icmp package to be sent
	memcpy((void *)new_icmp_hdr + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr) + 8);

    send_to_link(interface, icmp_package, sizeof(struct ether_header) + ntohs(new_ip_hdr->tot_len));
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);


	// allocate the route table, read and sort it
	rtable = malloc(100000 * sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), cmpfunc);

	
	arp_table_len = 0;

	package_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		uint8_t router_mac[6];
		get_interface_mac(interface, router_mac);

		// verify if the package is meant for the router, otherwise drop it
		if ((memcmp(eth_hdr->ether_dhost, router_mac, 6) != 0) && (memcmp(eth_hdr->ether_dhost, broadcast_mac_addr, 6) != 0)) {
			continue;
		}

		// if the package is not an ipv4 one, check if it is an arp one
		if (eth_hdr->ether_type != ntohs(0x0800)) {
			if (eth_hdr->ether_type == ntohs(0x0806)) {
				struct arp_header *arp_package = (struct arp_header *)(((void *)eth_hdr) + sizeof(struct ether_header));

				if (ntohs(arp_package->op) == 2) {

					// if it is a reply, create a new entry in the arp table, if it the entry doesn't already exist
					// and call the function that sends the packages waiting in the queue 
					if (get_arp_entry(arp_package->spa) != NULL) {
						continue;
					}
					
					memcpy(arp_table[arp_table_len].mac, arp_package->sha, 6);
					arp_table[arp_table_len].ip = arp_package->spa;
					arp_table_len++;

					package_queue = send_queued_packages();
					continue;
				}

				if (ntohs(arp_package->op) ==  1) {

					// if it is a request, transform it into a reply
					// update the ip adress and add the mac adress for the router

					arp_package->op = htons(2);
					memcpy(arp_package->tha, arp_package->sha, 6);
					memcpy(arp_package->sha, router_mac, 6);

					u_int32_t send_back_ip = arp_package->spa;
					arp_package->spa = arp_package->tpa;
					arp_package->tpa = send_back_ip;

					
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, router_mac, 6);
					send_to_link(interface, buf, len);
				}
			}
			
			continue;
		}


		// extract the ipv4 header	
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		// if it is an icmp package and if it meant fot the router
		if (ip_hdr->protocol == 1 && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)((uint8_t *)ip_hdr + sizeof(struct iphdr));

			// if it is an echo request, call the echo reply function
			if (icmp_hdr->type == 8) {
				send_icmp_echo(buf, len, interface);
				continue;
			}
		}

		// verify if the checksum is valid and the package is not corrupted
		u_int16_t package_checksum = ip_hdr->check;
		ip_hdr->check = 0;
		if (htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) != package_checksum) {
			continue;
		}

		// if the time has been exceeded, send an icmp message
		if (ip_hdr->ttl <= 1) {
			send_icmp(buf, len, interface, 11, 0);
			continue;
		}

		// decrease the ttl
        ip_hdr->ttl--;

		// get the route to the which the package should be sent to 
		// if we don't find it, send an icmp destination unreachable message 
		struct route_table_entry *next = get_best_route(ip_hdr->daddr);

		if (next == NULL) {
			send_icmp(buf, len, interface, 3, 0);
			continue;
        }

		// update the checksum
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		struct arp_table_entry *arp_entry = get_arp_entry(next->next_hop);
		if (arp_entry == NULL) {

			// add the length concatenated to the package in the waiting queue
			char queue_package_entry[len + 8];
			memcpy(queue_package_entry, &len, 8);
			memcpy(queue_package_entry + 8, buf, len);
			queue_enq(package_queue, (void*) queue_package_entry);

			// if the arp entry doesn't exist in the table, an arp request is created
			struct ether_header ether_hdr_for_arp;
			ether_hdr_for_arp.ether_type = htons(0x806);
    		memset(ether_hdr_for_arp.ether_dhost, 0xFF, 6);


			get_interface_mac(next->interface, ether_hdr_for_arp.ether_shost);

			struct arp_header arp_header;
			memset(&arp_header, 0, sizeof(struct arp_header));

			// initialise the arp header
			arp_header.htype = htons(1);
			arp_header.ptype = htons(0x0800);
			arp_header.hlen = 6;
			arp_header.plen = 4;
			arp_header.op = htons(1);
			arp_header.spa = inet_addr(get_interface_ip(next->interface));

			arp_header.tpa = next->next_hop; 
			get_interface_mac(next->interface, arp_header.sha);

			// create the arp request package and copy the ethernet header and the arp header into its structure
			char arp_request_package [sizeof(struct ether_header) + sizeof(struct arp_header)];
			memcpy(arp_request_package, &ether_hdr_for_arp, sizeof(struct ether_header));
			memcpy(arp_request_package + sizeof(struct ether_header), &arp_header, sizeof(struct arp_header));

			send_to_link(next->interface, arp_request_package, sizeof(arp_request_package));
			continue;
		}

		get_interface_mac(next->interface, eth_hdr->ether_shost);
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);

            // Trimitere pachet
        send_to_link(next->interface, buf, len);

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

