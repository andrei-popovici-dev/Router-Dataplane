#include <arpa/inet.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "trie.h"

#define MAX_ARP_ENTRIES 100
#define MAX_ROUTE_ENTRIES 100000

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	int rc;

	// Do not modify this line
	init(argv + 2, argc - 2);

	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_ENTRIES);
	struct route_table_entry *route_table = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);

	rc = parse_arp_table("./arp_table.txt", arp_table); // remove later -> after dynamic arp table
	DIE(rc < 0, "parse_arp_table");

	rc = read_rtable(argv[1], route_table);
	DIE(rc < 0, "read_rtable");

	struct trie_node* trie_head = init_trie(route_table, rc);

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr *eth_hdr;
		eth_hdr = (struct ether_hdr *)(buf);

		if(ntohs(eth_hdr->ethr_type) == IP_ETHERTYPE) { //identificam tipul de pachet
			struct ip_hdr *ip_hdr;
			ip_hdr = (struct ip_hdr*)(buf + sizeof(struct ether_hdr));

			struct in_addr addr;
			inet_aton(get_interface_ip(interface), &addr);
			if(ip_hdr->dest_addr == addr.s_addr) { //daca destinatia suntem chiar noi
				//TODO: cream un pachet ICMP de tip "Echo Response"
				continue;
			}

			//verificam checksum
			u_int16_t ip_header_checksum = ntohs(ip_hdr->checksum);
			ip_hdr->checksum = 0;
			if(ip_header_checksum != checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr))) {
				printf("Dropped : Bad IP Header Checksum");
				continue;
			}

			//verificare + actualizare TTL
			if(ip_hdr->ttl <= 1) {
				//TODO: (ICMP Time Limit Exceded)

				continue;
			}
			ip_hdr->ttl-=1;

			// aplicam un LPM eficientizat(cu trie de preferat/ arbore binar)
			struct route_table_entry *entry = LPM(trie_head, ip_hdr->dest_addr);

			if(entry == NULL) {
				printf("Dropped : Destination Unreachable");
				// daca nu gasim nimic pachetul este aruncat iar Router-ul trimite catre sursa un pachet ICMP de tip "Destination Unreachable"
				continue;
			}

			//actualizare checksum
			ip_hdr->checksum = 0;
			ip_hdr->checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));

			//TODO: trimiterea pachetului la Next Hop -> Pentru determinarea next-hop -> protocolul arp
				//TODO: rescriere adrese MAC
				// cautam in cache-ul tabelei ARP; daca avem intrare -> succes -> trimitem pachetul
				// altfel generam un broadcast ARP, bagam pachetul de transmis intr-o coada si continuam dirijarea pachetelor
				// (retransmisia pachetelor din coada va fi facuta in corpul ramurii unui pachet ARP)
			
		} else if(ntohs(eth_hdr->ethr_type) == ARP_ETHERTYPE) {
			struct arp_hdr *arp_hdr;
			arp_hdr = (struct arp_hdr*)(buf + sizeof(struct ether_hdr));
			if (ntohs(arp_hdr->opcode) == ARP_REPLY) //daca avem pachet de tip reply
			{ 
				// daca reply-ul ne da o adresa mac pentru ip-ul cerut
					//-> populam adresa arp cu raspunsul
					//   incercam retransmisia pachetelor din coada(acelasi proces ca pe ramura pachet ip)
			} else if(ntohs(arp_hdr->opcode) == ARP_REQUEST) { //daca avem pachet de tip request
					// trimitem un pachet ARP de tip reply cu adresa MAC
			}
		}

		printf("Dropped : Unknown Type");
	}
}