#include <arpa/inet.h>
#include <string.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "trie.h"

#define MAX_ARP_ENTRIES 100
#define MAX_ROUTE_ENTRIES 100000

void complete_ip_hdr_fields(struct ip_hdr *ip_hdr, uint32_t saddr, uint32_t daddr, int len)
{
	ip_hdr->dest_addr = daddr;
	ip_hdr->source_addr = saddr;
	ip_hdr->ttl = 64;
	ip_hdr->tos = 0;
	ip_hdr->frag = 0;
	ip_hdr->ver = 4;
	ip_hdr->ihl = 5;
	ip_hdr->id = htons(4);
	ip_hdr->proto = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(len + sizeof(struct ip_hdr));
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
}

void send_arp_broadcast(int router_interface, uint32_t searched_ip)
{
	uint8_t interface_mac[6];
	uint32_t interface_ip;
	int arp_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	char *interface_ip_str = get_interface_ip(router_interface);

	get_interface_mac(router_interface, interface_mac);
	inet_pton(AF_INET, interface_ip_str, &interface_ip);

	printf("Sending ARP Broadcast for IP : %s\n", interface_ip_str);

	uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	char *buffer = make_arp_msg(interface_mac, interface_ip, broadcast_mac, searched_ip, ARP_REQUEST);
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buffer + sizeof(struct ether_hdr));
	memset(arp_hdr->thwa, 0, 6);

	send_to_link(arp_len, buffer, router_interface);
	free(buffer);
}

void send_arp_reply(int router_interface, struct arp_hdr *arp_hdr)
{
	uint8_t interface_mac[6];
	get_interface_mac(router_interface, interface_mac);

	uint32_t interface_ip;
	char *interface_ip_str = get_interface_ip(router_interface);
	inet_pton(AF_INET, interface_ip_str, &interface_ip);
	printf("Sending ARP Reply at MAC : %02x:%02x:%02x:%02x:%02x:%02x ; IP : %s\n",
		   interface_mac[0], interface_mac[1], interface_mac[2], interface_mac[3], interface_mac[4], interface_mac[5], interface_ip_str);

	char *buffer = make_arp_msg(interface_mac, interface_ip, arp_hdr->shwa, arp_hdr->sprotoa, ARP_REPLY);
	int arp_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	send_to_link(arp_len, buffer, router_interface);
	free(buffer);
}

void send_error_icmp_packet(int router_interface, struct ether_hdr *pck_ether_hdr,
							struct ip_hdr *pck_ip_hdr, uint8_t icmp_type, uint8_t *pck_data, int pck_size)
{
	int len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + pck_size;
	char *buffer = calloc(1, len);
	struct ether_hdr *reply_ether_hdr = (struct ether_hdr *)buffer;
	struct ip_hdr *reply_ip_hdr = (struct ip_hdr *)(buffer + sizeof(struct ether_hdr));
	struct icmp_hdr *reply_icmp_hdr = (struct icmp_hdr *)(buffer + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	struct ip_hdr *reply_pck_ip_hdr = (struct ip_hdr *)(buffer + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));

	reply_icmp_hdr->mtype = icmp_type;
	reply_icmp_hdr->mcode = 0;
	memcpy(reply_pck_ip_hdr, pck_ip_hdr, sizeof(struct ip_hdr));
	memcpy((char *)reply_pck_ip_hdr + sizeof(struct ip_hdr), pck_data, pck_size);
	reply_icmp_hdr->check = htons(checksum((uint16_t *)reply_icmp_hdr, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + pck_size));

	uint32_t interface_ip;
	inet_pton(AF_INET, get_interface_ip(router_interface), &interface_ip);

	complete_ip_hdr_fields(reply_ip_hdr, interface_ip, pck_ip_hdr->source_addr, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + pck_size);

	memcpy(reply_ether_hdr->ethr_dhost, pck_ether_hdr->ethr_shost, 6);
	get_interface_mac(router_interface, reply_ether_hdr->ethr_shost);
	reply_ether_hdr->ethr_type = htons(IP_ETHERTYPE);
	send_to_link(len, buffer, router_interface);
}

void send_echo_icmp_packet(int router_interface, char *pck, int len)
{
	struct ether_hdr *reply_ether_hdr = (struct ether_hdr *)pck;
	struct ip_hdr *reply_ip_hdr = (struct ip_hdr *)(pck + sizeof(struct ether_hdr));
	struct icmp_hdr *reply_icmp_hdr = (struct icmp_hdr *)(pck + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	reply_icmp_hdr->mtype = ICMP_ECHO_REPLY;
	reply_icmp_hdr->mcode = 0;

	reply_icmp_hdr->check = 0;
	uint16_t icmp_len = ntohs(reply_ip_hdr->tot_len) - sizeof(struct ip_hdr);
	reply_icmp_hdr->check = htons(checksum((uint16_t *)reply_icmp_hdr, icmp_len));

	complete_ip_hdr_fields(reply_ip_hdr, reply_ip_hdr->dest_addr, reply_ip_hdr->source_addr, reply_ip_hdr->tot_len);

	uint8_t aux_mac[6];

	memcpy(aux_mac, reply_ether_hdr->ethr_dhost, 6);
	memcpy(reply_ether_hdr->ethr_dhost, reply_ether_hdr->ethr_shost, 6);
	memcpy(reply_ether_hdr->ethr_shost, aux_mac, 6);

	send_to_link(len, pck, router_interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	int rc;

	// Do not modify this line
	init(argv + 2, argc - 2);

	int arp_table_size = 0; // to be modified to 0 after dynamic arp table
	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_ENTRIES);
	struct route_table_entry *route_table = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);

	queue waiting_pck_queue = create_queue();

	rc = read_rtable(argv[1], route_table);
	DIE(rc < 0, "read_rtable");

	struct trie_node *trie_head = init_trie(route_table, rc);

	while (1)
	{

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		uint32_t recv_interface_ip;
		inet_pton(AF_INET, get_interface_ip(interface), &recv_interface_ip);

		struct ether_hdr *eth_hdr;
		eth_hdr = (struct ether_hdr *)(buf);

		if (ntohs(eth_hdr->ethr_type) == IP_ETHERTYPE)
		{
			struct ip_hdr *ip_hdr;
			ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			struct in_addr addr;
			inet_aton(get_interface_ip(interface), &addr);
			if (ip_hdr->dest_addr == addr.s_addr)
			{ // daca destinatia suntem chiar noi
				// TODO: cream un pachet ICMP de tip "Echo Response"
				send_echo_icmp_packet(interface, buf, len);
				continue;
			}

			// verificam checksum
			u_int16_t ip_header_checksum = ntohs(ip_hdr->checksum);
			ip_hdr->checksum = 0;
			if (checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)) != ip_header_checksum)
			{
				printf("Dropped : Bad IP Header Checksum\n");
				continue;
			}

			// verificare + actualizare TTL
			if (ip_hdr->ttl <= 1)
			{
				printf("Dropped : Time to Live exceded\n");
				uint8_t pck_data[9];
				memcpy(pck_data, (buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)), 8);
				send_error_icmp_packet(interface, eth_hdr, ip_hdr, ICMP_TLE, pck_data, 8);
				continue;
			}
			ip_hdr->ttl -= 1;

			// cautam in tabela de rutare eficientizata destinatia pentru next_hop
			struct route_table_entry *entry = LPM(trie_head, ip_hdr->dest_addr);

			if (entry == NULL)
			{
				printf("Dropped : Destination Unreachable\n");
				uint8_t pck_data[9];
				memcpy(pck_data, (buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)), 8);
				send_error_icmp_packet(interface, eth_hdr, ip_hdr, ICMP_DEST_UNREACHABLE, pck_data, 8);
				continue;
			}

			// actualizare checksum
			ip_hdr->checksum = 0;
			ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

			// TODO: trimiterea pachetului la Next Hop -> Pentru determinarea next-hop -> protocolul ARP
			struct arp_table_entry *next_hop = get_mac_entry(entry->next_hop, arp_table, arp_table_size);
			if (next_hop == NULL)
			{ // generam un broadcast ARP, bagam pachetul de transmis intr-o coada si continuam dirijarea pachetelor
				send_arp_broadcast(entry->interface, entry->next_hop);

				struct packet *pck = malloc(sizeof(struct packet));

				memcpy(pck->buf, buf, len);
				pck->len = len;

				// punem pachetul intr-o coada de pachete
				queue_enq(waiting_pck_queue, pck);

				continue;
			} // altfel daca avem intrare -> succes -> trimitem pachetul

			get_interface_mac(entry->interface, eth_hdr->ethr_shost);
			memcpy(eth_hdr->ethr_dhost, next_hop->mac, 6);
			send_to_link(len, buf, entry->interface);
			continue;
		}
		else if (ntohs(eth_hdr->ethr_type) == ARP_ETHERTYPE &&
				 ((struct arp_hdr *)(buf + sizeof(struct ether_hdr)))->tprotoa == recv_interface_ip)
		{ // daca avem pachet ARP si ne este adresat noua

			struct arp_hdr *arp_hdr;
			arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			if (ntohs(arp_hdr->opcode) == ARP_REPLY)
			{ // daca avem pachet de tip reply
				if (get_mac_entry(arp_hdr->sprotoa, arp_table, arp_table_size) == NULL)
				{
					arp_table[arp_table_size].ip = arp_hdr->sprotoa;
					memcpy(arp_table[arp_table_size].mac, arp_hdr->shwa, 6);
					arp_table_size++;
				} // daca nu exista entry-ul in tabela il adaugam

				queue temp_waiting_pck_queue = create_queue();

				while (!queue_empty(waiting_pck_queue))
				{
					struct packet *pck = queue_deq(waiting_pck_queue);
					struct ether_hdr *eth_hdr_pck;
					eth_hdr_pck = (struct ether_hdr *)(pck->buf);

					struct ip_hdr *ip_hdr_pck;
					ip_hdr_pck = (struct ip_hdr *)(pck->buf + sizeof(struct ether_hdr));

					// cautam in tabela de rutare eficientizata
					struct route_table_entry *entry = LPM(trie_head, ip_hdr_pck->dest_addr);

					struct arp_table_entry *next_hop = get_mac_entry(entry->next_hop, arp_table, arp_table_size);
					if (next_hop == NULL)
					{ // generam un broadcast ARP, bagam pachetul de transmis intr-o coada si continuam dirijarea pachetelor

						queue_enq(temp_waiting_pck_queue, pck);

						continue;
					} // altfel daca avem intrare -> succes -> trimitem pachetul

					get_interface_mac(entry->interface, eth_hdr_pck->ethr_shost);
					memcpy(eth_hdr_pck->ethr_dhost, next_hop->mac, 6);
					send_to_link(pck->len, pck->buf, entry->interface);
					free(pck);
				}

				while (!queue_empty(temp_waiting_pck_queue))
				{
					struct packet *pck = queue_deq(temp_waiting_pck_queue);
					queue_enq(waiting_pck_queue, pck);
				}

				free(temp_waiting_pck_queue);

				continue;
			}
			else if (ntohs(arp_hdr->opcode) == ARP_REQUEST)
			{
				// daca avem pachet de tip request si ne este cerut noua sa furnizam adresa MAC
				if (get_mac_entry(arp_hdr->sprotoa, arp_table, arp_table_size) == NULL)
				{
					arp_table[arp_table_size].ip = arp_hdr->sprotoa;
					memcpy(arp_table[arp_table_size].mac, arp_hdr->shwa, 6);
					arp_table_size++;
				} // retinem adresa mac in tabela arp;

				send_arp_reply(interface, arp_hdr);
				// trimitem un pachet ARP de tip reply cu adresa MAC a noastra
				continue;
			}
		}

		printf("Dropped : Unknown Type\n");
	}
}