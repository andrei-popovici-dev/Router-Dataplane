#include "trie.h"

struct trie_node *init_trie(struct route_table_entry *route_table, uint32_t size)
{ // could change to read directly from file
	struct trie_node *head = calloc(1, sizeof(struct trie_node));

	for (uint32_t i = 0; i < size; i++)
	{
		add_node(head, &route_table[i]);
	}

	return head;
}

struct trie_node *add_node(struct trie_node *head, struct route_table_entry *rte)
{
	uint32_t ip = ntohl(rte->prefix);
	uint32_t mask = ntohl(rte->mask);

	int mask_len = 0;
	uint32_t temp_mask = mask;

	while (temp_mask != 0)
	{
		if (temp_mask & 1)
		{
			mask_len++;
		}
		temp_mask >>= 1;
	}

	if (head == NULL)
	{
		head = calloc(1, sizeof(struct trie_node));
	}

	struct trie_node *p = head;

	for (int i = 0; i < mask_len; i++)
	{
		if ((ip >> (31 - i)) & 1)
		{
			if (p->right == NULL)
				p->right = calloc(1, sizeof(struct trie_node));
			p = p->right;
		}
		else
		{
			if (p->left == NULL)
				p->left = calloc(1, sizeof(struct trie_node));
			p = p->left;
		}
	}
	p->entry = rte;

	return head;
}

static struct route_table_entry *LPM_helper(struct trie_node *head, uint32_t ip_addr, struct route_table_entry *best_entry, uint8_t current_bit)
{
	if (head == NULL)
		return best_entry;

	if (head->entry != NULL)
		best_entry = head->entry;

	if (current_bit == 32)
	{
		return best_entry;
	}

	if ((ip_addr >> (31 - current_bit)) & 1)
		return LPM_helper(head->right, ip_addr, best_entry, current_bit + 1);
	else
		return LPM_helper(head->left, ip_addr, best_entry, current_bit + 1);
}

struct route_table_entry *LPM(struct trie_node *head, uint32_t ip_addr)
{
	return LPM_helper(head, ntohl(ip_addr), NULL, 0);
}

void test(char *string)
{
	struct route_table_entry *route_table = malloc(sizeof(struct route_table_entry) * 100000);

	int rc = read_rtable(string, route_table);
	DIE(rc < 0, "read_rtable");

	struct trie_node *trie_head = init_trie(route_table, rc);

	char *ip_str = "192.140.231.5";
	struct in_addr addr;
	inet_aton(ip_str, &addr);

	struct route_table_entry *node_wanted = LPM(trie_head, addr.s_addr);
	printf("%d\n", node_wanted->interface);
}