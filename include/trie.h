#ifndef _TRIE_H_
#define _TRIE_H_

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "lib.h"

struct trie_node{
    struct trie_node* left;
    struct trie_node* right;
	struct route_table_entry* entry;
};

struct trie_node* init_trie(struct route_table_entry *route_table, uint32_t size);

struct trie_node* add_node(struct trie_node* head, struct route_table_entry* rte);

struct route_table_entry* LPM(struct trie_node* head, uint32_t ip_addr);

void test(char* string);

#endif