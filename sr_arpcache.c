#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"

void sendARPRequest(struct sr_instance* sr, struct sr_arpreq* req){
	void* packetHeader=malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
	sr_ethernet_hdr_t* ehdr=(sr_ethernet_hdr_t*)packetHeader;
    struct sr_if* current = sr->if_list;
    struct sr_rt* rt_walker = sr->routing_table;
    while(rt_walker!=NULL){
    	printf("ARPCACHE CHECKING RT\n");
    	rt_walker->dest;
    	if((req->ip)==rt_walker->dest.s_addr){
    		printf("FOUND MATCH\n");
    		while(current!=NULL){
    			printf("%s vs. %s\n",current->name,rt_walker->interface);
    			if(strcmp(current->name,rt_walker->interface)==0){
    				printf("FOUND MATCHING INTERFACE\n");
    				break;
    			}
    			current=current->next;
    		}
    		break;
    	}
    	rt_walker=rt_walker->next;
    }
    memcpy(ehdr->ether_shost,current->addr,ETHER_ADDR_LEN);
    ehdr->ether_dhost[0]=0xFF;
    ehdr->ether_dhost[1]=0xFF;
    ehdr->ether_dhost[2]=0xFF;
    ehdr->ether_dhost[3]=0xFF;
    ehdr->ether_dhost[4]=0xFF;
    ehdr->ether_dhost[5]=0xFF;
    ehdr->ether_type=htons(ethertype_arp);
    printf("COMPOSED ETHERNET HEADER\n");
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packetHeader+sizeof(sr_ethernet_hdr_t));
    arp_hdr->ar_hrd=htons(1);
    arp_hdr->ar_pro=htons(0x800);
    arp_hdr->ar_hln=(ETHER_ADDR_LEN);
    arp_hdr->ar_pln=(4);
    arp_hdr->ar_op=htons(arp_op_request);
    memcpy(arp_hdr->ar_sha,current->addr,ETHER_ADDR_LEN);
    arp_hdr->ar_sip=current->ip;
    arp_hdr->ar_tha[0]=0x00;
    arp_hdr->ar_tha[1]=0x00;
    arp_hdr->ar_tha[2]=0x00;
    arp_hdr->ar_tha[3]=0x00;
    arp_hdr->ar_tha[4]=0x00;
    arp_hdr->ar_tha[5]=0x00;
    arp_hdr->ar_tip=req->ip;
    printf("COMPOSED ARP HEADER\n");
    print_hdrs(packetHeader,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
    printf("SENDING\n");
    sr_send_packet(sr , packetHeader , sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), current);

}
/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    /* Fill this in */
	struct sr_arpreq* req=sr->cache.requests;
	while(req!=NULL){
		if(time(NULL)-req->sent>=1){
			printf("NEED TO RESENT OR DELETE\n");
			if(req->times_sent>=5){
				printf("DELETING\n");
				sr_ip_hdr_t* header = (sr_ip_hdr_t*)(req->packets + sizeof(sr_ethernet_hdr_t));
				int oldSum = header->ip_sum;
				struct sr_if* current = sr->if_list;
				struct sr_rt* rt_walker = sr->routing_table;
				while(rt_walker!=NULL){
					printf("CHECKING RT\n");
					printf("%s\n",inet_ntoa(rt_walker->dest));
					if((header->ip_dst)==rt_walker->dest.s_addr){
						printf("FOUND MATCH\n");
						while(current!=NULL){
							printf("%s vs. %s\n",current->name,rt_walker->interface);
							if(strcmp(current->name,rt_walker->interface)==0){
								printf("FOUND MATCHING INTERFACE\n");
								break;
							}
							current=current->next;
						}
						break;
					}
					rt_walker=rt_walker->next;
				}
				void* errPacket=malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
				sr_ethernet_hdr_t* ethhdr= (sr_ethernet_hdr_t*)req->packets;
				sr_ethernet_hdr_t* errEthHdr=(sr_ethernet_hdr_t*)errPacket;
				 memcpy(errEthHdr->ether_dhost,ethhdr->ether_shost,ETHER_ADDR_LEN);
				 memcpy(errEthHdr->ether_shost,ethhdr->ether_dhost,ETHER_ADDR_LEN);
				 errEthHdr->ether_type=htons(ethertype_ip);
				 sr_ip_hdr_t* errIPhdr=(sr_ip_hdr_t*)(errPacket+sizeof(sr_ethernet_hdr_t));
				 memcpy(errIPhdr,header,sizeof(sr_ip_hdr_t));
				 errIPhdr->ip_p=ip_protocol_icmp;
				 errIPhdr->ip_len=htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
				 errIPhdr->ip_dst=header->ip_src;
				 errIPhdr->ip_src=header->ip_dst;
				 sr_icmp_t3_hdr_t* icmpHdr=(sr_icmp_t3_hdr_t*)(errPacket+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
				 icmpHdr->icmp_code=1;
				 icmpHdr->icmp_type=3;
				 icmpHdr->icmp_sum=0;
				 memcpy(icmpHdr->data,header,ICMP_DATA_SIZE);
				 icmpHdr->icmp_sum=cksum(icmpHdr,sizeof(sr_icmp_t3_hdr_t));
				 printf("MADE HEADER\n");
				 errIPhdr->ip_sum=0;
				 errIPhdr->ip_sum=cksum(errIPhdr,sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
				 print_hdrs(errPacket,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));

				 sr_send_packet(sr , errPacket , sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t), rt_walker->interface);
				sr_arpreq_destroy(&(sr->cache),req);

				printf("DELETED\n");
			}else{
				printf("RESENDING\n");
				sendARPRequest(sr,req);
				req->times_sent++;
			}
		}
		req=req->next;
	}


}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            }
            else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                }
                else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
