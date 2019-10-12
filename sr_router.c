/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void handleIP(struct sr_instance* sr,uint8_t *  , unsigned int , char* );
void hanldeARP(struct sr_instance* , uint8_t *, unsigned int , char* );
void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  print_hdrs(packet, len);
  printf("GOT HEADER\n");
  if(ethertype(packet) == ethertype_ip){

	  printf("HANDLING IP\n");
	  handleIP(sr, packet, len, interface);
  } else if(ethertype(packet) == ethertype_arp){
	  printf("HANDLING ARP\n");
	  handleARP(sr, packet, len, interface);
  } else{
	  printf("Not a valid ethernet type\n");
  }
}/* end sr_ForwardPacket */

void handleIP(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface){
	printf("Handling IP \n");
	if(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) > len){
		printf("Too small to be IP \n");
		return;
	}
	printf("HEADER Length OK\n");
	/*TODO: add Subtracting TTl, and other modifications/sanity checks*/
    sr_ip_hdr_t* header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	int oldSum = header->ip_sum;
	header->ip_sum = 0;
	if (oldSum != cksum(header, sizeof(sr_ip_hdr_t))) {
		printf("Detected error: checksum invalid");
		header->ip_sum = oldSum;
		return;
	}
	header->ip_sum = oldSum;

	header->ip_ttl = header->ip_ttl - 1;
									if(header->ip_ttl == 0){
										printf("TTL Expired \n");
										return;
									}
									header->ip_sum = 0;
									header->ip_sum = cksum(header, sizeof(sr_ip_hdr_t));


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


	printf("HELLO 0\n");
	if(rt_walker!=NULL){
		if(current!=NULL&&(header->ip_dst)==rt_walker->dest.s_addr){
		printf("HELLO 1\n");
		/*	if(header->ip_p != ip_protocol_icmp){*/
				printf("HELLO 2\n");
				struct sr_arpentry* destination=sr_arpcache_lookup(&(sr->cache), header->ip_dst);
					if(destination==NULL){
						printf("DESTINATION NOT IN CACHE\n");
						sr_arpcache_queuereq(&(sr->cache), header->ip_dst, packet,len, interface);
					}
					else{
						printf("DESTINGATION IN CACHE FORWARDING\n");



						sr_ethernet_hdr_t* ethhdr= (sr_ethernet_hdr_t*)packet;
						 memcpy(ethhdr->ether_dhost,destination->mac,ETHER_ADDR_LEN);
						 memcpy(ethhdr->ether_shost,current->addr,ETHER_ADDR_LEN);

						 print_hdrs(ethhdr,len);
						 sr_send_packet(sr , ethhdr , len, current);
						 printf("SENT\n");




					}
			/*} else{
				printf("HELLO ICMP\n");
				sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				if(icmpHeader->icmp_code == 0 && icmpHeader->icmp_type == 8){

				}
			}*/
		}
		else{
			/*TODO POTENTIAL ERROR MESSAGE??*/
			printf("HELLO 3\n");

		}

	}else{
		if(header->ip_p == ip_protocol_icmp){
			sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			print_hdr_icmp(icmpHeader);
			if(icmpHeader->icmp_type!=(0x08)||icmpHeader->icmp_code!=0){
				/*NOT PING*/
				printf("NOT PING\n");
				return;
			}
			 struct sr_if* if_walker = sr->if_list;
			 while(if_walker!=NULL){
				 printf("TRAVERSING ICMP\n");
				 print_addr_ip_int(ntohl(if_walker->ip));
				 print_addr_ip_int(htonl(header->ip_dst));
				 if(ntohl(if_walker->ip)==htonl(header->ip_dst)){

					 printf("FOUND MATCHING INTERFACE FOR ICMP\n");
					 icmpHeader->icmp_type=0;
					 header->ip_dst=header->ip_src;
					 header->ip_src=if_walker->ip;
					 sr_ethernet_hdr_t* ethhdr= (sr_ethernet_hdr_t*)packet;
					 uint8_t  temp[ETHER_ADDR_LEN];
					 memcpy(temp,ethhdr->ether_dhost,ETHER_ADDR_LEN);
					 memcpy(ethhdr->ether_dhost,ethhdr->ether_shost,ETHER_ADDR_LEN);
					 memcpy(ethhdr->ether_shost,temp,ETHER_ADDR_LEN);
					 printf("REPLYING\n");
					 print_hdrs(packet,len);
					 sr_send_packet(sr , ethhdr , len, interface);
					 return;


				 }
				 if_walker=if_walker->next;
			 }
		}else{
			/*ERROR WITH PACKET*/
			printf("ERROR WITH PACKET\n");
		}


	}

}

void handleARP(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface){
	printf("Handling ARP \n");
	if(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) > len){
		printf("Too small to be ARP \n");
		return;
	}
	sr_arp_hdr_t* header=(sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	/*_______________________________________ARP REQUEST HANDLING___________________________________*/
	if(header->ar_op==htons(arp_op_request)){
		struct sr_if* if_walker = 0;
				if_walker=sr->if_list;
				sr_print_if(if_walker);
		while(if_walker!=NULL){
			if( header->ar_tip==if_walker->ip){
					printf("CLIENT\n");
					void* packetHeader=malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
					 sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packetHeader+sizeof(sr_ethernet_hdr_t));
					 sr_ethernet_hdr_t* etherHeader=(sr_ethernet_hdr_t*)packetHeader;
					 memcpy(etherHeader->ether_dhost,header->ar_sha,ETHER_ADDR_LEN);
					 memcpy(etherHeader->ether_shost,if_walker->addr,ETHER_ADDR_LEN);
					 etherHeader->ether_type=htons(ethertype_arp);
					 memcpy((void*)arp_hdr,(void*)header,sizeof(sr_arp_hdr_t));
					 arp_hdr->ar_op=htons(arp_op_reply);
					 memcpy(arp_hdr->ar_sha,if_walker->addr,ETHER_ADDR_LEN);
					 arp_hdr->ar_sip=if_walker->ip;
					 memcpy(arp_hdr->ar_tha,header->ar_sha,ETHER_ADDR_LEN);
					 arp_hdr->ar_tip=header->ar_sip;
					 printf("COMPOSED HEADER\n");
					  print_hdrs(packetHeader, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
					 printf("SENDING ARP REPLY\n");
					 sr_send_packet(sr , packetHeader , sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), interface);
					 printf("SENT\n");
					 return;
				}else{
					printf("NOT CLIENT\n");
				}
			if_walker=if_walker->next;
		}
	}
	/*___________________________________TODO: ARP REPLY HANDLING___________________________________*/
	else if(header->ar_op==htons(arp_op_reply)){
		printf("ARP REPLY RECEIVED\n");
		struct sr_if* if_walker = 0;
		if_walker=sr->if_list;
		while(if_walker!=NULL){
			if( header->ar_tip==if_walker->ip){
				printf("FOUND MATCHING INTERFACE\n");
				struct sr_arpreq* req=sr_arpcache_insert(&(sr->cache),header->ar_sha,(header->ar_sip));

				if(req!=NULL){
					printf("INSERTED IN CACHE\n");
					struct sr_arpentry* arpentry=sr_arpcache_lookup(&(sr->cache), (header->ar_sip));
					if(arpentry==NULL){printf("ERROR RETRIEVING FROM CACHE\n");}
					/*TODO send queued packages + destroy request*/
					struct sr_packet* packet_walker= req->packets;
					while(packet_walker!=NULL){
					printf("SENDING QUEUED PACKET\n");
					sr_ethernet_hdr_t* ethhdr= (sr_ethernet_hdr_t*)packet_walker->buf;
					memcpy(ethhdr->ether_shost,if_walker->addr,ETHER_ADDR_LEN);
					memcpy(ethhdr->ether_dhost,arpentry->mac,ETHER_ADDR_LEN);
					print_hdrs(ethhdr,packet_walker->len);
					 sr_send_packet(sr , ethhdr , packet_walker->len, if_walker);
					 printf("SENT\n");
					 struct sr_packet* temp=packet_walker;
					 packet_walker=packet_walker->next;

					}
					sr_arpreq_destroy(&(sr->cache),req);
					printf("DONE forwarding\n");
				}
				else{printf("FAILED TO LOCATE REQUEST\n");
				print_addr_ip_int((header->ar_sip));
				}

				return;
			}
			if_walker=if_walker->next;
		}
	}


}
