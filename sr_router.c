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
  if(ethertype(packet) == ethertype_ip){
	  handleIP(sr, packet, len, interface);
  } else if(ethertype(packet) == ethertype_arp){
	  handleARP(sr, packet, len, interface);
  } else{
	  fprintf("Not a valid ethernet type");
  }
}/* end sr_ForwardPacket */

void handleIP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
	fprintf("Handling IP \n");
	if(sizeOf(sr_ethernet_hdr_t) + sizeOf(sr_ip_hdr_t) > len){
		fprintf("Too small to be IP \m");
		return;
	}

	sr_ip_hdr_t* header = (sr_ip_hdr_t*)(packet + size(sr_ethernet_hdr_t));
	struct sr_if* current = sr->if_list;
	while(current != NULL){
		if(current->ip == header->ip_dst){
			break;
		}
		current = current->next;
	}
	if(header->ip_dst == current->ip){
		// If packet is for current
		if(header->ip_p != ip_protocol_icmp){
			// not the correct protocol
			return;
		} else{
			sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			if(icmpHeader->icmp_code == 0 && icmpHeader->icmp_type == 8){
				//send icmpCode
			}
		}
	} else{
		// If packet isn't for current
	}
}

void handlARP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
	fprintf("Handling ARP \n");
	if(sizeOf(sr_ethernet_hdr_t) + sizeOf(sr_arp_hdr_t) > len){
		fprintf("Too small to be ARP \n");
		return;
	}
}
