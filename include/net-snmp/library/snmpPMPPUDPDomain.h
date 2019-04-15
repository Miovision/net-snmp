#ifndef _SNMPPMPPUDPDOMAIN_H
#define _SNMPPMPPUDPDOMAIN_H

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

config_require(UDP)

#include <net-snmp/types.h>
#include <net-snmp/library/snmp_transport.h>

#ifdef __cplusplus
extern          "C" {
#endif

#define TRANSPORT_DOMAIN_PMPP_UDP_IP	1,3,6,1,6,1,9
NETSNMP_IMPORT oid netsnmpPMPPUDPDomain[7];
NETSNMP_IMPORT size_t netsnmpPMPPUDPDomain_len;

netsnmp_transport *netsnmp_pmppudp_transport(struct sockaddr_in *addr,
                                             int local);


/*
 * Register any configuration tokens specific to the agent.  
 */

void            netsnmp_pmppudp_agent_config_tokens_register(void);

/*
 * "Constructor" for transport domain object.  
 */

void            netsnmp_pmppudp_ctor(void);

#ifdef __cplusplus
}
#endif
#endif/*_SNMPPMPPUDPDOMAIN_H*/
