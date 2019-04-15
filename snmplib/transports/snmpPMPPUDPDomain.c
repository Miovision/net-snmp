/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/* 
 * Written by Dave Hillis.
 * See the following web pages for useful documentation on this transport:
 * http://www.ntcip.org/library/documents/pdf/pmpp01.pdf
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-features.h>

netsnmp_feature_require(sockaddr_size)

#include <net-snmp/library/snmpPMPPUDPDomain.h>
#include <net-snmp/library/snmpUDPIPv6Domain.h>

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/callback.h>

#include <net-snmp/library/snmpSocketBaseDomain.h>
#include <net-snmp/library/snmpUDPDomain.h>

#ifndef INADDR_NONE
#define INADDR_NONE	-1
#endif

#define WE_ARE_SERVER 0
#define WE_ARE_CLIENT 1

#define NETSNMP_DONTWAIT MSG_DONTWAIT

oid             netsnmpPMPPUDPDomain[] = { TRANSPORT_DOMAIN_PMPP_UDP_IP };
size_t          netsnmpPMPPUDPDomain_len = OID_LENGTH(netsnmpPMPPUDPDomain);

static netsnmp_tdomain pmppudpDomain;

const int PPMP_BUFFER_SIZE = 1500;

static uint16_t fcstab[256] = {
0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

uint16_t _compute_fcs(unsigned char *data, int length) {
    uint16_t fcs;
    fcs = 0xffff;
    while (length--)
    { fcs = (fcs >> 8) ^ fcstab[(fcs ^ ((uint16_t)*data)) & 0xff];
        data++;
    }
    return (fcs);
}

// Constants for PMPP
const unsigned char FRAME_DELIMITER = 0x7e;
const unsigned char ESCAPE_DELIMITER = 0x7d;
const unsigned char ESCAPE_BITMASK = 0x20;
const unsigned char BROADCAST_ADDRESS = 0xff;
const unsigned char CONTROL_BYTE = 0x13; /* IPI */
const unsigned char COMMAND_BYTE = 0xc1; /* Says instruction is stmp/snmp */

const int SIZE_OF_SIGNING_FOOTER = 2;

int _pmppize(char* inbuf, int insize, char* outbuf) {
    int inIdx;
    int outIdx = 0;

    outbuf[outIdx++] = FRAME_DELIMITER; 
    outbuf[outIdx++] = BROADCAST_ADDRESS;
    outbuf[outIdx++] = CONTROL_BYTE;
    outbuf[outIdx++] = COMMAND_BYTE;

    for(inIdx = 0; inIdx < insize; ++inIdx) {
        outbuf[outIdx++] = inbuf[inIdx];
    }

    uint16_t fcs = _compute_fcs((unsigned char*) outbuf+1, outIdx-1) ^ 0xFFFF;

    outIdx = 0;
    outbuf[outIdx++] = FRAME_DELIMITER;
    outbuf[outIdx++] = BROADCAST_ADDRESS;
    outbuf[outIdx++] = CONTROL_BYTE;
    outbuf[outIdx++] = COMMAND_BYTE;

    inbuf[insize] = fcs & 0xFF;
    inbuf[insize+1] = (fcs >> 8) & 0xFF;

    for(inIdx = 0; inIdx < insize + SIZE_OF_SIGNING_FOOTER; ++inIdx) {
        if(inbuf[inIdx] == ESCAPE_DELIMITER || inbuf[inIdx] == FRAME_DELIMITER) {
            outbuf[outIdx++] = ESCAPE_DELIMITER;
            outbuf[outIdx++] = inbuf[inIdx] ^ ESCAPE_BITMASK;
        }
        else {
            outbuf[outIdx++] = inbuf[inIdx];
        }
    }

    outbuf[outIdx++] = FRAME_DELIMITER;
    return outIdx;
}

int _depmppize(char* inbuf, int insize, char* outbuf) {
    // Check the actual address to see if it's one-byte or two-bytes
    int sizeOfHeader = (inbuf[1] & 0x01) ? 4 : 5;
    const int SIZE_OF_FOOTER = 1;
    int outIdx = 0;
    int inIdx;
    
    for(inIdx = sizeOfHeader; inIdx < insize - SIZE_OF_FOOTER; ++inIdx) {
        if(inbuf[inIdx] == ESCAPE_DELIMITER) {
            inbuf[++inIdx] ^= ESCAPE_BITMASK;
        }
        outbuf[outIdx++] = inbuf[inIdx];
    }
    return outIdx - SIZE_OF_SIGNING_FOOTER;
}

static netsnmp_indexed_addr_pair *
_extract_addr_pair(netsnmp_transport *t, void *opaque, int olen)
{
    netsnmp_indexed_addr_pair *addr_pair = NULL;

    if (opaque && olen == sizeof(netsnmp_tmStateReference)) {
        netsnmp_tmStateReference *tmStateRef =
            (netsnmp_tmStateReference *) opaque;

        if (tmStateRef->have_addresses)
            addr_pair = &(tmStateRef->addresses);
    }
    if ((NULL == addr_pair) && (NULL != t)) {
        if (t->data != NULL &&
            t->data_length == sizeof(netsnmp_indexed_addr_pair))
            addr_pair = (netsnmp_indexed_addr_pair *) (t->data);
    }

    return addr_pair;
}

static struct sockaddr *
_find_remote_sockaddr(netsnmp_transport *t, void *opaque, int olen, int *socklen)
{
    netsnmp_indexed_addr_pair *addr_pair = _extract_addr_pair(t, opaque, olen);
    struct sockaddr *sa = NULL;

    if (NULL == addr_pair)
        return NULL;

    sa = &addr_pair->remote_addr.sa;
    *socklen = netsnmp_sockaddr_size(sa);
    return sa;
}

static int
netsnmp_pmppudp_recv(netsnmp_transport *t, void *buf, int size,
                     void **opaque, int *olength)
{
    int             rc = -1;
    socklen_t       fromlen = sizeof(struct sockaddr);
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct sockaddr *from;
    int i;

    /*
     * allocate space for saving remote address
     */
    addr_pair = (netsnmp_indexed_addr_pair *)
                calloc(1, sizeof(netsnmp_indexed_addr_pair));
    if (addr_pair == NULL) {
        *opaque = NULL;
        *olength = 0;
        return -1;
    }
    from = &addr_pair->remote_addr.sa;

    char pmppBuffer[PPMP_BUFFER_SIZE];

    while (rc < 0) {
        rc = recvfrom(t->sock, pmppBuffer, PPMP_BUFFER_SIZE, NETSNMP_DONTWAIT, from, &fromlen);
        if (rc < 0 && errno != EINTR)
            break;
    }

    int snmpSize = _depmppize(pmppBuffer, rc, buf);

    *opaque = (void *)addr_pair;
    *olength = sizeof(netsnmp_indexed_addr_pair);

    return snmpSize;
}


static int
netsnmp_pmppudp_send(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;
    netsnmp_indexed_addr_pair *addr_pair = NULL;

    char biggerBuffer[PPMP_BUFFER_SIZE];
    memcpy(biggerBuffer, buf, size);
    char pmppBuffer[PPMP_BUFFER_SIZE];
    int pmppSize = _pmppize(biggerBuffer, size, pmppBuffer);

    /*
     * find address to send to, from opaque pointer or t->data
     */
    if (opaque != NULL && *opaque != NULL &&
        *olength == sizeof(netsnmp_indexed_addr_pair)) {
        addr_pair = (netsnmp_indexed_addr_pair *) (*opaque);
    } else if (t != NULL && t->data != NULL &&
               t->data_length == sizeof(netsnmp_indexed_addr_pair))
        addr_pair = (netsnmp_indexed_addr_pair *) (t->data);

    if (addr_pair != NULL && t != NULL && t->sock >= 0) {
        struct sockaddr *to = &addr_pair->remote_addr.sa;
        while (rc < 0) {
            rc = sendto(t->sock, pmppBuffer, pmppSize, 0, to, sizeof(struct sockaddr));
            if (rc < 0 && errno != EINTR)
                break;
        }
    }
    return rc; 
}



static int
netsnmp_pmppudp_close(netsnmp_transport *t)
{
    return netsnmp_socketbase_close(t);
}

char *
netsnmp_pmppudp_fmtaddr(netsnmp_transport *t, void *data, int len)
{
    int              sa_len;
    struct sockaddr *sa = _find_remote_sockaddr(t, data, len, &sa_len);
    if (sa) {
        data = sa;
        len = sa_len;
    }

    return netsnmp_ipv4_fmtaddr("PMPPUDP", t, data, len);
}




/*
 * Open a PMPP-based transport for SNMP.  Local is TRUE if addr is the local
 * address to bind to (i.e. this is a server-type session); otherwise addr is 
 * the remote address to send things to.  
 */

static netsnmp_transport *
_transport_common(netsnmp_transport *t, int local)
{
    char *tmp = NULL;
    int tmp_len;

    DEBUGTRACETOK("9:pmppudp");

    if (NULL == t)
        return NULL;

    /** save base transport for clients; need in send/recv functions later */
    if (t->data) { /* don't copy data */
        tmp = t->data;
        tmp_len = t->data_length;
        t->data = NULL;
    }
    t->base_transport = netsnmp_transport_copy(t);

    if (tmp) {
        t->data = tmp;
        t->data_length = tmp_len;
    }
    if (NULL != t->data &&
        t->data_length == sizeof(netsnmp_indexed_addr_pair)) {
    }

    /*
     * Set Domain
     */
    t->domain = netsnmpPMPPUDPDomain;                                     
    t->domain_length = netsnmpPMPPUDPDomain_len;     

    t->f_recv          = netsnmp_pmppudp_recv;
    t->f_send          = netsnmp_pmppudp_send;
    t->f_close         = netsnmp_pmppudp_close;
    t->f_config        = NULL;
    t->f_setup_session = NULL;
    t->f_accept        = NULL;
    t->f_fmtaddr       = netsnmp_pmppudp_fmtaddr;

    t->flags = NETSNMP_TRANSPORT_FLAG_TUNNELED;

    return t;
}

netsnmp_transport *
netsnmp_pmppudp_transport(struct sockaddr_in *addr, int local)
{
    netsnmp_transport *t = NULL;
    struct sockaddr_in myinfo;
    int optval;

    DEBUGTRACETOK("pmppudp");

    t = netsnmp_udp_transport(addr, local);
    if (NULL == t)
        return NULL;

    _transport_common(t, local);

    memset(&myinfo, 0, sizeof(struct sockaddr_in));
    myinfo.sin_family = AF_INET;
    myinfo.sin_port = addr->sin_port;
    myinfo.sin_addr.s_addr = INADDR_ANY;

    optval = 1;
    setsockopt(t->sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof optval);

    if (bind(t->sock, (struct sockaddr*) &myinfo, sizeof(struct sockaddr)) == -1) {
        printf("sender: bind\n");
    }


    return t;
}


netsnmp_transport *
netsnmp_pmppudp_create_tstring(const char *str, int isserver,
                               const char *default_target)
{
    struct sockaddr_in addr;
    netsnmp_transport *t;

    if (netsnmp_sockaddr_in2(&addr, str, default_target))
        t = netsnmp_pmppudp_transport(&addr, isserver);
    else
        return NULL;

    return t;
}


netsnmp_transport *
netsnmp_pmppudp_create_ostring(const u_char * o, size_t o_len, int local)
{
    struct sockaddr_in addr;

    if (o_len == 6) {
        unsigned short porttmp = (o[4] << 8) + o[5];
        addr.sin_family = AF_INET;
        memcpy((u_char *) & (addr.sin_addr.s_addr), o, 4);
        addr.sin_port = htons(porttmp);
        return netsnmp_pmppudp_transport(&addr, local);
    }
#ifdef NETSNMP_TRANSPORT_UDPIPV6_DOMAIN
    else if (o_len == 18) {
        struct sockaddr_in6 addr6;
        unsigned short porttmp = (o[16] << 8) + o[17];
        addr6.sin6_family = AF_INET6;
        memcpy((u_char *) & (addr6.sin6_addr.s6_addr), o, 4);
        addr6.sin6_port = htons(porttmp);
        return netsnmp_pmppudp6_transport(&addr6, local);
    }
#endif
    return NULL;
}

void
netsnmp_pmppudp_ctor(void)
{
    char indexname[] = "_netsnmp_addr_info";
    static const char *prefixes[] = { "pmpp" };
    int i, num_prefixes = sizeof(prefixes) / sizeof(char *);

    DEBUGMSGTL(("pmppudp", "registering PMPP constructor\n"));

    /* config settings */
    pmppudpDomain.name = netsnmpPMPPUDPDomain;
    pmppudpDomain.name_length = netsnmpPMPPUDPDomain_len;
    pmppudpDomain.prefix = (const char**)calloc(num_prefixes + 1,
                                                sizeof(char *));
    for (i = 0; i < num_prefixes; ++ i)
        pmppudpDomain.prefix[i] = prefixes[i];

    pmppudpDomain.f_create_from_tstring     = NULL;
    pmppudpDomain.f_create_from_tstring_new = netsnmp_pmppudp_create_tstring;
    pmppudpDomain.f_create_from_ostring     = netsnmp_pmppudp_create_ostring;

    /*
    if (!openssl_addr_index)
        openssl_addr_index =
            SSL_get_ex_new_index(0, indexname, NULL, NULL, NULL);
    */

    netsnmp_tdomain_register(&pmppudpDomain);
}
