/*
    netcode

    Copyright © 2017 - 2026, Más Bandwidth LLC

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived 
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "netcode.h"
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>

#ifdef _MSC_VER
#define SODIUM_STATIC
#pragma warning(disable:4996)
#endif // #ifdef _MSC_VER

#include <sodium.h>

#define NETCODE_SOCKET_IPV6         1
#define NETCODE_SOCKET_IPV4         2

#define NETCODE_VERSION_INFO_BYTES 13
#define NETCODE_MAX_PACKET_BYTES 1300
#define NETCODE_MAX_PAYLOAD_BYTES 1200
#define NETCODE_PACKET_QUEUE_SIZE 256
#define NETCODE_REPLAY_PROTECTION_BUFFER_SIZE 256
#define NETCODE_CLIENT_MAX_RECEIVE_PACKETS 64
#define NETCODE_SERVER_MAX_RECEIVE_PACKETS ( 64 * NETCODE_MAX_CLIENTS )
#define NETCODE_CLIENT_SOCKET_SNDBUF_SIZE ( 4 * 1024 * 1024 )
#define NETCODE_CLIENT_SOCKET_RCVBUF_SIZE ( 4 * 1024 * 1024 )
#define NETCODE_SERVER_SOCKET_SNDBUF_SIZE ( 4 * 1024 * 1024 )
#define NETCODE_SERVER_SOCKET_RCVBUF_SIZE ( 4 * 1024 * 1024 )

#define NETCODE_VERSION_INFO ( (uint8_t*) "HYPERSOMNIA3" )
#define NETCODE_PACKET_SEND_RATE 10.0
#define NETCODE_NUM_DISCONNECT_PACKETS 10

#ifndef NETCODE_ENABLE_TESTS
#define NETCODE_ENABLE_TESTS 0
#endif // #ifndef NETCODE_ENABLE_TESTS

#ifndef NETCODE_ENABLE_LOGGING
#define NETCODE_ENABLE_LOGGING 1
#endif // #ifndef NETCODE_ENABLE_LOGGING

// ------------------------------------------------------------------

#if NETCODE_PACKET_TAGGING

static int netcode_packet_tagging_enabled = 0;

void netcode_enable_packet_tagging()
{
    netcode_packet_tagging_enabled = 1;
}

#else

void netcode_enable_packet_tagging() {}

#endif // #if NETCODE_PACKET_TAGGING

// ------------------------------------------------------------------

static void netcode_default_assert_handler( NETCODE_CONST char * condition, NETCODE_CONST char * function, NETCODE_CONST char * file, int line )
{
    printf( "assert failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    #if defined( __GNUC__ )
    __builtin_trap();
    #elif defined( _MSC_VER )
    __debugbreak();
    #endif
    exit( 1 );
}

static int log_level;
static int (*printf_function)( NETCODE_CONST char *, ... ) = ( int (*)( NETCODE_CONST char *, ... ) ) printf;
void (*netcode_assert_function)( NETCODE_CONST char *, NETCODE_CONST char *, NETCODE_CONST char * file, int line ) = netcode_default_assert_handler;

void netcode_log_level( int level )
{
    log_level = level;
}

void netcode_set_printf_function( int (*function)( NETCODE_CONST char *, ... ) )
{
    netcode_assert( function );
    printf_function = function;
}

void netcode_set_assert_function( void (*function)( NETCODE_CONST char *, NETCODE_CONST char *, NETCODE_CONST char * file, int line ) )
{
    netcode_assert_function = function;
}

#if NETCODE_ENABLE_LOGGING

void netcode_printf( int level, NETCODE_CONST char * format, ... ) 
{
    if ( level > log_level )
        return;
    va_list args;
    va_start( args, format );
    char buffer[4*1024];
    vsnprintf( buffer, sizeof(buffer), format, args );
    printf_function( "%s", buffer );
    va_end( args );
}

#else // #if NETCODE_ENABLE_LOGGING

void netcode_printf( int level, NETCODE_CONST char * format, ... ) 
{
    (void) level;
    (void) format;
}

#endif // #if NETCODE_ENABLE_LOGGING

void * netcode_default_allocate_function( void * context, size_t bytes )
{
    (void) context;
    return malloc( bytes );
}

void netcode_default_free_function( void * context, void * pointer )
{
    (void) context;
    free( pointer );
}

// ------------------------------------------------------------------

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    #ifndef NOMINMAX
    #define NOMINMAX
    #endif // #ifndef NOMINMAX
    #define _WINSOCK_DEPRECATED_NO_WARNINGS
    #include <winsock2.h>
    #include <ws2def.h>
    #include <ws2tcpip.h>
    #include <ws2ipdef.h>
    #include <iphlpapi.h>
    #ifdef _MSC_VER
    #pragma comment( lib, "WS2_32.lib" )
    #pragma comment( lib, "IPHLPAPI.lib" )
    #endif // #ifdef _MSC_VER

    #ifdef SetPort
    #undef SetPort
    #endif // #ifdef SetPort

    #include <iphlpapi.h>
    #ifdef _MSC_VER
    #pragma comment( lib, "IPHLPAPI.lib" )
    #endif // #ifdef _MSC_VER
    
#elif NETCODE_PLATFORM == NETCODE_PLATFORM_MAC || NETCODE_PLATFORM == NETCODE_PLATFORM_UNIX

    #include <netdb.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>

#else

    #error netcode - unknown platform!

#endif

static int netcode_parse_port( NETCODE_CONST char * string, uint16_t * port )
{
    // the port must be all digits and fit in [0,65535]. anything else is an error,
    // rather than whatever atoi truncation used to produce.

    if ( string[0] == '\0' )
        return NETCODE_ERROR;

    int value = 0;
    int i;
    for ( i = 0; string[i] != '\0'; i++ )
    {
        if ( string[i] < '0' || string[i] > '9' )
            return NETCODE_ERROR;
        value = value * 10 + ( string[i] - '0' );
        if ( value > 65535 )
            return NETCODE_ERROR;
    }

    *port = (uint16_t) value;

    return NETCODE_OK;
}

int netcode_parse_address( NETCODE_CONST char * address_string_in, struct netcode_address_t * address )
{
    netcode_assert( address_string_in );
    netcode_assert( address );

    memset( address, 0, sizeof( struct netcode_address_t ) );

    // first try to parse the string as an IPv6 address:
    // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
    // 2. otherwise try to parse as a raw IPv6 address using inet_pton

    char buffer[NETCODE_MAX_ADDRESS_STRING_LENGTH];

    char * address_string = buffer;
    strncpy( address_string, address_string_in, NETCODE_MAX_ADDRESS_STRING_LENGTH - 1 );
    address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH-1] = '\0';

    int address_string_length = (int) strlen( address_string );

    if ( address_string[0] == '[' )
    {
        int base_index = address_string_length - 1;

        int i;
        for ( i = 0; i < 6; i++ )         // note: no need to search past 6 characters as ":65535" is longest possible port value
        {
            int index = base_index - i;
            if ( index < 3 )
                break;
            if ( address_string[index] == ':' && address_string[index-1] == ']' )
            {
                if ( netcode_parse_port( &address_string[index+1], &address->port ) != NETCODE_OK )
                    return NETCODE_ERROR;
                address_string[index-1] = '\0';
                break;
            }
        }

        // if a port is omitted, it is assumed to be zero. strip the trailing ']' so "[addr]" parses as just the address

        if ( address_string[base_index] == ']' )
            address_string[base_index] = '\0';

        address_string += 1;
    }

    struct in6_addr sockaddr6;
    if ( inet_pton( AF_INET6, address_string, &sockaddr6 ) == 1 )
    {
        address->type = NETCODE_ADDRESS_IPV6;
        uint16_t ipv6_network_order[8];
        memcpy( ipv6_network_order, &sockaddr6, sizeof( ipv6_network_order ) );
        int i;
        for ( i = 0; i < 8; i++ )
        {
            address->data.ipv6[i] = ntohs( ipv6_network_order[i] );
        }
        return NETCODE_OK;
    }

    // otherwise it's probably an IPv4 address:
    // 1. look for ":portnum", if found save the portnum and strip it out
    // 2. parse remaining ipv4 address via inet_pton

    address_string_length = (int) strlen( address_string );
    int base_index = address_string_length - 1;
    int i;
    for ( i = 0; i < 6; i++ )
    {
        int index = base_index - i;
        if ( index < 0 )
            break;
        if ( address_string[index] == ':' )
        {
            if ( netcode_parse_port( &address_string[index+1], &address->port ) != NETCODE_OK )
                return NETCODE_ERROR;
            address_string[index] = '\0';
            break;
        }
    }

    struct sockaddr_in sockaddr4;
    if ( inet_pton( AF_INET, address_string, &sockaddr4.sin_addr ) == 1 )
    {
        address->type = NETCODE_ADDRESS_IPV4;
        uint32_t ipv4_host_order = ntohl( sockaddr4.sin_addr.s_addr );
        address->data.ipv4[0] = (uint8_t) ( ( ipv4_host_order >> 24 ) & 0xFF );
        address->data.ipv4[1] = (uint8_t) ( ( ipv4_host_order >> 16 ) & 0xFF );
        address->data.ipv4[2] = (uint8_t) ( ( ipv4_host_order >> 8  ) & 0xFF );
        address->data.ipv4[3] = (uint8_t) ( ( ipv4_host_order       ) & 0xFF );
        return NETCODE_OK;
    }

    return NETCODE_ERROR;
}

char * netcode_address_to_string( struct netcode_address_t * address, char * buffer )
{
    netcode_assert( address );
    netcode_assert( buffer );

    if ( address->type == NETCODE_ADDRESS_IPV6 )
    {
        if ( address->port == 0 )
        {
            uint16_t ipv6_network_order[8];
            int i;
            for ( i = 0; i < 8; i++ )
                ipv6_network_order[i] = htons( address->data.ipv6[i] );
            struct in6_addr sockaddr6;
            memcpy( &sockaddr6, ipv6_network_order, sizeof( ipv6_network_order ) );
            inet_ntop( AF_INET6, &sockaddr6, buffer, NETCODE_MAX_ADDRESS_STRING_LENGTH );
            return buffer;
        }
        else
        {
            char address_string[INET6_ADDRSTRLEN];
            uint16_t ipv6_network_order[8];
            int i;
            for ( i = 0; i < 8; i++ )
                ipv6_network_order[i] = htons( address->data.ipv6[i] );
            struct in6_addr sockaddr6;
            memcpy( &sockaddr6, ipv6_network_order, sizeof( ipv6_network_order ) );
            inet_ntop( AF_INET6, &sockaddr6, address_string, INET6_ADDRSTRLEN );
            snprintf( buffer, NETCODE_MAX_ADDRESS_STRING_LENGTH, "[%s]:%d", address_string, address->port );
            return buffer;
        }
    }
    else if ( address->type == NETCODE_ADDRESS_IPV4 )
    {
        if ( address->port != 0 )
        {
            snprintf( buffer, NETCODE_MAX_ADDRESS_STRING_LENGTH, "%d.%d.%d.%d:%d", 
                address->data.ipv4[0], 
                address->data.ipv4[1], 
                address->data.ipv4[2], 
                address->data.ipv4[3], 
                address->port );
        }
        else
        {
            snprintf( buffer, NETCODE_MAX_ADDRESS_STRING_LENGTH, "%d.%d.%d.%d", 
                address->data.ipv4[0], 
                address->data.ipv4[1], 
                address->data.ipv4[2], 
                address->data.ipv4[3] );
        }
        return buffer;
    }
    else
    {
        snprintf( buffer, NETCODE_MAX_ADDRESS_STRING_LENGTH, "%s", "NONE" );
        return buffer;
    }
}

int netcode_address_equal( struct netcode_address_t * a, struct netcode_address_t * b )
{
    netcode_assert( a );
    netcode_assert( b );

    if ( a->type != b->type )
        return 0;

    if ( a->port != b->port )
        return 0;

    if ( a->type == NETCODE_ADDRESS_IPV4 )
    {
        int i;
        for ( i = 0; i < 4; i++ )
        {
            if ( a->data.ipv4[i] != b->data.ipv4[i] )
                return 0;
        }
    }
    else if ( a->type == NETCODE_ADDRESS_IPV6 )
    {
        int i;
        for ( i = 0; i < 8; i++ )
        {
            if ( a->data.ipv6[i] != b->data.ipv6[i] )
                return 0;
        }
    }
    else
    {
        return 0;
    }

    return 1;
}

// ----------------------------------------------------------------

struct netcode_t
{
    int initialized;
};

static struct netcode_t netcode;

int netcode_init()
{
    // reference counted so multiple subsystems in the same application can call
    // netcode_init and netcode_term independently

    if ( netcode.initialized )
    {
        netcode.initialized++;
        return NETCODE_OK;
    }

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    WSADATA WsaData;
    if ( WSAStartup( MAKEWORD(2,2), &WsaData ) != NO_ERROR )
        return NETCODE_ERROR;
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    if ( sodium_init() == -1 )
        return NETCODE_ERROR;

    netcode.initialized = 1;

    return NETCODE_OK;
}

void netcode_term()
{
    netcode_assert( netcode.initialized );

    if ( !netcode.initialized )
        return;

    netcode.initialized--;

    if ( netcode.initialized )
        return;

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    WSACleanup();
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
}

// ----------------------------------------------------------------

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
typedef uint32_t netcode_socket_handle_t;
#else // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
typedef size_t netcode_socket_handle_t;
#endif // #if NETCODE_PLATFORM == NETCODe_PLATFORM_WINDOWS

struct netcode_socket_t
{
    struct netcode_address_t address;
    netcode_socket_handle_t handle;
};

struct netcode_socket_holder_t
{
    struct netcode_socket_t ipv4;
    struct netcode_socket_t ipv6;
};

#define NETCODE_SOCKET_ERROR_NONE                                    0
#define NETCODE_SOCKET_ERROR_CREATE_FAILED                           1
#define NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED                 2
#define NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED                3
#define NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED                   4
#define NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED                   5
#define NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED                        6
#define NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED                        7
#define NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED                8
#define NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED                9
#define NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED      10
#define NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED           11

void netcode_socket_destroy( struct netcode_socket_t * socket )
{
    netcode_assert( socket );
    netcode_assert( netcode.initialized );

    if ( socket->handle != 0 )
    {
        #if NETCODE_PLATFORM == NETCODE_PLATFORM_MAC || NETCODE_PLATFORM == NETCODE_PLATFORM_UNIX
        close( socket->handle );
        #elif NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
        closesocket( socket->handle );
        #else
        #error unsupported platform
        #endif
        socket->handle = 0;
    }
}

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS && NETCODE_PACKET_TAGGING

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <wininet.h>
#include <iphlpapi.h>

#ifdef __MINGW32__
typedef UINT32 QOS_FLOWID, *PQOS_FLOWID;
#ifndef QOS_NON_ADAPTIVE_FLOW
#define QOS_NON_ADAPTIVE_FLOW 0x00000002
#endif // #ifndef QOS_NON_ADAPTIVE_FLOW
#endif // #ifdef __MINGW32__
#include <qos2.h>

#ifdef _MSC_VER
#pragma comment( lib, "Qwave.lib" )
#endif // #ifdef _MSC_VER

static int netcode_set_socket_codepoint( SOCKET socket, QOS_TRAFFIC_TYPE trafficType, QOS_FLOWID flowId, PSOCKADDR addr )
{
    // IMPORTANT: closing the QOS handle removes all flows added on it, so we create one handle
    // on first use and share it across all sockets for the lifetime of the process.

    static HANDLE qosHandle = NULL;
    if ( qosHandle == NULL )
    {
        QOS_VERSION QosVersion = { 1 , 0 };
        if ( QOSCreateHandle( &QosVersion, &qosHandle ) == FALSE )
        {
            qosHandle = NULL;
            return GetLastError();
        }
    }
    if ( QOSAddSocketToFlow( qosHandle, socket, addr, trafficType, QOS_NON_ADAPTIVE_FLOW, &flowId ) == FALSE )
    {
        return GetLastError();
    }
    return 0;
}

#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS && NETCODE_PACKET_TAGGING

static socklen_t netcode_address_to_sockaddr( NETCODE_CONST struct netcode_address_t * address, struct sockaddr_storage * sockaddr )
{
    netcode_assert( address );
    netcode_assert( sockaddr );
    netcode_assert( address->type == NETCODE_ADDRESS_IPV4 || address->type == NETCODE_ADDRESS_IPV6 );

    memset( sockaddr, 0, sizeof( struct sockaddr_storage ) );

    if ( address->type == NETCODE_ADDRESS_IPV6 )
    {
        struct sockaddr_in6 * addr_ipv6 = (struct sockaddr_in6*) sockaddr;
        addr_ipv6->sin6_family = AF_INET6;
        int i;
        uint16_t ipv6_network_order[8];
        for ( i = 0; i < 8; i++ )
        {
            ipv6_network_order[i] = htons( address->data.ipv6[i] );
        }
        memcpy( &addr_ipv6->sin6_addr, ipv6_network_order, sizeof( ipv6_network_order ) );
        addr_ipv6->sin6_port = htons( address->port );
        return sizeof( struct sockaddr_in6 );
    }
    else
    {
        struct sockaddr_in * addr_ipv4 = (struct sockaddr_in*) sockaddr;
        addr_ipv4->sin_family = AF_INET;
        addr_ipv4->sin_addr.s_addr = htonl( ( ( (uint32_t) address->data.ipv4[0] ) << 24 ) |
                                            ( ( (uint32_t) address->data.ipv4[1] ) << 16 ) |
                                            ( ( (uint32_t) address->data.ipv4[2] ) << 8  ) |
                                            ( ( (uint32_t) address->data.ipv4[3] )       ) );
        addr_ipv4->sin_port = htons( address->port );
        return sizeof( struct sockaddr_in );
    }
}

static int netcode_sockaddr_to_address( NETCODE_CONST struct sockaddr_storage * sockaddr, struct netcode_address_t * address )
{
    netcode_assert( sockaddr );
    netcode_assert( address );

    if ( sockaddr->ss_family == AF_INET6 )
    {
        NETCODE_CONST struct sockaddr_in6 * addr_ipv6 = (NETCODE_CONST struct sockaddr_in6*) sockaddr;
        address->type = NETCODE_ADDRESS_IPV6;
        uint16_t ipv6_network_order[8];
        memcpy( ipv6_network_order, &addr_ipv6->sin6_addr, sizeof( ipv6_network_order ) );
        int i;
        for ( i = 0; i < 8; i++ )
        {
            address->data.ipv6[i] = ntohs( ipv6_network_order[i] );
        }
        address->port = ntohs( addr_ipv6->sin6_port );
        return NETCODE_OK;
    }
    else if ( sockaddr->ss_family == AF_INET )
    {
        NETCODE_CONST struct sockaddr_in * addr_ipv4 = (NETCODE_CONST struct sockaddr_in*) sockaddr;
        address->type = NETCODE_ADDRESS_IPV4;
        uint32_t ipv4_host_order = ntohl( addr_ipv4->sin_addr.s_addr );
        address->data.ipv4[0] = (uint8_t) ( ( ipv4_host_order >> 24 ) & 0xFF );
        address->data.ipv4[1] = (uint8_t) ( ( ipv4_host_order >> 16 ) & 0xFF );
        address->data.ipv4[2] = (uint8_t) ( ( ipv4_host_order >> 8  ) & 0xFF );
        address->data.ipv4[3] = (uint8_t) ( ( ipv4_host_order       ) & 0xFF );
        address->port = ntohs( addr_ipv4->sin_port );
        return NETCODE_OK;
    }

    return NETCODE_ERROR;
}

int netcode_socket_set_ttl( struct netcode_socket_t * s, int ttl )
{
	return setsockopt(s->handle, IPPROTO_IP, IP_TTL, (const char*)(&ttl), sizeof(ttl));
}

int netcode_socket_get_ttl(struct netcode_socket_t * s)
{
	int ttl;
	socklen_t len = sizeof(ttl);
	int result = getsockopt(s->handle, IPPROTO_IP, IP_TTL, (char*)(&ttl), &len);

	(void)result;

	netcode_assert(0 == result);

	return ttl;
}

int netcode_socket_create( struct netcode_socket_t * s, struct netcode_address_t * address, int send_buffer_size, int receive_buffer_size )
{
    netcode_assert( s );
    netcode_assert( address );
    netcode_assert( netcode.initialized );

    netcode_assert( address->type != NETCODE_ADDRESS_NONE );

    s->address = *address;

    // create socket

    s->handle = socket( ( address->type == NETCODE_ADDRESS_IPV6 ) ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP );

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    if ( s->handle == (uint32_t)INVALID_SOCKET )
#else // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    if ( s->handle == 0 || s->handle == (netcode_socket_handle_t) -1 )
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to create socket\n" );
        s->handle = 0;
        return NETCODE_SOCKET_ERROR_CREATE_FAILED;
    }

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    // IMPORTANT: tell windows we don't want to receive any connection reset messages for this socket
    // If we don't do this, clients disconnecting hard will cause recvfrom on the server to repeatedly error out 
    // due to ICMP disconnected packets, causing long periods where the server doesn't receive any packets from clients.

    #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    if ( WSAIoctl( s->handle, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL ) != 0 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to disable UDP CONNRESET (port unreachable) message reporting on socket\n" );
        netcode_socket_destroy( s );
        return NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED;
    }

#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    // force IPv6 only if necessary

    if ( address->type == NETCODE_ADDRESS_IPV6 )
    {
        int yes = 1;
        if ( setsockopt( s->handle, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&yes, sizeof(yes) ) != 0 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to set socket ipv6 only\n" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED;
        }
    }

    // increase socket send and receive buffer sizes. linux and windows clamp requests that
    // exceed the OS limit, but the BSDs reject them instead, so back off until accepted.

    {
        int size = send_buffer_size;
        while ( setsockopt( s->handle, SOL_SOCKET, SO_SNDBUF, (char*)&size, sizeof(int) ) != 0 )
        {
            size /= 2;
            if ( size < 256 * 1024 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to set socket send buffer size\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED;
            }
        }
        if ( size != send_buffer_size )
        {
            netcode_printf( NETCODE_LOG_LEVEL_INFO, "socket send buffer size reduced from %d to %d\n", send_buffer_size, size );
        }
    }

    {
        int size = receive_buffer_size;
        while ( setsockopt( s->handle, SOL_SOCKET, SO_RCVBUF, (char*)&size, sizeof(int) ) != 0 )
        {
            size /= 2;
            if ( size < 256 * 1024 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to set socket receive buffer size\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED;
            }
        }
        if ( size != receive_buffer_size )
        {
            netcode_printf( NETCODE_LOG_LEVEL_INFO, "socket receive buffer size reduced from %d to %d\n", receive_buffer_size, size );
        }
    }

    // bind to port

    {
        struct sockaddr_storage socket_address;
        socklen_t socket_address_length = netcode_address_to_sockaddr( address, &socket_address );

        if ( bind( s->handle, (struct sockaddr*) &socket_address, socket_address_length ) < 0 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to bind socket (%s)\n", ( address->type == NETCODE_ADDRESS_IPV6 ) ? "ipv6" : "ipv4" );
            netcode_socket_destroy( s );
            return ( address->type == NETCODE_ADDRESS_IPV6 ) ? NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED : NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED;
        }
    }

    // if bound to port 0 find the actual port we got

    if ( address->port == 0 )
    {
        struct sockaddr_storage socket_address;
        socklen_t socket_address_length = sizeof( socket_address );
        struct netcode_address_t bound_address;

        if ( getsockname( s->handle, (struct sockaddr*) &socket_address, &socket_address_length ) == -1 ||
             netcode_sockaddr_to_address( &socket_address, &bound_address ) != NETCODE_OK )
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to get socket port (%s)\n", ( address->type == NETCODE_ADDRESS_IPV6 ) ? "ipv6" : "ipv4" );
            netcode_socket_destroy( s );
            return ( address->type == NETCODE_ADDRESS_IPV6 ) ? NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED : NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED;
        }

        s->address.port = bound_address.port;
    }

    // set non-blocking io

#if NETCODE_PLATFORM == NETCODE_PLATFORM_MAC || NETCODE_PLATFORM == NETCODE_PLATFORM_UNIX

    int non_blocking = 1;
    if ( fcntl( s->handle, F_SETFL, O_NONBLOCK, non_blocking ) == -1 )
    {
        netcode_socket_destroy( s );
        return NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED;
    }

#elif NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    DWORD nonBlocking = 1;
    if ( ioctlsocket( s->handle, FIONBIO, &nonBlocking ) != 0 )
    {
        netcode_socket_destroy( s );
        return NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED;
    }

#else

    #error unsupported platform

#endif

#if NETCODE_PACKET_TAGGING

    // tag packets as low latency

#if NETCODE_PLATFORM == NETCODE_PLATFORM_MAC

    if ( netcode_packet_tagging_enabled )
    {
        if ( address->type == NETCODE_ADDRESS_IPV6 )
        {
            int tos = 46;
            if ( setsockopt( s->handle, IPPROTO_IPV6, IPV6_TCLASS, (NETCODE_CONST char *)&tos, sizeof(tos) ) != 0 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to enable packet tagging (ipv6)\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED;
            }
        }
        else
        {
            int tos = 46;
            if ( setsockopt( s->handle, IPPROTO_IP, IP_TOS, (NETCODE_CONST char *)&tos, sizeof(tos) ) != 0 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to enable packet tagging (ipv4)\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED;
            }
        }
    }

#elif NETCODE_PLATFORM == NETCODE_PLATFORM_UNIX

    if ( netcode_packet_tagging_enabled )
    {
        if ( address->type == NETCODE_ADDRESS_IPV6 )
        {
            int tos = 46;
            if ( setsockopt( s->handle, IPPROTO_IPV6, IPV6_TCLASS, (NETCODE_CONST char *)&tos, sizeof(tos) ) != 0 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to enable packet tagging (ipv6)\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED;
            }
        }
        else
        {
            int tos = 46;
            if ( setsockopt( s->handle, IPPROTO_IP, IP_TOS, (NETCODE_CONST char *)&tos, sizeof(tos) ) != 0 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to enable packet tagging (ipv4)\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED;
            }
        }
    }

#elif NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    if ( netcode_packet_tagging_enabled )
    {
        struct sockaddr_storage addr;
        memset( &addr, 0, sizeof(addr) );
        addr.ss_family = ( address->type == NETCODE_ADDRESS_IPV6 ) ? AF_INET6 : AF_INET;
        netcode_set_socket_codepoint( s->handle, QOSTrafficTypeAudioVideo, 0, (PSOCKADDR) &addr );
    }

#endif

#endif // #if NETCODE_PACKET_TAGGING

    return NETCODE_SOCKET_ERROR_NONE;
}

void netcode_socket_send_packet( struct netcode_socket_t * socket, struct netcode_address_t * to, void * packet_data, int packet_bytes )
{
    netcode_assert( socket );
    netcode_assert( socket->handle != 0 );
    netcode_assert( to );
    netcode_assert( to->type == NETCODE_ADDRESS_IPV6 || to->type == NETCODE_ADDRESS_IPV4 );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );

    struct sockaddr_storage socket_address;
    socklen_t socket_address_length = netcode_address_to_sockaddr( to, &socket_address );

    int result = sendto( socket->handle, (NETCODE_CONST char*) packet_data, packet_bytes, 0, (struct sockaddr*) &socket_address, socket_address_length );

    (void) result;
}

int netcode_socket_receive_packet( struct netcode_socket_t * socket, struct netcode_address_t * from, void * packet_data, int max_packet_size )
{
    netcode_assert( socket );
    netcode_assert( socket->handle != 0 );
    netcode_assert( from );
    netcode_assert( packet_data );
    netcode_assert( max_packet_size > 0 );

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    typedef int socklen_t;
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    
    struct sockaddr_storage sockaddr_from;
    memset( &sockaddr_from, 0, sizeof(sockaddr_from) );

    socklen_t from_length = sizeof( sockaddr_from );

    int result = recvfrom( socket->handle, (char*) packet_data, max_packet_size, 0, (struct sockaddr*) &sockaddr_from, &from_length );

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    if ( result == SOCKET_ERROR )
    {
        int error = WSAGetLastError();

        if ( error == WSAEWOULDBLOCK )
            return 0;

        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: recvfrom failed with error %d\n", error );

        return 0;
    }
#else // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    if ( result <= 0 )
    {
        if ( errno == EAGAIN )
            return 0;

        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: recvfrom failed with error %d\n", errno );

        return 0;
    }
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    if ( netcode_sockaddr_to_address( &sockaddr_from, from ) != NETCODE_OK )
    {
        netcode_assert( 0 );
        return 0;
    }
  
    netcode_assert( result >= 0 );

    int bytes_read = result;

    return bytes_read;
}

// ----------------------------------------------------------------

void netcode_write_uint8( uint8_t ** p, uint8_t value )
{
    **p = value;
    ++(*p);
}

void netcode_write_uint16( uint8_t ** p, uint16_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = value >> 8;
    *p += 2;
}

void netcode_write_uint32( uint8_t ** p, uint32_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = ( value >> 8  ) & 0xFF;
    (*p)[2] = ( value >> 16 ) & 0xFF;
    (*p)[3] = value >> 24;
    *p += 4;
}

void netcode_write_uint64( uint8_t ** p, uint64_t value )
{
    (*p)[0] = value & 0xFF;
    (*p)[1] = ( value >> 8  ) & 0xFF;
    (*p)[2] = ( value >> 16 ) & 0xFF;
    (*p)[3] = ( value >> 24 ) & 0xFF;
    (*p)[4] = ( value >> 32 ) & 0xFF;
    (*p)[5] = ( value >> 40 ) & 0xFF;
    (*p)[6] = ( value >> 48 ) & 0xFF;
    (*p)[7] = value >> 56;
    *p += 8;
}

void netcode_write_bytes( uint8_t ** p, uint8_t * byte_array, int num_bytes )
{
    int i;
    for ( i = 0; i < num_bytes; i++ )
    {
        netcode_write_uint8( p, byte_array[i] );
    }
}

uint8_t netcode_read_uint8( uint8_t ** p )
{
    uint8_t value = **p;
    ++(*p);
    return value;
}

uint16_t netcode_read_uint16( uint8_t ** p )
{
    uint16_t value;
    value = (*p)[0];
    value |= ( ( (uint16_t)( (*p)[1] ) ) << 8 );
    *p += 2;
    return value;
}

uint32_t netcode_read_uint32( uint8_t ** p )
{
    uint32_t value;
    value  = (*p)[0];
    value |= ( ( (uint32_t)( (*p)[1] ) ) << 8 );
    value |= ( ( (uint32_t)( (*p)[2] ) ) << 16 );
    value |= ( ( (uint32_t)( (*p)[3] ) ) << 24 );
    *p += 4;
    return value;
}

uint64_t netcode_read_uint64( uint8_t ** p )
{
    uint64_t value;
    value  = (*p)[0];
    value |= ( ( (uint64_t)( (*p)[1] ) ) << 8  );
    value |= ( ( (uint64_t)( (*p)[2] ) ) << 16 );
    value |= ( ( (uint64_t)( (*p)[3] ) ) << 24 );
    value |= ( ( (uint64_t)( (*p)[4] ) ) << 32 );
    value |= ( ( (uint64_t)( (*p)[5] ) ) << 40 );
    value |= ( ( (uint64_t)( (*p)[6] ) ) << 48 );
    value |= ( ( (uint64_t)( (*p)[7] ) ) << 56 );
    *p += 8;
    return value;
}

void netcode_read_bytes( uint8_t ** p, uint8_t * byte_array, int num_bytes )
{
    int i;
    for ( i = 0; i < num_bytes; i++ )
    {
        byte_array[i] = netcode_read_uint8( p );
    }
}

// ----------------------------------------------------------------

void netcode_generate_key( uint8_t * key )
{
    netcode_assert( key );
    randombytes_buf( key, NETCODE_KEY_BYTES );
}

void netcode_random_bytes( uint8_t * data, int bytes )
{
    netcode_assert( data );
    netcode_assert( bytes > 0 );
    randombytes_buf( data, bytes );
}

int netcode_encrypt_aead( uint8_t * message, uint64_t message_length, 
                          uint8_t * additional, uint64_t additional_length,
                          NETCODE_CONST uint8_t * nonce,
                          NETCODE_CONST uint8_t * key )
{
    unsigned long long encrypted_length;

    int result = crypto_aead_chacha20poly1305_ietf_encrypt( message, &encrypted_length,
                                                            message, (unsigned long long) message_length,
                                                            additional, (unsigned long long) additional_length,
                                                            NULL, nonce, key );
    
    if ( result != 0 )
        return NETCODE_ERROR;

    netcode_assert( encrypted_length == message_length + NETCODE_MAC_BYTES );

    return NETCODE_OK;
}

int netcode_decrypt_aead( uint8_t * message, uint64_t message_length, 
                          uint8_t * additional, uint64_t additional_length,
                          uint8_t * nonce,
                          uint8_t * key )
{
    unsigned long long decrypted_length;

    int result = crypto_aead_chacha20poly1305_ietf_decrypt( message, &decrypted_length,
                                                            NULL,
                                                            message, (unsigned long long) message_length,
                                                            additional, (unsigned long long) additional_length,
                                                            nonce, key );

    if ( result != 0 )
        return NETCODE_ERROR;

    netcode_assert( decrypted_length == message_length - NETCODE_MAC_BYTES );

    return NETCODE_OK;
}

// ----------------------------------------------------------------

// ----------------------------------------------------------------

/*
    Hypersomnia: the handshake without connect tokens.

    The three handshake packets are plaintext. Their first byte is below 0x10, which an encrypted
    packet's prefix byte never is (it holds at least one sequence byte in its high nibble).
*/

#define NETCODE_HANDSHAKE_REQUEST_PACKET        0x00
#define NETCODE_HANDSHAKE_CHALLENGE_PACKET      0x01
#define NETCODE_HANDSHAKE_RESPONSE_PACKET       0x02
#define NETCODE_HANDSHAKE_VERSION_PACKET        0x03

#define NETCODE_COOKIE_BYTES                    24
#define NETCODE_COOKIE_SECONDS                  10
#define NETCODE_CONNECTION_SECRET_BYTES         32

#define NETCODE_CHALLENGE_FLAG_SERVER_FULL      1

#define NETCODE_HANDSHAKE_REQUEST_BYTES         96
#define NETCODE_HANDSHAKE_CHALLENGE_BYTES       ( 1 + NETCODE_COOKIE_BYTES + NETCODE_PUBLIC_KEY_BYTES + 1 )
#define NETCODE_HANDSHAKE_VERSION_BYTES         ( 1 + NETCODE_VERSION_INFO_BYTES )
#define NETCODE_RESPONSE_PLAINTEXT_BYTES        ( NETCODE_COOKIE_BYTES + NETCODE_CONNECTION_SECRET_BYTES + NETCODE_SIGNATURE_BYTES + NETCODE_USER_DATA_BYTES )
#define NETCODE_HANDSHAKE_RESPONSE_BYTES        ( 1 + NETCODE_COOKIE_BYTES + crypto_box_SEALBYTES + NETCODE_RESPONSE_PLAINTEXT_BYTES )

#define NETCODE_USED_COOKIES                    1024

typedef char netcode_challenge_fits_in_request[ ( NETCODE_HANDSHAKE_CHALLENGE_BYTES <= NETCODE_HANDSHAKE_REQUEST_BYTES ) ? 1 : -1 ];
typedef char netcode_version_fits_in_request[ ( NETCODE_HANDSHAKE_VERSION_BYTES <= NETCODE_HANDSHAKE_REQUEST_BYTES ) ? 1 : -1 ];
typedef char netcode_response_fits_in_a_packet[ ( NETCODE_HANDSHAKE_RESPONSE_BYTES <= NETCODE_MAX_PAYLOAD_BYTES ) ? 1 : -1 ];

static int netcode_write_address_bytes( NETCODE_CONST struct netcode_address_t * address, uint8_t * out )
{
    uint8_t * p = out;
    netcode_write_uint8( &p, address->type );
    netcode_write_uint16( &p, address->port );

    if ( address->type == NETCODE_ADDRESS_IPV4 )
    {
        netcode_write_bytes( &p, (uint8_t*) address->data.ipv4, 4 );
    }
    else if ( address->type == NETCODE_ADDRESS_IPV6 )
    {
        int i;
        for ( i = 0; i < 8; i++ )
        {
            netcode_write_uint16( &p, address->data.ipv6[i] );
        }
    }

    return (int) ( p - out );
}

static void netcode_cookie_mac( uint8_t * mac,
                                NETCODE_CONST uint8_t * cookie_key,
                                NETCODE_CONST struct netcode_address_t * address,
                                uint64_t timestamp,
                                uint64_t protocol_id )
{
    uint8_t data[64];
    int bytes = netcode_write_address_bytes( address, data );
    uint8_t * p = data + bytes;
    netcode_write_uint64( &p, timestamp );
    netcode_write_uint64( &p, protocol_id );

    crypto_generichash( mac, NETCODE_MAC_BYTES, data, (unsigned long long) ( p - data ), cookie_key, NETCODE_KEY_BYTES );
}

void netcode_connection_binding( uint8_t * binding,
                                 uint64_t protocol_id,
                                 NETCODE_CONST uint8_t * server_public_key,
                                 NETCODE_CONST uint8_t * connection_secret,
                                 NETCODE_CONST uint8_t * cookie )
{
    static NETCODE_CONST char tag[] = "hs-conn-v1";

    uint8_t data[sizeof( tag ) - 1 + NETCODE_VERSION_INFO_BYTES + 8 + NETCODE_PUBLIC_KEY_BYTES + NETCODE_CONNECTION_SECRET_BYTES + NETCODE_COOKIE_BYTES];
    uint8_t * p = data;
    netcode_write_bytes( &p, (uint8_t*) tag, (int) sizeof( tag ) - 1 );
    netcode_write_bytes( &p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    netcode_write_uint64( &p, protocol_id );
    netcode_write_bytes( &p, (uint8_t*) server_public_key, NETCODE_PUBLIC_KEY_BYTES );
    netcode_write_bytes( &p, (uint8_t*) connection_secret, NETCODE_CONNECTION_SECRET_BYTES );
    netcode_write_bytes( &p, (uint8_t*) cookie, NETCODE_COOKIE_BYTES );

    netcode_assert( p - data == (int) sizeof( data ) );

    crypto_generichash( binding, NETCODE_BINDING_BYTES, data, sizeof( data ), NULL, 0 );
}

/*
    Both directions' packet keys come from the one secret the client sealed to the server, so they never match.
*/

static void netcode_derive_packet_keys( NETCODE_CONST uint8_t * connection_secret, uint8_t * client_to_server_key, uint8_t * server_to_client_key )
{
    crypto_kdf_derive_from_key( client_to_server_key, NETCODE_KEY_BYTES, 1, "hs-keys1", connection_secret );
    crypto_kdf_derive_from_key( server_to_client_key, NETCODE_KEY_BYTES, 2, "hs-keys1", connection_secret );
}

static int netcode_version_info_equal( NETCODE_CONST uint8_t * version_info )
{
    return memcmp( version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES ) == 0;
}

// ----------------------------------------------------------------

/*
    The encrypted packet types. 0 to 3 were the connect token handshake's and are never sent now.
*/

#define NETCODE_CONNECTION_KEEP_ALIVE_PACKET        4
#define NETCODE_CONNECTION_PAYLOAD_PACKET           5
#define NETCODE_CONNECTION_DISCONNECT_PACKET        6
#define NETCODE_CONNECTION_NUM_PACKETS              7

struct netcode_connection_keep_alive_packet_t
{
    uint8_t packet_type;
    int client_index;
    int max_clients;
};

struct netcode_connection_payload_packet_t
{
    uint8_t packet_type;
    uint32_t payload_bytes;
    /* serialize's BitReader loads an 8-byte window from the current byte, so a
       read in the last payload byte reaches 7 past it. This array is the last
       member; sizeof(*packet)+payload_bytes is allocated, leaving 8 bytes
       behind the returned payload pointer. Do not shrink it. */
    uint8_t payload_data[8];
};

typedef char netcode_payload_packet_tail_holds_reader_slack[
    ( sizeof( struct netcode_connection_payload_packet_t )
      - offsetof( struct netcode_connection_payload_packet_t, payload_data ) >= 8 ) ? 1 : -1 ];

struct netcode_connection_disconnect_packet_t
{
    uint8_t packet_type;
};

struct netcode_connection_payload_packet_t * netcode_create_payload_packet( int payload_bytes, void * allocator_context, void* (*allocate_function)(void*,size_t) )
{
    netcode_assert( payload_bytes >= 0 );
    netcode_assert( payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES );

    if ( allocate_function == NULL )
    {
        allocate_function = netcode_default_allocate_function;
    }

    struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) 
        allocate_function( allocator_context, sizeof( struct netcode_connection_payload_packet_t ) + payload_bytes );

    if ( !packet )
        return NULL;
    
    packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
    packet->payload_bytes = payload_bytes;

    return packet;
}

struct netcode_context_t
{
    uint8_t write_packet_key[NETCODE_KEY_BYTES];
    uint8_t read_packet_key[NETCODE_KEY_BYTES];
};

int netcode_sequence_number_bytes_required( uint64_t sequence )
{
    int i;
    uint64_t mask = 0xFF00000000000000UL;
    for ( i = 0; i < 7; i++ )
    {
        if ( sequence & mask )
            break;
        mask >>= 8;
    }
    return 8 - i;
}

#if NETCODE_ENABLE_NONCE_AUDIT

/*
    Test-only instrumentation, compiled in by the NETCODE_NONCE_AUDIT build option.

    Records the key and nonce of every packet netcode_write_packet encrypts and counts how
    many times a pair repeats. A repeated key and nonce pair under AEAD is what a connect
    token used for two sessions produces, so the whole test suite running with zero repeats
    is the property worth pinning. Not built into the library.
*/

#define NETCODE_NONCE_AUDIT_MAX_RECORDS ( 1 << 18 )
#define NETCODE_NONCE_AUDIT_HASH_SIZE ( 1 << 19 )
#define NETCODE_NONCE_AUDIT_NONCE_BYTES 12

struct netcode_nonce_audit_record_t
{
    uint8_t key[NETCODE_KEY_BYTES];
    uint8_t nonce[NETCODE_NONCE_AUDIT_NONCE_BYTES];
};

static struct netcode_nonce_audit_record_t netcode_nonce_audit_records[NETCODE_NONCE_AUDIT_MAX_RECORDS];
static int netcode_nonce_audit_hash[NETCODE_NONCE_AUDIT_HASH_SIZE];
static int netcode_nonce_audit_hash_initialized;
static int netcode_nonce_audit_num_records;
static int netcode_nonce_audit_num_repeats;
static int netcode_nonce_audit_overflowed;

static void netcode_nonce_audit_write_packet( uint8_t * key, uint8_t * nonce )
{
    if ( !netcode_nonce_audit_hash_initialized )
    {
        int i;
        for ( i = 0; i < NETCODE_NONCE_AUDIT_HASH_SIZE; i++ )
        {
            netcode_nonce_audit_hash[i] = -1;
        }
        netcode_nonce_audit_hash_initialized = 1;
    }

    uint64_t hash = 0xCBF29CE484222325ULL;
    int i;
    for ( i = 0; i < NETCODE_KEY_BYTES; i++ )
    {
        hash ^= key[i];
        hash *= 0x00000100000001B3ULL;
    }
    for ( i = 0; i < NETCODE_NONCE_AUDIT_NONCE_BYTES; i++ )
    {
        hash ^= nonce[i];
        hash *= 0x00000100000001B3ULL;
    }

    int slot = (int) ( hash & ( NETCODE_NONCE_AUDIT_HASH_SIZE - 1 ) );

    while ( netcode_nonce_audit_hash[slot] != -1 )
    {
        struct netcode_nonce_audit_record_t * record = &netcode_nonce_audit_records[netcode_nonce_audit_hash[slot]];
        if ( memcmp( record->key, key, NETCODE_KEY_BYTES ) == 0 && memcmp( record->nonce, nonce, NETCODE_NONCE_AUDIT_NONCE_BYTES ) == 0 )
        {
            netcode_nonce_audit_num_repeats++;
            printf( "NONCE AUDIT: repeated key and nonce pair: key %.2x%.2x%.2x%.2x.. sequence %d\n", 
                key[0], key[1], key[2], key[3], (int) nonce[4] );
            return;
        }
        slot = ( slot + 1 ) & ( NETCODE_NONCE_AUDIT_HASH_SIZE - 1 );
    }

    if ( netcode_nonce_audit_num_records == NETCODE_NONCE_AUDIT_MAX_RECORDS )
    {
        netcode_nonce_audit_overflowed = 1;
        return;
    }

    struct netcode_nonce_audit_record_t * record = &netcode_nonce_audit_records[netcode_nonce_audit_num_records];
    memcpy( record->key, key, NETCODE_KEY_BYTES );
    memcpy( record->nonce, nonce, NETCODE_NONCE_AUDIT_NONCE_BYTES );
    netcode_nonce_audit_hash[slot] = netcode_nonce_audit_num_records;
    netcode_nonce_audit_num_records++;
}

int netcode_nonce_audit_num_pairs()
{
    return netcode_nonce_audit_num_records;
}

int netcode_nonce_audit_repeats()
{
    return netcode_nonce_audit_num_repeats;
}

int netcode_nonce_audit_overflow()
{
    return netcode_nonce_audit_overflowed;
}

#endif // #if NETCODE_ENABLE_NONCE_AUDIT

int netcode_write_packet( void * packet, uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * write_packet_key, uint64_t protocol_id )
{
    netcode_assert( packet );
    netcode_assert( buffer );
    netcode_assert( write_packet_key );

    (void) buffer_length;

    uint8_t packet_type = ((uint8_t*)packet)[0];

    netcode_assert( packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET && packet_type < NETCODE_CONNECTION_NUM_PACKETS );

    {
        // *** encrypted packets ***

        // write the prefix byte (this is a combination of the packet type and number of sequence bytes)

        uint8_t * start = buffer;

        uint8_t sequence_bytes = (uint8_t) netcode_sequence_number_bytes_required( sequence );

        netcode_assert( sequence_bytes >= 1 );
        netcode_assert( sequence_bytes <= 8 );

        netcode_assert( packet_type <= 0xF );

        uint8_t prefix_byte = packet_type | ( sequence_bytes << 4 );

        netcode_write_uint8( &buffer, prefix_byte );

        // write the variable length sequence number [1,8] bytes.

        uint64_t sequence_temp = sequence;

        int i;
        for ( i = 0; i < sequence_bytes; i++ )
        {
            netcode_write_uint8( &buffer, (uint8_t) ( sequence_temp & 0xFF ) );
            sequence_temp >>= 8;
        }

        // write packet data according to type. this data will be encrypted.

        uint8_t * encrypted_start = buffer;

        switch ( packet_type )
        {
            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
            {
                struct netcode_connection_keep_alive_packet_t * p = (struct netcode_connection_keep_alive_packet_t*) packet;
                netcode_write_uint32( &buffer, p->client_index );
                netcode_write_uint32( &buffer, p->max_clients );
            }
            break;

            case NETCODE_CONNECTION_PAYLOAD_PACKET:
            {
                struct netcode_connection_payload_packet_t * p = (struct netcode_connection_payload_packet_t*) packet;

                netcode_assert( p->payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES );

                netcode_write_bytes( &buffer, p->payload_data, p->payload_bytes );
            }
            break;

            case NETCODE_CONNECTION_DISCONNECT_PACKET:
            {
                // ...
            }
            break;

            default:
                netcode_assert( 0 );
        }

        netcode_assert( buffer - start <= buffer_length - NETCODE_MAC_BYTES );

        uint8_t * encrypted_finish = buffer;

        // encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

        uint8_t additional_data[NETCODE_VERSION_INFO_BYTES+8+1];
        {
            uint8_t * p = additional_data;
            netcode_write_bytes( &p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
            netcode_write_uint64( &p, protocol_id );
            netcode_write_uint8( &p, prefix_byte );
        }

        uint8_t nonce[12];
        {
            uint8_t * p = nonce;
            netcode_write_uint32( &p, 0 );
            netcode_write_uint64( &p, sequence );
        }

        #if NETCODE_ENABLE_NONCE_AUDIT
        netcode_nonce_audit_write_packet( write_packet_key, nonce );
        #endif // #if NETCODE_ENABLE_NONCE_AUDIT

        if ( netcode_encrypt_aead( encrypted_start, 
                                   encrypted_finish - encrypted_start, 
                                   additional_data, sizeof( additional_data ), 
                                   nonce, write_packet_key ) != NETCODE_OK )
        {
            return NETCODE_ERROR;
        }

        buffer += NETCODE_MAC_BYTES;

        netcode_assert( buffer - start <= buffer_length );

        return (int) ( buffer - start );
    }
}

struct netcode_replay_protection_t
{
    uint64_t most_recent_sequence;
    uint64_t received_packet[NETCODE_REPLAY_PROTECTION_BUFFER_SIZE];
};

void netcode_replay_protection_reset( struct netcode_replay_protection_t * replay_protection )
{
    netcode_assert( replay_protection );
    replay_protection->most_recent_sequence = 0;
    memset( replay_protection->received_packet, 0xFF, sizeof( replay_protection->received_packet ) );
}

int netcode_replay_protection_already_received( struct netcode_replay_protection_t * replay_protection, uint64_t sequence )
{
    netcode_assert( replay_protection );

    // written so it cannot overflow: "sequence + BUFFER_SIZE <= most_recent" wraps for
    // sequence values near UINT64_MAX and falsely rejects them as replays

    if ( replay_protection->most_recent_sequence >= NETCODE_REPLAY_PROTECTION_BUFFER_SIZE &&
         sequence <= replay_protection->most_recent_sequence - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE )
        return 1;
    
    int index = (int) ( sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE );

    if ( replay_protection->received_packet[index] == UINT64_MAX )
        return 0;

    if ( replay_protection->received_packet[index] >= sequence )
        return 1;

    return 0;
}

void netcode_replay_protection_advance_sequence( struct netcode_replay_protection_t * replay_protection, uint64_t sequence )
{
    netcode_assert( replay_protection );

    if ( sequence > replay_protection->most_recent_sequence )
        replay_protection->most_recent_sequence = sequence;

    int index = (int) ( sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE );

    replay_protection->received_packet[index] = sequence;
}

void * netcode_read_packet( uint8_t * buffer, 
                            int buffer_length, 
                            uint64_t * sequence, 
                            uint8_t * read_packet_key, 
                            uint64_t protocol_id, 
                            uint8_t * allowed_packets, 
                            struct netcode_replay_protection_t * replay_protection, 
                            void * allocator_context, 
                            void* (*allocate_function)(void*,size_t) )
{
    netcode_assert( sequence );
    netcode_assert( allowed_packets );

    *sequence = 0;

    if ( allocate_function == NULL )
    {
        allocate_function = netcode_default_allocate_function;
    }

    if ( buffer_length < 1 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored packet. buffer length is less than 1\n" );
        return NULL;
    }

    uint8_t * start = buffer;

    uint8_t prefix_byte = netcode_read_uint8( &buffer );

    if ( prefix_byte < 0x10 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored packet. handshake packets are not read here\n" );
        return NULL;
    }
    {
        // *** encrypted packets ***

        if ( !read_packet_key )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. no read packet key for this address\n" );
            return NULL;
        }

        if ( buffer_length < 1 + 1 + NETCODE_MAC_BYTES )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet is too small to be valid (%d bytes)\n", buffer_length );
            return NULL;
        }

        // extract the packet type and number of sequence bytes from the prefix byte

        int packet_type = prefix_byte & 0xF;

        if ( packet_type >= NETCODE_CONNECTION_NUM_PACKETS )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet type %d is invalid\n", packet_type );
            return NULL;
        }

        if ( !allowed_packets[packet_type] )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet type %d is not allowed\n", packet_type );
            return NULL;
        }

        int sequence_bytes = prefix_byte >> 4;

        if ( sequence_bytes < 1 || sequence_bytes > 8 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. sequence bytes %d is out of range [1,8]\n", sequence_bytes );
            return NULL;
        }

        if ( buffer_length < 1 + sequence_bytes + NETCODE_MAC_BYTES )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. buffer is too small for sequence bytes + encryption mac\n" );
            return NULL;
        }

        // read variable length sequence number [1,8]

        int i;
        for ( i = 0; i < sequence_bytes; i++ )
        {
            uint8_t value = netcode_read_uint8( &buffer );
            (*sequence) |= ( uint64_t) ( value ) << ( 8 * i );
        }

        // ignore the packet if it has already been received

        if ( replay_protection && packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET )
        {
            if ( netcode_replay_protection_already_received( replay_protection, *sequence ) )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored packet. sequence %.16" PRIx64 " already received (replay protection)\n", *sequence );
                return NULL;
            }
        }

        // decrypt the per-packet type data

        uint8_t additional_data[NETCODE_VERSION_INFO_BYTES+8+1];
        {
            uint8_t * p = additional_data;
            netcode_write_bytes( &p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
            netcode_write_uint64( &p, protocol_id );
            netcode_write_uint8( &p, prefix_byte );
        }

        uint8_t nonce[12];
        {
            uint8_t * p = nonce;
            netcode_write_uint32( &p, 0 );
            netcode_write_uint64( &p, *sequence );
        }

        int encrypted_bytes = (int) ( buffer_length - ( buffer - start ) );

        if ( encrypted_bytes < NETCODE_MAC_BYTES )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. encrypted payload is too small\n" );
            return NULL;
        }

        if ( netcode_decrypt_aead( buffer, encrypted_bytes, additional_data, sizeof( additional_data ), nonce, read_packet_key ) != NETCODE_OK )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. failed to decrypt\n" );
            return NULL;
        }

        int decrypted_bytes = encrypted_bytes - NETCODE_MAC_BYTES;

        // update the latest replay protection sequence #

        if ( replay_protection && packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET )
        {
            netcode_replay_protection_advance_sequence( replay_protection, *sequence );
        }

        // process the per-packet type data that was just decrypted
        
        switch ( packet_type )
        {
            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
            {
                if ( decrypted_bytes != 8 )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection keep alive packet. decrypted packet data is wrong size\n" );
                    return NULL;
                }

                struct netcode_connection_keep_alive_packet_t * packet = (struct netcode_connection_keep_alive_packet_t*) 
                    allocate_function( allocator_context, sizeof( struct netcode_connection_keep_alive_packet_t ) );

                if ( !packet )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection keep alive packet. could not allocate packet struct\n" );
                    return NULL;
                }
                
                packet->packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
                packet->client_index = netcode_read_uint32( &buffer );
                packet->max_clients = netcode_read_uint32( &buffer );
                
                return packet;
            }
            break;
            
            case NETCODE_CONNECTION_PAYLOAD_PACKET:
            {
                if ( decrypted_bytes < 1 )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too small\n" );
                    return NULL;
                }

                if ( decrypted_bytes > NETCODE_MAX_PAYLOAD_BYTES )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too large\n" );
                    return NULL;
                }

                struct netcode_connection_payload_packet_t * packet = netcode_create_payload_packet( decrypted_bytes, allocator_context, allocate_function );

                if ( !packet )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. could not allocate packet struct\n" );
                    return NULL;
                }
                
                memcpy( packet->payload_data, buffer, decrypted_bytes );
                
                return packet;
            }
            break;

            case NETCODE_CONNECTION_DISCONNECT_PACKET:
            {
                if ( decrypted_bytes != 0 )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection disconnect packet. decrypted packet data is wrong size\n" );
                    return NULL;
                }

                struct netcode_connection_disconnect_packet_t * packet = (struct netcode_connection_disconnect_packet_t*) 
                    allocate_function( allocator_context, sizeof( struct netcode_connection_disconnect_packet_t ) );

                if ( !packet )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "ignored connection disconnect packet. could not allocate packet struct\n" );
                    return NULL;
                }
                
                packet->packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;
                
                return packet;
            }
            break;

            default:
                return NULL;
        }
    }
}

// ----------------------------------------------------------------

struct netcode_packet_queue_t
{
    void * allocator_context;
    void * (*allocate_function)(void*,size_t);
    void (*free_function)(void*,void*);
    int num_packets;
    int start_index;
    void * packet_data[NETCODE_PACKET_QUEUE_SIZE];
    uint64_t packet_sequence[NETCODE_PACKET_QUEUE_SIZE];
};

void netcode_packet_queue_init( struct netcode_packet_queue_t * queue, 
                                void * allocator_context, 
                                void * (*allocate_function)(void*,size_t), 
                                void (*free_function)(void*,void*) )
{
    if ( allocate_function == NULL )
    {
        allocate_function = netcode_default_allocate_function;
    }

    if ( free_function == NULL )
    {
        free_function = netcode_default_free_function;
    }

    netcode_assert( queue );

    queue->allocator_context = allocator_context;
    queue->allocate_function = allocate_function;
    queue->free_function = free_function;
    queue->num_packets = 0;
    queue->start_index = 0;
    memset( queue->packet_data, 0, sizeof( queue->packet_data ) );
    memset( queue->packet_sequence, 0, sizeof( queue->packet_sequence ) );
}

int netcode_packet_queue_push( struct netcode_packet_queue_t * queue, void * packet_data, uint64_t packet_sequence )
{
    netcode_assert( queue );
    netcode_assert( packet_data );
    if ( queue->num_packets == NETCODE_PACKET_QUEUE_SIZE )
    {
        queue->free_function( queue->allocator_context, packet_data );
        return 0;
    }
    int index = ( queue->start_index + queue->num_packets ) % NETCODE_PACKET_QUEUE_SIZE;
    queue->packet_data[index] = packet_data;
    queue->packet_sequence[index] = packet_sequence;
    queue->num_packets++;
    return 1;
}

void * netcode_packet_queue_pop( struct netcode_packet_queue_t * queue, uint64_t * packet_sequence )
{
    if ( queue->num_packets == 0 )
        return NULL;
    void * packet = queue->packet_data[queue->start_index];
    if ( packet_sequence )
        *packet_sequence = queue->packet_sequence[queue->start_index];
    queue->start_index = ( queue->start_index + 1 ) % NETCODE_PACKET_QUEUE_SIZE;
    queue->num_packets--;
    return packet;
}

void netcode_packet_queue_clear( struct netcode_packet_queue_t * queue )
{
    netcode_assert( queue );
    while ( queue->num_packets > 0 )
    {
        queue->free_function( queue->allocator_context, netcode_packet_queue_pop( queue, NULL ) );
    }
    queue->start_index = 0;
    memset( queue->packet_data, 0, sizeof( queue->packet_data ) );
    memset( queue->packet_sequence, 0, sizeof( queue->packet_sequence ) );
}

// ----------------------------------------------------------------

#define NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES ( NETCODE_MAX_CLIENTS * 256 )
#define NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS ( NETCODE_MAX_CLIENTS * 64 )
#define NETCODE_NETWORK_SIMULATOR_RNG_SEED 0x9E3779B97F4A7C15ULL

struct netcode_network_simulator_packet_entry_t
{
    struct netcode_address_t from;
    struct netcode_address_t to;
    double delivery_time;
    uint8_t * packet_data;
    int packet_bytes;
};

struct netcode_network_simulator_t
{
    void * allocator_context;
    void * (*allocate_function)(void*,size_t);
    void (*free_function)(void*,void*);
    float latency_milliseconds;
    float jitter_milliseconds;
    float packet_loss_percent;
    float duplicate_packet_percent;
    uint64_t rng_state;
    double time;
    int current_index;
    int num_pending_receive_packets;
    struct netcode_network_simulator_packet_entry_t packet_entries[NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES];
    struct netcode_network_simulator_packet_entry_t pending_receive_packets[NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS];
};

struct netcode_network_simulator_t * netcode_network_simulator_create( void * allocator_context, 
                                                                       void * (*allocate_function)(void*,size_t), 
                                                                       void (*free_function)(void*,void*) )
{
    if ( allocate_function == NULL )
    {
        allocate_function = netcode_default_allocate_function;
    }

    if ( free_function == NULL )
    {
        free_function = netcode_default_free_function;
    }

    struct netcode_network_simulator_t * network_simulator = (struct netcode_network_simulator_t*) 
        allocate_function( allocator_context, sizeof( struct netcode_network_simulator_t ) );

    netcode_assert( network_simulator );

    memset( network_simulator, 0, sizeof( struct netcode_network_simulator_t ) );

    network_simulator->allocator_context = allocator_context;
    network_simulator->allocate_function = allocate_function;
    network_simulator->free_function = free_function;
    network_simulator->rng_state = NETCODE_NETWORK_SIMULATOR_RNG_SEED;

    return network_simulator;
}

void netcode_network_simulator_reset( struct netcode_network_simulator_t * network_simulator )
{
    netcode_assert( network_simulator );

    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "network simulator reset\n" );

    int i;
    for ( i = 0; i < NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; i++ )
    {
        network_simulator->free_function( network_simulator->allocator_context, network_simulator->packet_entries[i].packet_data );
        memset( &network_simulator->packet_entries[i], 0, sizeof( struct netcode_network_simulator_packet_entry_t ) );
    }

    for ( i = 0; i < network_simulator->num_pending_receive_packets; i++ )
    {
        network_simulator->free_function( network_simulator->allocator_context, network_simulator->pending_receive_packets[i].packet_data );
        memset( &network_simulator->pending_receive_packets[i], 0, sizeof( struct netcode_network_simulator_packet_entry_t ) );
    }

    network_simulator->current_index = 0;
    network_simulator->num_pending_receive_packets = 0;
    network_simulator->rng_state = NETCODE_NETWORK_SIMULATOR_RNG_SEED;
}

void netcode_network_simulator_destroy( struct netcode_network_simulator_t * network_simulator )
{
    netcode_assert( network_simulator );
    netcode_network_simulator_reset( network_simulator );
    network_simulator->free_function( network_simulator->allocator_context, network_simulator );
}

static uint64_t netcode_network_simulator_random_uint64( struct netcode_network_simulator_t * network_simulator )
{
    // xorshift64*. self-contained and deterministic, unlike rand(): the simulator
    // produces the same loss, jitter and duplication sequence on every run, and
    // shares no state with the application or other simulator instances.

    uint64_t x = network_simulator->rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    network_simulator->rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static float netcode_network_simulator_random_float( struct netcode_network_simulator_t * network_simulator, float a, float b )
{
    netcode_assert( a < b );
    float random = (float) ( netcode_network_simulator_random_uint64( network_simulator ) >> 40 ) / (float) ( 1 << 24 );
    return a + random * ( b - a );
}

void netcode_network_simulator_queue_packet( struct netcode_network_simulator_t * network_simulator, 
                                             struct netcode_address_t * from, 
                                             struct netcode_address_t * to, 
                                             uint8_t * packet_data, 
                                             int packet_bytes, 
                                             float delay )
{
    // allocate before touching the slot. if the allocator fails, drop this packet and leave
    // the entry already queued in that slot alone, rather than copying into null.

    uint8_t * entry_packet_data = (uint8_t*) network_simulator->allocate_function( network_simulator->allocator_context, packet_bytes );

    if ( !entry_packet_data )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: network simulator could not allocate packet data\n" );
        return;
    }

    if ( network_simulator->packet_entries[network_simulator->current_index].packet_data )
    {
        network_simulator->free_function( network_simulator->allocator_context, network_simulator->packet_entries[network_simulator->current_index].packet_data );
        network_simulator->packet_entries[network_simulator->current_index].packet_data = NULL;
    }

    network_simulator->packet_entries[network_simulator->current_index].from = *from;
    network_simulator->packet_entries[network_simulator->current_index].to = *to;
    network_simulator->packet_entries[network_simulator->current_index].packet_data = entry_packet_data;
    memcpy( network_simulator->packet_entries[network_simulator->current_index].packet_data, packet_data, packet_bytes );
    network_simulator->packet_entries[network_simulator->current_index].packet_bytes = packet_bytes;
    network_simulator->packet_entries[network_simulator->current_index].delivery_time = network_simulator->time + delay;
    network_simulator->current_index++;
    network_simulator->current_index %= NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES;
}

void netcode_network_simulator_send_packet( struct netcode_network_simulator_t * network_simulator, 
                                            struct netcode_address_t * from, 
                                            struct netcode_address_t * to, 
                                            uint8_t * packet_data, 
                                            int packet_bytes )
{
    netcode_assert( network_simulator );
    netcode_assert( from );
    netcode_assert( from->type != 0 );
    netcode_assert( to );
    netcode_assert( to->type != 0 );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    if ( netcode_network_simulator_random_float( network_simulator, 0.0f, 100.0f ) <= network_simulator->packet_loss_percent )
        return;

    float delay = network_simulator->latency_milliseconds / 1000.0f;

    if ( network_simulator->jitter_milliseconds > 0.0 )
        delay += netcode_network_simulator_random_float( network_simulator, -network_simulator->jitter_milliseconds, +network_simulator->jitter_milliseconds ) / 1000.0f;

    netcode_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, delay );

    if ( netcode_network_simulator_random_float( network_simulator, 0.0f, 100.0f ) <= network_simulator->duplicate_packet_percent )
    {
        netcode_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, delay + netcode_network_simulator_random_float( network_simulator, 0, 1.0 ) );
    }
}

int netcode_network_simulator_receive_packets( struct netcode_network_simulator_t * network_simulator, 
                                               struct netcode_address_t * to, 
                                               int max_packets, 
                                               uint8_t ** packet_data, 
                                               int * packet_bytes, 
                                               struct netcode_address_t * from )
{
    netcode_assert( network_simulator );
    netcode_assert( max_packets >= 0 );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes );
    netcode_assert( from );
    netcode_assert( to );

    int num_packets = 0;

    int i;
    for ( i = 0; i < network_simulator->num_pending_receive_packets; i++ )
    {
        if ( num_packets == max_packets )
            break;

        if ( !network_simulator->pending_receive_packets[i].packet_data )
            continue;

        if ( !netcode_address_equal( &network_simulator->pending_receive_packets[i].to, to ) )
            continue;

        packet_data[num_packets] = network_simulator->pending_receive_packets[i].packet_data;
        packet_bytes[num_packets] = network_simulator->pending_receive_packets[i].packet_bytes;
        from[num_packets] = network_simulator->pending_receive_packets[i].from;

        network_simulator->pending_receive_packets[i].packet_data = NULL;

        num_packets++;
    }

    netcode_assert( num_packets <= max_packets );

    return num_packets;
}

void netcode_network_simulator_update( struct netcode_network_simulator_t * network_simulator, double time )
{   
    netcode_assert( network_simulator );

    network_simulator->time = time;

    // discard any pending receive packets that are still in the buffer

    int i;
    for ( i = 0; i < network_simulator->num_pending_receive_packets; i++ )
    {
        if ( network_simulator->pending_receive_packets[i].packet_data )
        {
            network_simulator->free_function( network_simulator->allocator_context, network_simulator->pending_receive_packets[i].packet_data );
            network_simulator->pending_receive_packets[i].packet_data = NULL;
        }
    }

    network_simulator->num_pending_receive_packets = 0;

    // walk across packet entries and move any that are ready to be received into the pending receive buffer

    for ( i = 0; i < NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES; i++ )
    {
        if ( !network_simulator->packet_entries[i].packet_data )
            continue;

        if ( network_simulator->num_pending_receive_packets == NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS )
            break;

        if ( network_simulator->packet_entries[i].packet_data && network_simulator->packet_entries[i].delivery_time <= time )
        {
            network_simulator->pending_receive_packets[network_simulator->num_pending_receive_packets] = network_simulator->packet_entries[i];
            network_simulator->num_pending_receive_packets++;
            network_simulator->packet_entries[i].packet_data = NULL;
        }
    }
}

// ----------------------------------------------------------------

// shared by the client and server send paths: dispatch a written packet to the network
// simulator, the send override, or the socket matching the destination address family

static void netcode_send_packet_to_address( struct netcode_network_simulator_t * network_simulator,
                                            void * override_context,
                                            void (*send_packet_override)(void*,struct netcode_address_t*,NETCODE_CONST uint8_t*,int),
                                            struct netcode_socket_holder_t * socket_holder,
                                            struct netcode_address_t * from,
                                            struct netcode_address_t * to,
                                            uint8_t * packet_data,
                                            int packet_bytes )
{
    if ( network_simulator )
    {
        netcode_network_simulator_send_packet( network_simulator, from, to, packet_data, packet_bytes );
    }
    else if ( send_packet_override )
    {
        send_packet_override( override_context, to, packet_data, packet_bytes );
    }
    else if ( to->type == NETCODE_ADDRESS_IPV4 )
    {
        netcode_socket_send_packet( &socket_holder->ipv4, to, packet_data, packet_bytes );
    }
    else if ( to->type == NETCODE_ADDRESS_IPV6 )
    {
        netcode_socket_send_packet( &socket_holder->ipv6, to, packet_data, packet_bytes );
    }
}

// ----------------------------------------------------------------

NETCODE_CONST char * netcode_client_state_name( int client_state )
{
    switch ( client_state )
    {
        case NETCODE_CLIENT_STATE_SERVER_KEY_MISMATCH:                  return "server key mismatch";
        case NETCODE_CLIENT_STATE_VERSION_MISMATCH:                     return "version mismatch";
        case NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT:                 return "connection timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT:         return "connection request timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT:        return "connection response timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_DENIED:                    return "connection denied";
        case NETCODE_CLIENT_STATE_DISCONNECTED:                         return "disconnected";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:           return "sending connection request";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:          return "sending connection response";
        case NETCODE_CLIENT_STATE_CONNECTED:                            return "connected";
        default:
            netcode_assert( 0 );
            return "???";
    }
}

void netcode_default_client_config( struct netcode_client_config_t * config )
{
    netcode_assert( config );
    config->allocator_context = NULL;
    config->allocate_function = netcode_default_allocate_function;
    config->free_function = netcode_default_free_function;
    config->network_simulator = NULL;
    config->callback_context = NULL;
    config->state_change_callback = NULL;
    config->send_loopback_packet_callback = NULL;
    config->override_send_and_receive = 0;
    config->send_packet_override = NULL;
    config->receive_packet_override = NULL;
    config->auxiliary_command_function = NULL;
    config->auxiliary_command_context = NULL;
    config->protocol_id = 0;
    config->connect_timeout_seconds = NETCODE_DEFAULT_CONNECT_TIMEOUT_SECONDS;
    config->timeout_seconds = NETCODE_DEFAULT_CONNECT_TIMEOUT_SECONDS;
}

struct netcode_client_t
{
    struct netcode_client_config_t config;
    int state;
    double time;
    double connect_start_time;
    double last_packet_send_time;
    double last_packet_receive_time;
    int should_disconnect;
    int should_disconnect_state;
    uint64_t sequence;
    int client_index;
    int max_clients;
    int server_address_index;
    int num_server_addresses;
    struct netcode_address_t server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    struct netcode_address_t address;
    struct netcode_address_t server_address;
    struct netcode_socket_holder_t socket_holder;
    struct netcode_context_t context;
    struct netcode_replay_protection_t replay_protection;
    struct netcode_packet_queue_t packet_receive_queue;

    int has_expected_server_public_key;
    uint8_t expected_server_public_key[NETCODE_PUBLIC_KEY_BYTES];
    int has_session_secret_key;
    uint8_t session_secret_key[NETCODE_SECRET_KEY_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];

    // per attempt (one server address)

    int has_server_public_key;
    uint8_t server_public_key[NETCODE_PUBLIC_KEY_BYTES];
    uint8_t connection_secret[NETCODE_CONNECTION_SECRET_BYTES];
    uint8_t cookie[NETCODE_COOKIE_BYTES];
    uint8_t response_packet[NETCODE_HANDSHAKE_RESPONSE_BYTES];
    int saw_server_key_mismatch;
    int saw_version_mismatch;
    double server_full_since;

    uint8_t * receive_packet_data[NETCODE_CLIENT_MAX_RECEIVE_PACKETS];
    int receive_packet_bytes[NETCODE_CLIENT_MAX_RECEIVE_PACKETS];
    struct netcode_address_t receive_from[NETCODE_CLIENT_MAX_RECEIVE_PACKETS];
    int loopback;
};

static int client_create_error;

int netcode_client_create_error()
{
    return client_create_error;
}

int netcode_client_socket_create( struct netcode_socket_t * socket,
                                  struct netcode_address_t * address,
                                  int send_buffer_size,
                                  int receive_buffer_size,
                                  NETCODE_CONST struct netcode_client_config_t * config )
{
    netcode_assert( socket );
    netcode_assert( address );
    netcode_assert( config );

    if ( !config->network_simulator )
    {
        if ( !config->override_send_and_receive )
        {
            if ( netcode_socket_create( socket, address, send_buffer_size, receive_buffer_size ) != NETCODE_SOCKET_ERROR_NONE )
            {
                client_create_error = ( address->type == NETCODE_ADDRESS_IPV6 ) ? NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED
                                                                                : NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED;
                return 0;
            }
        }
    }
    else
    {
        if ( address->port == 0 )
        {
            netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: must bind to a specific port when using network simulator\n" );
            client_create_error = NETCODE_CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT;
            return 0;
        }
    }

    return 1;
}

/*
    Why the attempts failed - kept over all the addresses of one connect (e.g. a remote address and then 127.0.0.1),
    so the reason a remote server gave is not lost to the next address. Cleared only when a new connect starts.
*/

static void netcode_client_clear_failure_hints( struct netcode_client_t * client )
{
    client->saw_server_key_mismatch = 0;
    client->saw_version_mismatch = 0;
    client->server_full_since = -1.0;
}

static void netcode_client_clear_attempt( struct netcode_client_t * client )
{
    client->has_server_public_key = 0;
    memset( client->server_public_key, 0, NETCODE_PUBLIC_KEY_BYTES );
    sodium_memzero( client->connection_secret, NETCODE_CONNECTION_SECRET_BYTES );
    memset( client->cookie, 0, NETCODE_COOKIE_BYTES );
    sodium_memzero( client->response_packet, NETCODE_HANDSHAKE_RESPONSE_BYTES );
    sodium_memzero( &client->context, sizeof( struct netcode_context_t ) );
}

struct netcode_client_t * netcode_client_create_dual( NETCODE_CONST char * address1_string,
                                                          NETCODE_CONST char * address2_string,
                                                          NETCODE_CONST struct netcode_client_config_t * config,
                                                          double time )
{
    netcode_assert( config );
    netcode_assert( netcode.initialized );

    client_create_error = NETCODE_CLIENT_CREATE_ERROR_NONE;

    // tolerate a zeroed config: default the allocator functions so a forgotten
    // netcode_default_client_config is an inconvenience, not a crash

    struct netcode_client_config_t config_copy = *config;
    if ( !config_copy.allocate_function )
        config_copy.allocate_function = netcode_default_allocate_function;
    if ( !config_copy.free_function )
        config_copy.free_function = netcode_default_free_function;
    if ( config_copy.connect_timeout_seconds <= 0 )
        config_copy.connect_timeout_seconds = NETCODE_DEFAULT_CONNECT_TIMEOUT_SECONDS;
    config = &config_copy;

    // the overrides are called on the update path with no null check. a missing one is a
    // configuration error, refused here rather than dereferenced on the first update.

    if ( config->override_send_and_receive && ( !config->send_packet_override || !config->receive_packet_override ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: override_send_and_receive requires both send_packet_override and receive_packet_override\n" );
        client_create_error = NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK;
        return NULL;
    }

    struct netcode_address_t address1;
    struct netcode_address_t address2;

    memset( &address1, 0, sizeof( address1 ) );
    memset( &address2, 0, sizeof( address2 ) );

    if ( netcode_parse_address( address1_string, &address1 ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse client address\n" );
        client_create_error = NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED;
        return NULL;
    }

    if ( address2_string != NULL && netcode_parse_address( address2_string, &address2 ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse client address2\n" );
        client_create_error = NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED;
        return NULL;
    }


    struct netcode_socket_t socket_ipv4;
    struct netcode_socket_t socket_ipv6;

    memset( &socket_ipv4, 0, sizeof( socket_ipv4 ) );
    memset( &socket_ipv6, 0, sizeof( socket_ipv6 ) );

    if ( address1.type == NETCODE_ADDRESS_IPV4 || address2.type == NETCODE_ADDRESS_IPV4 )
    {
        if ( !netcode_client_socket_create( &socket_ipv4, address1.type == NETCODE_ADDRESS_IPV4 ? &address1 : &address2, NETCODE_CLIENT_SOCKET_SNDBUF_SIZE, NETCODE_CLIENT_SOCKET_RCVBUF_SIZE, config ) )
        {
            return NULL;
        }
    }

    if ( address1.type == NETCODE_ADDRESS_IPV6 || address2.type == NETCODE_ADDRESS_IPV6 )
    {
        if ( !netcode_client_socket_create( &socket_ipv6, address1.type == NETCODE_ADDRESS_IPV6 ? &address1 : &address2, NETCODE_CLIENT_SOCKET_SNDBUF_SIZE, NETCODE_CLIENT_SOCKET_RCVBUF_SIZE, config ) )
        {
            netcode_socket_destroy( &socket_ipv4 );
            return NULL;
        }
    }

    struct netcode_client_t * client = (struct netcode_client_t*) config->allocate_function( config->allocator_context, sizeof( struct netcode_client_t ) );

    if ( !client )
    {
        netcode_socket_destroy( &socket_ipv4 );
        netcode_socket_destroy( &socket_ipv6 );
        client_create_error = NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED;
        return NULL;
    }

    memset( client, 0, sizeof( struct netcode_client_t ) );

    struct netcode_address_t socket_address = address1.type == NETCODE_ADDRESS_IPV4 ? socket_ipv4.address : socket_ipv6.address;

    if ( !config->network_simulator )
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "client started on port %d\n", socket_address.port );
    }
    else
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "client started on port %d (network simulator)\n", socket_address.port );
    }

    client->config = *config;
    client->socket_holder.ipv4 = socket_ipv4;
    client->socket_holder.ipv6 = socket_ipv6;
    client->address = config->network_simulator ? address1 : socket_address;
    client->state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client->time = time;
    client->connect_start_time = 0.0;
    client->last_packet_send_time = -1000.0;
    client->last_packet_receive_time = -1000.0;
    client->should_disconnect = 0;
    client->should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client->sequence = 0;
    client->client_index = 0;
    client->max_clients = 0;
    client->server_address_index = 0;
    client->loopback = 0;
    netcode_client_clear_attempt( client );
    netcode_client_clear_failure_hints( client );

    netcode_packet_queue_init( &client->packet_receive_queue, config->allocator_context, config->allocate_function, config->free_function );

    netcode_replay_protection_reset( &client->replay_protection );

    return client;
}

struct netcode_client_t * netcode_client_create( NETCODE_CONST char * address,
                                                 NETCODE_CONST struct netcode_client_config_t * config,
                                                 double time )
{
    return netcode_client_create_dual( address, NULL, config, time );
}

void netcode_client_destroy( struct netcode_client_t * client )
{
    netcode_assert( client );
    if ( !client->loopback )
        netcode_client_disconnect( client );
    else
        netcode_client_disconnect_loopback( client );
    netcode_socket_destroy( &client->socket_holder.ipv4 );
    netcode_socket_destroy( &client->socket_holder.ipv6 );
    netcode_packet_queue_clear( &client->packet_receive_queue );
    sodium_memzero( client->session_secret_key, NETCODE_SECRET_KEY_BYTES );
    client->config.free_function( client->config.allocator_context, client );
}

void netcode_client_set_state( struct netcode_client_t * client, int client_state )
{
    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client changed state from '%s' to '%s'\n",
        netcode_client_state_name( client->state ), netcode_client_state_name( client_state ) );

    if ( client->config.state_change_callback )
    {
        client->config.state_change_callback( client->config.callback_context, client->state, client_state );
    }

    client->state = client_state;
}

void netcode_client_reset_before_next_connect( struct netcode_client_t * client )
{
    client->connect_start_time = client->time;
    client->last_packet_send_time = client->time - 1.0f;
    client->last_packet_receive_time = client->time;
    client->should_disconnect = 0;
    client->should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client->sequence = 0;

    netcode_client_clear_attempt( client );

    netcode_replay_protection_reset( &client->replay_protection );
}

void netcode_client_reset_connection_data( struct netcode_client_t * client, int client_state )
{
    netcode_assert( client );

    client->sequence = 0;
    client->loopback = 0;
    client->client_index = 0;
    client->max_clients = 0;
    client->connect_start_time = 0.0;
    client->server_address_index = 0;
    client->num_server_addresses = 0;
    memset( &client->server_address, 0, sizeof( struct netcode_address_t ) );
    memset( client->server_addresses, 0, sizeof( client->server_addresses ) );
    client->has_expected_server_public_key = 0;
    client->has_session_secret_key = 0;
    sodium_memzero( client->session_secret_key, NETCODE_SECRET_KEY_BYTES );
    sodium_memzero( client->user_data, NETCODE_USER_DATA_BYTES );

    netcode_client_set_state( client, client_state );

    netcode_client_reset_before_next_connect( client );

    netcode_packet_queue_clear( &client->packet_receive_queue );
}

void netcode_client_disconnect_internal( struct netcode_client_t * client, int destination_state, int send_disconnect_packets );

static void netcode_client_send_raw( struct netcode_client_t * client, uint8_t * packet_data, int packet_bytes )
{
    netcode_send_packet_to_address( client->config.network_simulator,
                                    client->config.callback_context,
                                    client->config.override_send_and_receive ? client->config.send_packet_override : NULL,
                                    &client->socket_holder,
                                    &client->address,
                                    &client->server_address,
                                    packet_data,
                                    packet_bytes );

    client->last_packet_send_time = client->time;
}

static void netcode_client_log_connecting( struct netcode_client_t * client )
{
    char server_address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];

    if ( client->num_server_addresses == 1 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connecting to server %s\n",
            netcode_address_to_string( &client->server_address, server_address_string ) );
    }
    else
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connecting to server %s [%d/%d]\n",
            netcode_address_to_string( &client->server_address, server_address_string ), client->server_address_index + 1, client->num_server_addresses );
    }
}

void netcode_client_connect( struct netcode_client_t * client,
                             int num_server_addresses,
                             NETCODE_CONST struct netcode_address_t * server_addresses,
                             NETCODE_CONST uint8_t * expected_server_public_key,
                             NETCODE_CONST uint8_t * session_secret_key,
                             NETCODE_CONST uint8_t * user_data )
{
    netcode_assert( client );
    netcode_assert( server_addresses );
    netcode_assert( num_server_addresses > 0 );
    netcode_assert( num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );

    netcode_client_disconnect( client );

    if ( num_server_addresses <= 0 || num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: number of server addresses must be in [1,%d], got %d\n", NETCODE_MAX_SERVERS_PER_CONNECT, num_server_addresses );
        netcode_client_set_state( client, NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );
        return;
    }

    client->num_server_addresses = num_server_addresses;
    memcpy( client->server_addresses, server_addresses, sizeof( struct netcode_address_t ) * num_server_addresses );
    client->server_address_index = 0;
    client->server_address = client->server_addresses[0];

    client->has_expected_server_public_key = expected_server_public_key != NULL;

    if ( expected_server_public_key )
        memcpy( client->expected_server_public_key, expected_server_public_key, NETCODE_PUBLIC_KEY_BYTES );

    client->has_session_secret_key = session_secret_key != NULL;

    if ( session_secret_key )
        memcpy( client->session_secret_key, session_secret_key, NETCODE_SECRET_KEY_BYTES );

    if ( user_data )
        memcpy( client->user_data, user_data, NETCODE_USER_DATA_BYTES );
    else
        memset( client->user_data, 0, NETCODE_USER_DATA_BYTES );

    netcode_client_log_connecting( client );

    netcode_client_reset_before_next_connect( client );
    netcode_client_clear_failure_hints( client );

    netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );
}

NETCODE_CONST uint8_t * netcode_client_server_public_key( struct netcode_client_t * client )
{
    netcode_assert( client );
    return client->has_server_public_key ? client->server_public_key : NULL;
}

int netcode_client_server_address_index( struct netcode_client_t * client )
{
    netcode_assert( client );
    return client->server_address_index;
}

/*
    Seals the response to a challenge. A later challenge - the server found the cookie stale - is answered
    with the same connection secret under the new cookie.
*/

static int netcode_client_prepare_response( struct netcode_client_t * client, NETCODE_CONST uint8_t * cookie )
{
    uint8_t binding[NETCODE_BINDING_BYTES];
    netcode_connection_binding( binding, client->config.protocol_id, client->server_public_key, client->connection_secret, cookie );

    uint8_t plaintext[NETCODE_RESPONSE_PLAINTEXT_BYTES];
    uint8_t * p = plaintext;

    netcode_write_bytes( &p, (uint8_t*) cookie, NETCODE_COOKIE_BYTES );
    netcode_write_bytes( &p, client->connection_secret, NETCODE_CONNECTION_SECRET_BYTES );

    if ( client->has_session_secret_key )
    {
        if ( crypto_sign_detached( p, NULL, binding, NETCODE_BINDING_BYTES, client->session_secret_key ) != 0 )
        {
            sodium_memzero( plaintext, sizeof( plaintext ) );
            return 0;
        }
    }
    else
    {
        memset( p, 0, NETCODE_SIGNATURE_BYTES );
    }

    p += NETCODE_SIGNATURE_BYTES;

    netcode_write_bytes( &p, client->user_data, NETCODE_USER_DATA_BYTES );

    netcode_assert( p - plaintext == NETCODE_RESPONSE_PLAINTEXT_BYTES );

    uint8_t server_x25519_public_key[crypto_box_PUBLICKEYBYTES];

    if ( crypto_sign_ed25519_pk_to_curve25519( server_x25519_public_key, client->server_public_key ) != 0 )
    {
        sodium_memzero( plaintext, sizeof( plaintext ) );
        return 0;
    }

    uint8_t * out = client->response_packet;
    netcode_write_uint8( &out, NETCODE_HANDSHAKE_RESPONSE_PACKET );
    netcode_write_bytes( &out, (uint8_t*) cookie, NETCODE_COOKIE_BYTES );

    const int sealed = crypto_box_seal( out, plaintext, NETCODE_RESPONSE_PLAINTEXT_BYTES, server_x25519_public_key ) == 0;

    sodium_memzero( plaintext, sizeof( plaintext ) );

    memcpy( client->cookie, cookie, NETCODE_COOKIE_BYTES );

    return sealed;
}

static void netcode_client_process_challenge( struct netcode_client_t * client, NETCODE_CONST uint8_t * packet_data, int packet_bytes )
{
    if ( packet_bytes != NETCODE_HANDSHAKE_CHALLENGE_BYTES )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client ignored challenge packet. bad size %d\n", packet_bytes );
        return;
    }

    if ( client->state != NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST && client->state != NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
        return;

    uint8_t * p = (uint8_t*) packet_data + 1;

    uint8_t cookie[NETCODE_COOKIE_BYTES];
    uint8_t server_public_key[NETCODE_PUBLIC_KEY_BYTES];

    netcode_read_bytes( &p, cookie, NETCODE_COOKIE_BYTES );
    netcode_read_bytes( &p, server_public_key, NETCODE_PUBLIC_KEY_BYTES );
    const uint8_t flags = netcode_read_uint8( &p );

    /*
        Unauthenticated, like everything before the server proves it holds the key: a challenge with
        another key is only noted, so that a forged one can not break the connection, only explain its failure.
    */

    if ( client->has_expected_server_public_key && sodium_memcmp( server_public_key, client->expected_server_public_key, NETCODE_PUBLIC_KEY_BYTES ) != 0 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client ignored challenge packet. unexpected server public key\n" );

        /*
            Not on a fallback address (e.g. the same port on localhost): another server there is not the one
            being joined pretending to be it - it is just not that server.
        */

        if ( client->server_address_index == 0 )
        {
            client->saw_server_key_mismatch = 1;
        }

        return;
    }

    if ( client->has_server_public_key && sodium_memcmp( server_public_key, client->server_public_key, NETCODE_PUBLIC_KEY_BYTES ) != 0 )
    {
        /*
            Joined by address (no key pinned - see the pinned case above), a challenge with another key starts over with it:
            a forged first challenge is then corrected by the real server's next one. A fresh secret for every key -
            one sealed to someone else's key must never reach the real server. A "full" answer is no reason to switch.
        */

        if ( flags & NETCODE_CHALLENGE_FLAG_SERVER_FULL )
            return;

        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client took another server public key\n" );
        client->has_server_public_key = 0;
    }

    if ( flags & NETCODE_CHALLENGE_FLAG_SERVER_FULL )
    {
        if ( client->server_full_since < 0.0 )
            client->server_full_since = client->time;

        return;
    }

    // a challenge that does not say full ends a "full" spell, whatever its cookie

    client->server_full_since = -1.0;

    if ( !client->has_server_public_key )
    {
        memcpy( client->server_public_key, server_public_key, NETCODE_PUBLIC_KEY_BYTES );
        client->has_server_public_key = 1;

        netcode_random_bytes( client->connection_secret, NETCODE_CONNECTION_SECRET_BYTES );
        netcode_derive_packet_keys( client->connection_secret, client->context.write_packet_key, client->context.read_packet_key );
    }
    else if ( sodium_memcmp( cookie, client->cookie, NETCODE_COOKIE_BYTES ) == 0 )
    {
        return;
    }

    if ( !netcode_client_prepare_response( client, cookie ) )
    {
        // e.g. a forged key that is no valid point - ignored, a real challenge may still come

        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client ignored challenge packet. could not seal the response to its key\n" );
        client->has_server_public_key = 0;
        return;
    }

    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received connection challenge packet from server\n" );

    client->last_packet_receive_time = client->time;

    if ( client->state != NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
        netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE );

    // answer right away instead of on the next send tick

    client->last_packet_send_time = client->time - 1.0;
}

static void netcode_client_process_handshake_packet( struct netcode_client_t * client, struct netcode_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    if ( !netcode_address_equal( from, &client->server_address ) )
        return;

    switch ( packet_data[0] )
    {
        case NETCODE_HANDSHAKE_CHALLENGE_PACKET:
            netcode_client_process_challenge( client, packet_data, packet_bytes );
            break;

        case NETCODE_HANDSHAKE_VERSION_PACKET:
        {
            if ( packet_bytes == NETCODE_HANDSHAKE_VERSION_BYTES && 
                 ( client->state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST || client->state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE ) &&
                 !netcode_version_info_equal( packet_data + 1 ) )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received a version packet: the server runs another version\n" );
                client->saw_version_mismatch = 1;
            }
        }
        break;

        default:
            break;
    }
}

void netcode_client_process_packet_internal( struct netcode_client_t * client, struct netcode_address_t * from, uint8_t * packet, uint64_t sequence )
{
    netcode_assert( client );
    netcode_assert( packet );

    uint8_t packet_type = ( (uint8_t*) packet ) [0];

    switch ( packet_type )
    {
        case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
        {
            if ( netcode_address_equal( from, &client->server_address ) )
            {
                struct netcode_connection_keep_alive_packet_t * p = (struct netcode_connection_keep_alive_packet_t*) packet;

                if ( client->state == NETCODE_CLIENT_STATE_CONNECTED )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n" );

                    client->last_packet_receive_time = client->time;
                }
                else if ( client->state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n" );

                    client->last_packet_receive_time = client->time;
                    client->client_index = p->client_index;
                    client->max_clients = p->max_clients;

                    netcode_client_set_state( client, NETCODE_CLIENT_STATE_CONNECTED );

                    netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connected to server\n" );
                }
            }
        }
        break;

        case NETCODE_CONNECTION_PAYLOAD_PACKET:
        {
            if ( client->state == NETCODE_CLIENT_STATE_CONNECTED && netcode_address_equal( from, &client->server_address ) )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received connection payload packet from server\n" );

                netcode_packet_queue_push( &client->packet_receive_queue, packet, sequence );

                client->last_packet_receive_time = client->time;

                return;
            }
        }
        break;

        case NETCODE_CONNECTION_DISCONNECT_PACKET:
        {
            if ( client->state == NETCODE_CLIENT_STATE_CONNECTED && netcode_address_equal( from, &client->server_address ) )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client received disconnect packet from server\n" );

                client->should_disconnect = 1;
                client->should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
                client->last_packet_receive_time = client->time;
            }
        }
        break;

        default:
            break;
    }

    client->config.free_function( client->config.allocator_context, packet );    
}

void netcode_client_process_packet( struct netcode_client_t * client, struct netcode_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    if ( packet_bytes < 1 )
        return;

    if ( packet_data[0] < 0x10 )
    {
        netcode_client_process_handshake_packet( client, from, packet_data, packet_bytes );
        return;
    }

    if ( client->state != NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE && client->state != NETCODE_CLIENT_STATE_CONNECTED )
        return;

    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 0, sizeof( allowed_packets ) );
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;

    uint64_t sequence;

    void * packet = netcode_read_packet( packet_data, 
                                         packet_bytes, 
                                         &sequence, 
                                         client->context.read_packet_key, 
                                         client->config.protocol_id, 
                                         allowed_packets, 
                                         &client->replay_protection, 
                                         client->config.allocator_context, 
                                         client->config.allocate_function );

    if ( !packet )
        return;
    
    netcode_client_process_packet_internal( client, from, (uint8_t*)packet, sequence );
}

void netcode_client_receive_packets( struct netcode_client_t * client )
{
    netcode_assert( client );
    netcode_assert( !client->loopback );

    if ( !client->config.network_simulator )
    {
        // process packets received from socket

        while ( 1 )
        {
            struct netcode_address_t from;
            uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];
            int packet_bytes = 0;

            if ( client->config.override_send_and_receive )
            {
                packet_bytes = client->config.receive_packet_override( client->config.callback_context, &from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }
            else if ( client->server_address.type == NETCODE_ADDRESS_IPV4 )
            {
                packet_bytes = netcode_socket_receive_packet( &client->socket_holder.ipv4, &from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }
            else if ( client->server_address.type == NETCODE_ADDRESS_IPV6 )
            {
                packet_bytes = netcode_socket_receive_packet( &client->socket_holder.ipv6, &from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }

            if ( packet_bytes == 0 )
                break;

            if ( client->config.auxiliary_command_function != NULL )
            {
                if ( client->config.auxiliary_command_function( client->config.auxiliary_command_context, packet_data, packet_bytes ) )
                {
                    continue;
                }
            }

            netcode_client_process_packet( client, &from, packet_data, packet_bytes );
        }
    }
    else
    {
        // process packets received from network simulator

        int num_packets_received = netcode_network_simulator_receive_packets( client->config.network_simulator,
                                                                              &client->address,
                                                                              NETCODE_CLIENT_MAX_RECEIVE_PACKETS,
                                                                              client->receive_packet_data,
                                                                              client->receive_packet_bytes,
                                                                              client->receive_from );

        int i;
        for ( i = 0; i < num_packets_received; i++ )
        {
            netcode_client_process_packet( client, &client->receive_from[i], client->receive_packet_data[i], client->receive_packet_bytes[i] );

            client->config.free_function( client->config.allocator_context, client->receive_packet_data[i] );
        }
    }
}

void netcode_client_send_packet_to_server_internal( struct netcode_client_t * client, void * packet )
{
    netcode_assert( client );
    netcode_assert( !client->loopback );
    
    uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];

    int packet_bytes = netcode_write_packet( packet, 
                                             packet_data, 
                                             NETCODE_MAX_PACKET_BYTES, 
                                             client->sequence++, 
                                             client->context.write_packet_key, 
                                             client->config.protocol_id );

    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    if ( packet_bytes <= 0 )
        return;

    netcode_client_send_raw( client, packet_data, packet_bytes );
}

void netcode_client_send_packets( struct netcode_client_t * client )
{
    netcode_assert( client );
    netcode_assert( !client->loopback );

    switch ( client->state )
    {
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client->last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) >= client->time )
                return;

            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent connection request packet to server\n" );

            uint8_t packet_data[NETCODE_HANDSHAKE_REQUEST_BYTES];
            memset( packet_data, 0, sizeof( packet_data ) );

            uint8_t * p = packet_data;
            netcode_write_uint8( &p, NETCODE_HANDSHAKE_REQUEST_PACKET );
            netcode_write_bytes( &p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
            netcode_write_uint64( &p, client->config.protocol_id );

            netcode_client_send_raw( client, packet_data, NETCODE_HANDSHAKE_REQUEST_BYTES );
        }
        break;

        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client->last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) >= client->time )
                return;

            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent connection response packet to server\n" );

            netcode_client_send_raw( client, client->response_packet, NETCODE_HANDSHAKE_RESPONSE_BYTES );
        }
        break;

        case NETCODE_CLIENT_STATE_CONNECTED:
        {
            if ( client->last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) >= client->time )
                return;

            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent connection keep alive packet to server\n" );

            struct netcode_connection_keep_alive_packet_t packet;
            packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            packet.client_index = 0;
            packet.max_clients = 0;

            netcode_client_send_packet_to_server_internal( client, &packet );
        }
        break;
        
        default:
            break;
    }
}

int netcode_client_connect_to_next_server( struct netcode_client_t * client )
{
    netcode_assert( client );

    if ( client->server_address_index + 1 >= client->num_server_addresses )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client has no more servers to connect to\n" );
        return 0;
    }

    client->server_address_index++;
    client->server_address = client->server_addresses[client->server_address_index];

    netcode_client_reset_before_next_connect( client );

    netcode_client_log_connecting( client );

    netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );

    return 1;
}

/*
    Why an attempt failed. Each hint was unauthenticated, so it only names the failure
    of an attempt that got nowhere else.
*/

static int netcode_client_failed_attempt_state( struct netcode_client_t * client, int timed_out_state )
{
    if ( client->saw_version_mismatch )
        return NETCODE_CLIENT_STATE_VERSION_MISMATCH;

    if ( client->server_full_since >= 0.0 )
        return NETCODE_CLIENT_STATE_CONNECTION_DENIED;

    if ( client->saw_server_key_mismatch )
        return NETCODE_CLIENT_STATE_SERVER_KEY_MISMATCH;

    return timed_out_state;
}

void netcode_client_update( struct netcode_client_t * client, double time )
{
    netcode_assert( client );

    client->time = time;

    if ( client->loopback )
        return;

    netcode_client_receive_packets( client );

    netcode_client_send_packets( client );

    if ( client->should_disconnect )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client should disconnect -> %s\n", netcode_client_state_name( client->should_disconnect_state ) );
        if ( client->state != NETCODE_CLIENT_STATE_CONNECTED && netcode_client_connect_to_next_server( client ) )
            return;
        netcode_client_disconnect_internal( client, client->should_disconnect_state, 0 );
        return;
    }

    if ( client->state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST || client->state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
    {
        /*
            A server that says it is full is given a second to have a slot after all.
        */

        const int full_for_long = client->server_full_since >= 0.0 && client->server_full_since + 1.0 <= time;
        const int attempt_timed_out = client->connect_start_time + client->config.connect_timeout_seconds <= time;

        if ( full_for_long || attempt_timed_out )
        {
            const int timed_out_state = client->state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST ? 
                NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT : 
                NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT
            ;

            const int failed_state = netcode_client_failed_attempt_state( client, timed_out_state );

            netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connect failed: %s\n", netcode_client_state_name( failed_state ) );

            if ( netcode_client_connect_to_next_server( client ) )
                return;

            netcode_client_disconnect_internal( client, failed_state, 0 );
            return;
        }
    }
    else if ( client->state == NETCODE_CLIENT_STATE_CONNECTED )
    {
        if ( client->config.timeout_seconds > 0 && client->last_packet_receive_time + client->config.timeout_seconds < time )
        {
            netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connection timed out\n" );
            netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT, 0 );
            return;
        }
    }
}

uint64_t netcode_client_next_packet_sequence( struct netcode_client_t * client )
{
    netcode_assert( client );
    return client->sequence;  
}

void netcode_client_send_packet( struct netcode_client_t * client, NETCODE_CONST uint8_t * packet_data, int packet_bytes )
{
    netcode_assert( client );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_SIZE );

    // zero byte payloads are not valid on the wire and would silently vanish at the receiver

    if ( packet_bytes <= 0 || packet_bytes > NETCODE_MAX_PACKET_SIZE )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: payload packet size is out of range (%d)\n", packet_bytes );
        return;
    }

    if ( client->state != NETCODE_CLIENT_STATE_CONNECTED )
        return;

    if ( !client->loopback )
    {
        uint8_t buffer[NETCODE_MAX_PAYLOAD_BYTES*2];

        struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) buffer;

        packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        packet->payload_bytes = packet_bytes;
        memcpy( packet->payload_data, packet_data, packet_bytes );

        netcode_client_send_packet_to_server_internal( client, packet );
    }
    else
    {
        client->config.send_loopback_packet_callback( client->config.callback_context, 
                                                      client->client_index, 
                                                      packet_data,
                                                      packet_bytes,
                                                      client->sequence++ );
    }
}

uint8_t * netcode_client_receive_packet( struct netcode_client_t * client, int * packet_bytes, uint64_t * packet_sequence )
{
    netcode_assert( client );
    netcode_assert( packet_bytes );

    struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) 
        netcode_packet_queue_pop( &client->packet_receive_queue, packet_sequence );
    
    if ( packet )
    {
        netcode_assert( packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
        *packet_bytes = packet->payload_bytes;
        netcode_assert( *packet_bytes >= 0 );
        netcode_assert( *packet_bytes <= NETCODE_MAX_PAYLOAD_BYTES );
        return (uint8_t*) &packet->payload_data;
    }
    else
    {
        return NULL;
    }
}

void netcode_client_free_packet( struct netcode_client_t * client, void * packet )
{
    netcode_assert( client );
    netcode_assert( packet );
    uint8_t * packet_data = (uint8_t*) packet;
    int offset = offsetof( struct netcode_connection_payload_packet_t, payload_data );
    client->config.free_function( client->config.allocator_context, packet_data - offset );
}

void netcode_client_disconnect( struct netcode_client_t * client )
{
    netcode_assert( client );
    netcode_assert( !client->loopback );
    netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_DISCONNECTED, 1 );
}

void netcode_client_disconnect_internal( struct netcode_client_t * client, int destination_state, int send_disconnect_packets )
{
    netcode_assert( !client->loopback );
    netcode_assert( destination_state <= NETCODE_CLIENT_STATE_DISCONNECTED );

    if ( client->state <= NETCODE_CLIENT_STATE_DISCONNECTED || client->state == destination_state )
        return;

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "client disconnected\n" );

    if ( !client->loopback && send_disconnect_packets && client->state > NETCODE_CLIENT_STATE_DISCONNECTED )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent disconnect packets to server\n" );

        int i;
        for ( i = 0; i < NETCODE_NUM_DISCONNECT_PACKETS; i++ )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client sent disconnect packet %d\n", i );

            struct netcode_connection_disconnect_packet_t packet;
            packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

            netcode_client_send_packet_to_server_internal( client, &packet );
        }
    }

    netcode_client_reset_connection_data( client, destination_state );
}

int netcode_client_state( struct netcode_client_t * client )
{
    netcode_assert( client );
    return client->state;
}

int netcode_client_index( struct netcode_client_t * client )
{
    netcode_assert( client );
    return client->client_index;
}

int netcode_client_max_clients( struct netcode_client_t * client )
{   
    netcode_assert( client );
    return client->max_clients;
}

void netcode_client_connect_loopback( struct netcode_client_t * client, int client_index, int max_clients )
{
    netcode_assert( client );
    netcode_assert( client->state <= NETCODE_CLIENT_STATE_DISCONNECTED );

    // a loopback client sends only through this callback. without it the first send would
    // call a null pointer, so refuse to enter loopback at all, in every build.

    netcode_assert( client->config.send_loopback_packet_callback );

    if ( !client->config.send_loopback_packet_callback )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: a loopback client requires send_loopback_packet_callback\n" );
        return;
    }

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "client connected to server via loopback as client %d\n", client_index );
    client->state = NETCODE_CLIENT_STATE_CONNECTED;
    client->client_index = client_index;
    client->max_clients = max_clients;
    client->loopback = 1;
}

void netcode_client_disconnect_loopback( struct netcode_client_t * client )
{
    netcode_assert( client );
    netcode_assert( client->loopback );
    netcode_client_reset_connection_data( client, NETCODE_CLIENT_STATE_DISCONNECTED );
}

int netcode_client_loopback( struct netcode_client_t * client )
{
    netcode_assert( client );
    return client->loopback;
}

void netcode_client_process_loopback_packet( struct netcode_client_t * client, NETCODE_CONST uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence )
{
    netcode_assert( client );
    netcode_assert( client->loopback );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_SIZE );

    if ( !client->loopback )
        return;

    if ( packet_bytes <= 0 || packet_bytes > NETCODE_MAX_PACKET_SIZE )
        return;

    struct netcode_connection_payload_packet_t * packet = netcode_create_payload_packet( packet_bytes, client->config.allocator_context, client->config.allocate_function );
    if ( !packet )
        return;
    memcpy( packet->payload_data, packet_data, packet_bytes );
    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "client processing loopback packet from server\n" );
    netcode_packet_queue_push( &client->packet_receive_queue, packet, packet_sequence );
}

uint16_t netcode_client_get_port( struct netcode_client_t * client )
{
    netcode_assert( client );
    return client->address.type == NETCODE_ADDRESS_IPV4 ? client->socket_holder.ipv4.address.port : client->socket_holder.ipv6.address.port;
}

struct netcode_address_t * netcode_client_server_address( struct netcode_client_t * client )
{
    netcode_assert( client );
    return &client->server_address;
}

// ----------------------------------------------------------------

#define NETCODE_MAX_ENCRYPTION_MAPPINGS ( NETCODE_MAX_CLIENTS * 4 )

struct netcode_encryption_manager_t
{
    int num_encryption_mappings;
    int timeout[NETCODE_MAX_ENCRYPTION_MAPPINGS];
    double expire_time[NETCODE_MAX_ENCRYPTION_MAPPINGS];
    double last_access_time[NETCODE_MAX_ENCRYPTION_MAPPINGS];
    struct netcode_address_t address[NETCODE_MAX_ENCRYPTION_MAPPINGS];
    int client_index[NETCODE_MAX_ENCRYPTION_MAPPINGS];
    uint8_t send_key[NETCODE_KEY_BYTES*NETCODE_MAX_ENCRYPTION_MAPPINGS];
    uint8_t receive_key[NETCODE_KEY_BYTES*NETCODE_MAX_ENCRYPTION_MAPPINGS];
};

void netcode_encryption_manager_reset( struct netcode_encryption_manager_t * encryption_manager )
{
    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "reset encryption manager\n" );

    netcode_assert( encryption_manager );

    encryption_manager->num_encryption_mappings = 0;
    
    int i;
    for ( i = 0; i < NETCODE_MAX_ENCRYPTION_MAPPINGS; i++ )
    {
        encryption_manager->client_index[i] = -1;
        encryption_manager->expire_time[i] = -1.0;
        encryption_manager->last_access_time[i] = -1000.0;
        memset( &encryption_manager->address[i], 0, sizeof( struct netcode_address_t ) );
    }

    memset( encryption_manager->timeout, 0, sizeof( encryption_manager->timeout ) );    
    sodium_memzero( encryption_manager->send_key, sizeof( encryption_manager->send_key ) );
    sodium_memzero( encryption_manager->receive_key, sizeof( encryption_manager->receive_key ) );
}

int netcode_encryption_manager_entry_expired( struct netcode_encryption_manager_t * encryption_manager, int index, double time )
{
    return ( encryption_manager->timeout[index] > 0 && ( encryption_manager->last_access_time[index] + encryption_manager->timeout[index] ) < time ) ||
           ( encryption_manager->expire_time[index] >= 0.0 && encryption_manager->expire_time[index] < time );
}

int netcode_encryption_manager_add_encryption_mapping( struct netcode_encryption_manager_t * encryption_manager, 
                                                       struct netcode_address_t * address, 
                                                       uint8_t * send_key, 
                                                       uint8_t * receive_key, 
                                                       double time, 
                                                       double expire_time,
                                                       int timeout )
{
    int i;
    for ( i = 0; i < encryption_manager->num_encryption_mappings; i++ )
    {
        if ( netcode_address_equal( &encryption_manager->address[i], address ) && !netcode_encryption_manager_entry_expired( encryption_manager, i, time ) )
        {
            encryption_manager->timeout[i] = timeout;
            encryption_manager->expire_time[i] = expire_time;
            encryption_manager->last_access_time[i] = time;
            memcpy( encryption_manager->send_key + i * NETCODE_KEY_BYTES, send_key, NETCODE_KEY_BYTES );
            memcpy( encryption_manager->receive_key + i * NETCODE_KEY_BYTES, receive_key, NETCODE_KEY_BYTES );
            return 1;
        }
    }

    for ( i = 0; i < NETCODE_MAX_ENCRYPTION_MAPPINGS; i++ )
    {
        if ( encryption_manager->address[i].type == NETCODE_ADDRESS_NONE || 
            ( netcode_encryption_manager_entry_expired( encryption_manager, i, time ) && encryption_manager->client_index[i] == -1 ) )
        {
            encryption_manager->timeout[i] = timeout;
            encryption_manager->address[i] = *address;
            encryption_manager->expire_time[i] = expire_time;
            encryption_manager->last_access_time[i] = time;
            memcpy( encryption_manager->send_key + i * NETCODE_KEY_BYTES, send_key, NETCODE_KEY_BYTES );
            memcpy( encryption_manager->receive_key + i * NETCODE_KEY_BYTES, receive_key, NETCODE_KEY_BYTES );
            if ( i + 1 > encryption_manager->num_encryption_mappings )
                encryption_manager->num_encryption_mappings = i + 1;
            return 1;
        }
    }

    return 0;
}

int netcode_encryption_manager_remove_encryption_mapping( struct netcode_encryption_manager_t * encryption_manager, struct netcode_address_t * address, double time )
{
    netcode_assert( encryption_manager );
    netcode_assert( address );

    int i;
    for ( i = 0; i < encryption_manager->num_encryption_mappings; i++ )
    {
        if ( netcode_address_equal( &encryption_manager->address[i], address ) )
        {
            encryption_manager->expire_time[i] = -1.0;
            encryption_manager->last_access_time[i] = -1000.0;
            memset( &encryption_manager->address[i], 0, sizeof( struct netcode_address_t ) );
            sodium_memzero( encryption_manager->send_key + i * NETCODE_KEY_BYTES, NETCODE_KEY_BYTES );
            sodium_memzero( encryption_manager->receive_key + i * NETCODE_KEY_BYTES, NETCODE_KEY_BYTES );

            if ( i + 1 == encryption_manager->num_encryption_mappings )
            {
                int index = i - 1;
                while ( index >= 0 )
                {
                    if ( !netcode_encryption_manager_entry_expired( encryption_manager, index, time ) || encryption_manager->client_index[index] != -1 )
                    {
                        break;
                    }
                    encryption_manager->address[index].type = NETCODE_ADDRESS_NONE;
                    index--;
                }
                encryption_manager->num_encryption_mappings = index + 1;
            }

            return 1;
        }
    }

    return 0;
}

int netcode_encryption_manager_find_encryption_mapping( struct netcode_encryption_manager_t * encryption_manager, struct netcode_address_t * address, double time )
{
    int i;
    for ( i = 0; i < encryption_manager->num_encryption_mappings; i++ )
    {
        if ( netcode_address_equal( &encryption_manager->address[i], address ) && !netcode_encryption_manager_entry_expired( encryption_manager, i, time ) )
        {
            encryption_manager->last_access_time[i] = time;
            return i;
        }
    }
    return -1;
}

int netcode_encryption_manager_touch( struct netcode_encryption_manager_t * encryption_manager, int index, struct netcode_address_t * address, double time )
{
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager->num_encryption_mappings );
    if ( !netcode_address_equal( &encryption_manager->address[index], address ) )
        return 0;
    encryption_manager->last_access_time[index] = time;
    return 1;
}

void netcode_encryption_manager_set_expire_time( struct netcode_encryption_manager_t * encryption_manager, int index, double expire_time )
{
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager->num_encryption_mappings );
    encryption_manager->expire_time[index] = expire_time;
}


uint8_t * netcode_encryption_manager_get_send_key( struct netcode_encryption_manager_t * encryption_manager, int index )
{
    netcode_assert( encryption_manager );
    if ( index == -1 )
        return NULL;
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager->num_encryption_mappings );
    return encryption_manager->send_key + index * NETCODE_KEY_BYTES;
}

uint8_t * netcode_encryption_manager_get_receive_key( struct netcode_encryption_manager_t * encryption_manager, int index )
{
    netcode_assert( encryption_manager );
    if ( index == -1 )
        return NULL;
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager->num_encryption_mappings );
    return encryption_manager->receive_key + index * NETCODE_KEY_BYTES;
}

int netcode_encryption_manager_get_timeout( struct netcode_encryption_manager_t * encryption_manager, int index )
{
    netcode_assert( encryption_manager );
    if ( index == -1 )
        return 0;
    netcode_assert( index >= 0 );
    netcode_assert( index < encryption_manager->num_encryption_mappings );
    return encryption_manager->timeout[index];
}

typedef uint64_t netcode_fnv_t;

void netcode_fnv_init( netcode_fnv_t * fnv )
{
    *fnv = 0xCBF29CE484222325;
}

void netcode_fnv_write( netcode_fnv_t * fnv, NETCODE_CONST uint8_t * data, size_t size )
{
    for ( size_t i = 0; i < size; i++ )
    {
        (*fnv) ^= data[i];
        (*fnv) *= 0x00000100000001B3;
    }
}

uint64_t netcode_fnv_finalize( netcode_fnv_t * fnv )
{
    return *fnv;
}

uint64_t netcode_hash_string( NETCODE_CONST char * string )
{
    netcode_fnv_t fnv;
    netcode_fnv_init( &fnv );
    netcode_fnv_write( &fnv, (uint8_t *)( string ), strlen( string ) );
    return netcode_fnv_finalize( &fnv );
}

uint64_t netcode_hash_data( NETCODE_CONST uint8_t * data, size_t size )
{
    netcode_fnv_t fnv;
    netcode_fnv_init( &fnv );
    netcode_fnv_write( &fnv, (uint8_t *)( data ), size );
    return netcode_fnv_finalize( &fnv );
}

// ----------------------------------------------------------------

#define NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS       1
#define NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS      (1<<1)

void netcode_default_server_config( struct netcode_server_config_t * config )
{
    netcode_assert( config );
    config->allocator_context = NULL;
    config->allocate_function = netcode_default_allocate_function;
    config->free_function = netcode_default_free_function;
    config->network_simulator = NULL;
    config->callback_context = NULL;
    config->connect_disconnect_callback = NULL;
    config->send_loopback_packet_callback = NULL;
    config->override_send_and_receive = 0;
    config->send_packet_override = NULL;
    config->receive_packet_override = NULL;
    config->aux_send_packet = NULL;
    config->aux_receive_packet = NULL;
    config->auxiliary_command_function = NULL;
    config->auxiliary_command_context = NULL;
    config->disable_disconnect_packets = 0;
    config->timeout_seconds = NETCODE_DEFAULT_CONNECT_TIMEOUT_SECONDS;
    config->handshakes_per_second = NETCODE_DEFAULT_HANDSHAKES_PER_SECOND;
    config->allow_handshake_callback = NULL;
    config->allow_handshake_context = NULL;
}

struct netcode_server_t
{
    struct netcode_server_config_t config;
    struct netcode_socket_holder_t socket_holder;
    struct netcode_address_t address;
    struct netcode_address_t address2;
    uint32_t flags;
    double time;
    int running;
    int max_clients;
    int num_connected_clients;
    uint64_t global_sequence;
    uint8_t public_key[NETCODE_PUBLIC_KEY_BYTES];
    uint8_t x25519_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t x25519_secret_key[crypto_box_SECRETKEYBYTES];
    uint8_t cookie_key[NETCODE_KEY_BYTES];
    double handshake_rate_last_time;
    double handshake_rate_tokens;
    uint8_t used_cookies[NETCODE_USED_COOKIES][NETCODE_MAC_BYTES];
    int used_cookie_next;
    double rate_limit_last_logged;
    double table_full_last_logged;
    int client_connected[NETCODE_MAX_CLIENTS];
    int client_timeout[NETCODE_MAX_CLIENTS];
    int client_loopback[NETCODE_MAX_CLIENTS];
    int client_confirmed[NETCODE_MAX_CLIENTS];
    int client_disconnect_reason[NETCODE_MAX_CLIENTS];
    int client_encryption_index[NETCODE_MAX_CLIENTS];
    uint64_t client_id[NETCODE_MAX_CLIENTS];
    uint64_t client_sequence[NETCODE_MAX_CLIENTS];
    double client_last_packet_send_time[NETCODE_MAX_CLIENTS];
    double client_last_packet_receive_time[NETCODE_MAX_CLIENTS];
    uint8_t client_user_data[NETCODE_MAX_CLIENTS][NETCODE_USER_DATA_BYTES];
    uint8_t client_binding[NETCODE_MAX_CLIENTS][NETCODE_BINDING_BYTES];
    uint8_t client_session_signature[NETCODE_MAX_CLIENTS][NETCODE_SIGNATURE_BYTES];
    struct netcode_replay_protection_t client_replay_protection[NETCODE_MAX_CLIENTS];
    struct netcode_packet_queue_t client_packet_queue[NETCODE_MAX_CLIENTS];
    struct netcode_address_t client_address[NETCODE_MAX_CLIENTS];
    struct netcode_encryption_manager_t encryption_manager;
    uint8_t * receive_packet_data[NETCODE_SERVER_MAX_RECEIVE_PACKETS];
    int receive_packet_bytes[NETCODE_SERVER_MAX_RECEIVE_PACKETS];
    struct netcode_address_t receive_from[NETCODE_SERVER_MAX_RECEIVE_PACKETS];
};

static int server_create_error;

int netcode_server_create_error()
{
    return server_create_error;
}

int netcode_server_socket_create( struct netcode_socket_t * socket,
                                  struct netcode_address_t * address,
                                  int send_buffer_size,
                                  int receive_buffer_size,
                                  NETCODE_CONST struct netcode_server_config_t * config )
{
    netcode_assert( socket );
    netcode_assert( address );
    netcode_assert( config );

    if ( !config->network_simulator )
    {
        if ( !config->override_send_and_receive )
        {
            int socket_error = netcode_socket_create( socket, address, send_buffer_size, receive_buffer_size );

            if ( socket_error != NETCODE_SOCKET_ERROR_NONE )
            {
                // report bind failures separately: a port already in use is the common
                // operational failure for dedicated servers, and callers want to react
                // to it differently than to a socket that could not be created at all

                if ( socket_error == NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED || socket_error == NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED )
                {
                    server_create_error = ( address->type == NETCODE_ADDRESS_IPV6 ) ? NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED
                                                                                    : NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED;
                }
                else
                {
                    server_create_error = ( address->type == NETCODE_ADDRESS_IPV6 ) ? NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED
                                                                                    : NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED;
                }
                return 0;
            }
        }
    }

    return 1;
}

struct netcode_server_t * netcode_server_create_dual( NETCODE_CONST char * server_address1_string, NETCODE_CONST char * server_address2_string, NETCODE_CONST struct netcode_server_config_t * config, double time )
{
    netcode_assert( config );
    netcode_assert( netcode.initialized );

    server_create_error = NETCODE_SERVER_CREATE_ERROR_NONE;

    // tolerate a zeroed config: default the allocator functions so a forgotten
    // netcode_default_server_config is an inconvenience, not a crash

    struct netcode_server_config_t config_copy = *config;
    if ( !config_copy.allocate_function )
        config_copy.allocate_function = netcode_default_allocate_function;
    if ( !config_copy.free_function )
        config_copy.free_function = netcode_default_free_function;
    config = &config_copy;

    /*
        The private key is an Ed25519 secret key: the seed and the public key. Its X25519 form
        is what the clients seal their responses to.
    */

    uint8_t derived_public_key[NETCODE_PUBLIC_KEY_BYTES];
    uint8_t x25519_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t x25519_secret_key[crypto_box_SECRETKEYBYTES];

    if ( crypto_sign_ed25519_sk_to_pk( derived_public_key, config->private_key ) != 0 ||
         crypto_sign_ed25519_pk_to_curve25519( x25519_public_key, derived_public_key ) != 0 ||
         crypto_sign_ed25519_sk_to_curve25519( x25519_secret_key, config->private_key ) != 0 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: the server private key is not a valid Ed25519 secret key\n" );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_INVALID_PRIVATE_KEY;
        return NULL;
    }

    // the overrides are called on the update path with no null check. a missing one is a
    // configuration error, refused here rather than dereferenced on the first update.

    if ( config->override_send_and_receive && ( !config->send_packet_override || !config->receive_packet_override ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: override_send_and_receive requires both send_packet_override and receive_packet_override\n" );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK;
        return NULL;
    }

    struct netcode_address_t server_address1;
    struct netcode_address_t server_address2;

    memset( &server_address1, 0, sizeof( server_address1 ) );
    memset( &server_address2, 0, sizeof( server_address2 ) );

    if ( netcode_parse_address( server_address1_string, &server_address1 ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse server public address\n" );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED;
        return NULL;
    }

    if ( server_address2_string != NULL && netcode_parse_address( server_address2_string, &server_address2 ) != NETCODE_OK )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse server public address2\n" );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED;
        return NULL;
    }

    struct netcode_address_t bind_address_ipv4;
    struct netcode_address_t bind_address_ipv6;

    memset( &bind_address_ipv4, 0, sizeof( bind_address_ipv4 ) );
    memset( &bind_address_ipv6, 0, sizeof( bind_address_ipv6 ) );

    struct netcode_socket_t socket_ipv4;
    struct netcode_socket_t socket_ipv6;

    memset( &socket_ipv4, 0, sizeof( socket_ipv4 ) );
    memset( &socket_ipv6, 0, sizeof( socket_ipv6 ) );

    if ( server_address1.type == NETCODE_ADDRESS_IPV4 || server_address2.type == NETCODE_ADDRESS_IPV4 )
    {
        bind_address_ipv4.type = NETCODE_ADDRESS_IPV4;
        bind_address_ipv4.port = server_address1.type == NETCODE_ADDRESS_IPV4 ? server_address1.port : server_address2.port;

        if ( !netcode_server_socket_create( &socket_ipv4, &bind_address_ipv4, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE, config ) )
        {
            return NULL;
        }
    }

    if ( server_address1.type == NETCODE_ADDRESS_IPV6 || server_address2.type == NETCODE_ADDRESS_IPV6 )
    {
        bind_address_ipv6.type = NETCODE_ADDRESS_IPV6;
        bind_address_ipv6.port = server_address1.type == NETCODE_ADDRESS_IPV6 ? server_address1.port : server_address2.port;

        if ( !netcode_server_socket_create( &socket_ipv6, &bind_address_ipv6, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE, config ) )
        {
            netcode_socket_destroy( &socket_ipv4 );
            return NULL;
        }
    }

    struct netcode_server_t * server = (struct netcode_server_t*) config->allocate_function( config->allocator_context, sizeof( struct netcode_server_t ) );
    if ( !server )
    {
        netcode_socket_destroy( &socket_ipv4 );
        netcode_socket_destroy( &socket_ipv6 );
        server_create_error = NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED;
        return NULL;
    }

    memset( server, 0, sizeof(struct netcode_server_t) );

    if ( !config->network_simulator )
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "server listening on %s\n", server_address1_string );
    }
    else
    {
        netcode_printf( NETCODE_LOG_LEVEL_INFO, "server listening on %s (network simulator)\n", server_address1_string );
    }

    server->config = *config;
    server->socket_holder.ipv4 = socket_ipv4;
    server->socket_holder.ipv6 = socket_ipv6;
    server->address = server_address1;
    server->address2 = server_address2;
    server->time = time;
    server->global_sequence = 1ULL << 63;
    memcpy( server->public_key, derived_public_key, NETCODE_PUBLIC_KEY_BYTES );
    memcpy( server->x25519_public_key, x25519_public_key, crypto_box_PUBLICKEYBYTES );
    memcpy( server->x25519_secret_key, x25519_secret_key, crypto_box_SECRETKEYBYTES );
    sodium_memzero( x25519_secret_key, sizeof( x25519_secret_key ) );
    server->rate_limit_last_logged = -1000.0;
    server->table_full_last_logged = -1000.0;

    int i;
    for ( i = 0; i < NETCODE_MAX_CLIENTS; i++ )
    {
        server->client_encryption_index[i] = -1;
    }

    netcode_encryption_manager_reset( &server->encryption_manager );

    for ( i = 0; i < NETCODE_MAX_CLIENTS; i++ )
    {
        netcode_replay_protection_reset( &server->client_replay_protection[i] );
    }

    return server;
}

struct netcode_server_t * netcode_server_create( NETCODE_CONST char * server_address_string, NETCODE_CONST struct netcode_server_config_t * config, double time )
{
    return netcode_server_create_dual( server_address_string, NULL, config, time );
}

void netcode_server_stop( struct netcode_server_t * server );

void netcode_server_destroy( struct netcode_server_t * server )
{
    netcode_assert( server );

    netcode_server_stop( server );

    netcode_socket_destroy( &server->socket_holder.ipv4 );
    netcode_socket_destroy( &server->socket_holder.ipv6 );

    sodium_memzero( server->config.private_key, NETCODE_SECRET_KEY_BYTES );
    sodium_memzero( server->x25519_secret_key, crypto_box_SECRETKEYBYTES );

    server->config.free_function( server->config.allocator_context, server );
}

void netcode_server_start( struct netcode_server_t * server, int max_clients )
{
    netcode_assert( server );
    netcode_assert( max_clients > 0 );
    netcode_assert( max_clients <= NETCODE_MAX_CLIENTS );

    // the per-client arrays are sized NETCODE_MAX_CLIENTS. an out of range value here
    // must not get through in release builds where asserts compile out

    if ( max_clients <= 0 || max_clients > NETCODE_MAX_CLIENTS )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: max clients must be in [1,%d], got %d\n", NETCODE_MAX_CLIENTS, max_clients );
        return;
    }

    if ( server->running )
    {
        netcode_server_stop( server );
    }

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server started with %d client slots\n", max_clients );

    server->running = 1;
    server->max_clients = max_clients;
    server->num_connected_clients = 0;

    // a new cookie key: the cookies of a previous run do not get anywhere

    netcode_generate_key( server->cookie_key );
    memset( server->used_cookies, 0, sizeof( server->used_cookies ) );
    server->used_cookie_next = 0;

    server->handshake_rate_last_time = server->time;
    server->handshake_rate_tokens = 2.0 * server->config.handshakes_per_second;

    server->global_sequence = 1ULL << 63;

    int i;
    for ( i = 0; i < server->max_clients; i++ )
    {
        netcode_packet_queue_init( &server->client_packet_queue[i], server->config.allocator_context, server->config.allocate_function, server->config.free_function );
    }

    for ( i = 0; i < NETCODE_MAX_CLIENTS; i++ )
    {
        server->client_disconnect_reason[i] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    }
}

// Hypersomnia: lets the game route a packet through its own transport (e.g. WebRTC) instead of the real socket.
static int netcode_server_aux_send_packet( struct netcode_server_t * server, struct netcode_address_t * to, uint8_t * packet_data, int packet_bytes )
{
    if ( server->config.network_simulator || server->config.override_send_and_receive || server->config.aux_send_packet == NULL )
        return 0;

    if ( to->type != NETCODE_ADDRESS_IPV4 )
        return 0;

    return server->config.aux_send_packet( server->config.callback_context, to, packet_data, packet_bytes ) ? 1 : 0;
}

void netcode_server_send_client_packet( struct netcode_server_t * server, void * packet, int client_index )
{
    netcode_assert( server );
    netcode_assert( packet );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    netcode_assert( server->client_connected[client_index] );
    netcode_assert( !server->client_loopback[client_index] );

    uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];

    if ( !netcode_encryption_manager_touch( &server->encryption_manager, 
                                            server->client_encryption_index[client_index], 
                                            &server->client_address[client_index], 
                                            server->time ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: encryption mapping is out of date for client %d\n", client_index );
        return;
    }

    uint8_t * packet_key = netcode_encryption_manager_get_send_key( &server->encryption_manager, server->client_encryption_index[client_index] );

    int packet_bytes = netcode_write_packet( packet, packet_data, NETCODE_MAX_PACKET_BYTES, server->client_sequence[client_index], packet_key, server->config.protocol_id );

    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    // the sequence must advance however the packet was sent, or the client's replay protection drops the next ones
    if ( !netcode_server_aux_send_packet( server, &server->client_address[client_index], packet_data, packet_bytes ) )
    {
        netcode_send_packet_to_address( server->config.network_simulator,
                                        server->config.callback_context,
                                        server->config.override_send_and_receive ? server->config.send_packet_override : NULL,
                                        &server->socket_holder,
                                        &server->address,
                                        &server->client_address[client_index],
                                        packet_data,
                                        packet_bytes );
    }

    server->client_sequence[client_index]++;

    server->client_last_packet_send_time[client_index] = server->time;
}

static void netcode_server_reset_client_slot( struct netcode_server_t * server, int client_index )
{
    netcode_packet_queue_clear( &server->client_packet_queue[client_index] );

    server->client_connected[client_index] = 0;
    server->client_loopback[client_index] = 0;
    server->client_confirmed[client_index] = 0;
    server->client_id[client_index] = 0;
    server->client_sequence[client_index] = 0;
    server->client_last_packet_send_time[client_index] = 0.0;
    server->client_last_packet_receive_time[client_index] = 0.0;
    memset( &server->client_address[client_index], 0, sizeof( struct netcode_address_t ) );
    server->client_encryption_index[client_index] = -1;
    sodium_memzero( server->client_user_data[client_index], NETCODE_USER_DATA_BYTES );
    memset( server->client_binding[client_index], 0, NETCODE_BINDING_BYTES );
    memset( server->client_session_signature[client_index], 0, NETCODE_SIGNATURE_BYTES );

    server->num_connected_clients--;

    netcode_assert( server->num_connected_clients >= 0 );
}

void netcode_server_disconnect_client_internal( struct netcode_server_t * server, int client_index, int send_disconnect_packets, int disconnect_reason )
{
    netcode_assert( server );
    netcode_assert( server->running );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    netcode_assert( server->client_connected[client_index] );
    netcode_assert( !server->client_loopback[client_index] );
    netcode_assert( server->encryption_manager.client_index[server->client_encryption_index[client_index]] == client_index );

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server disconnected client %d\n", client_index );

    // record why before the callback fires, so the reason can be queried from inside the callback

    server->client_disconnect_reason[client_index] = disconnect_reason;

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.callback_context, client_index, 0 );
    }

    // Hypersomnia: the game can opt out of netcode disconnect packets.
    if ( send_disconnect_packets && !server->config.disable_disconnect_packets )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server sent disconnect packets to client %d\n", client_index );

        int i;
        for ( i = 0; i < NETCODE_NUM_DISCONNECT_PACKETS; i++ )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server sent disconnect packet %d\n", i );

            struct netcode_connection_disconnect_packet_t packet;
            packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

            netcode_server_send_client_packet( server, &packet, client_index );
        }
    }

    netcode_replay_protection_reset( &server->client_replay_protection[client_index] );

    server->encryption_manager.client_index[server->client_encryption_index[client_index]] = -1;

    netcode_encryption_manager_remove_encryption_mapping( &server->encryption_manager, &server->client_address[client_index], server->time );

    netcode_server_reset_client_slot( server, client_index );
}

void netcode_server_disconnect_client( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );

    if ( !server->running )
        return;

    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );

    if ( client_index < 0 || client_index >= server->max_clients )
        return;

    netcode_assert( server->client_loopback[client_index] == 0 );

    if ( !server->client_connected[client_index] )
        return;

    if ( server->client_loopback[client_index] )
        return;

    netcode_server_disconnect_client_internal( server, client_index, 1, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );
}

void netcode_server_disconnect_all_clients( struct netcode_server_t * server )
{
    netcode_assert( server );

    if ( !server->running )
        return;

    int i;
    for ( i = 0; i < server->max_clients; i++ )
    {
        if ( server->client_connected[i] && !server->client_loopback[i] )
        {
            netcode_server_disconnect_client_internal( server, i, 1, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );
        }
    }
}

void netcode_server_stop( struct netcode_server_t * server )
{
    netcode_assert( server );

    if ( !server->running )
        return;

    netcode_server_disconnect_all_clients( server );

    // loopback clients are not disconnected above, but they must not survive a server stop

    int i;
    for ( i = 0; i < server->max_clients; i++ )
    {
        if ( server->client_connected[i] && server->client_loopback[i] )
        {
            netcode_server_disconnect_loopback_client( server, i );
        }
    }

    server->running = 0;
    server->max_clients = 0;
    server->num_connected_clients = 0;

    server->global_sequence = 0;
    sodium_memzero( server->cookie_key, NETCODE_KEY_BYTES );

    netcode_encryption_manager_reset( &server->encryption_manager );

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server stopped\n" );
}

int netcode_server_find_client_index_by_id( struct netcode_server_t * server, uint64_t client_id )
{
    netcode_assert( server );

    int i;
    for ( i = 0; i < server->max_clients; i++ )
    {   
        if ( server->client_connected[i] && server->client_id[i] == client_id )
            return i;
    }

    return -1;
}

int netcode_server_find_client_index_by_address( struct netcode_server_t * server, struct netcode_address_t * address )
{
    netcode_assert( server );
    netcode_assert( address );

    int i;
    for ( i = 0; i < server->max_clients; i++ )
    {   
        if ( server->client_connected[i] && netcode_address_equal( &server->client_address[i], address ) )
            return i;
    }

    return -1;
}

int netcode_server_find_free_client_index( struct netcode_server_t * server )
{
    netcode_assert( server );

    int i;
    for ( i = 0; i < server->max_clients; i++ )
    {
        if ( !server->client_connected[i] )
            return i;
    }

    return -1;
}

void netcode_server_connect_client( struct netcode_server_t * server, 
                                    int client_index, 
                                    struct netcode_address_t * address, 
                                    uint64_t client_id, 
                                    int encryption_index,
                                    int timeout_seconds, 
                                    void * user_data )
{
    netcode_assert( server );
    netcode_assert( server->running );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    netcode_assert( address );
    netcode_assert( encryption_index != -1 );
    netcode_assert( user_data );
    netcode_assert( server->encryption_manager.client_index[encryption_index] == -1 );

    server->num_connected_clients++;

    netcode_assert( server->num_connected_clients <= server->max_clients );

    netcode_assert( server->client_connected[client_index] == 0 );

    netcode_encryption_manager_set_expire_time( &server->encryption_manager, encryption_index, -1.0 );
    
    server->encryption_manager.client_index[encryption_index] = client_index;

    server->client_connected[client_index] = 1;
    server->client_timeout[client_index] = timeout_seconds;
    server->client_encryption_index[client_index] = encryption_index;
    server->client_id[client_index] = client_id;
    server->client_sequence[client_index] = 0;
    server->client_address[client_index] = *address;
    server->client_disconnect_reason[client_index] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;

    netcode_assert( netcode_server_find_client_index_by_id( server, client_id ) == client_index );
    netcode_assert( netcode_server_find_client_index_by_address( server, address ) == client_index );

    server->client_last_packet_send_time[client_index] = server->time;
    server->client_last_packet_receive_time[client_index] = server->time;
    memcpy( server->client_user_data[client_index], user_data, NETCODE_USER_DATA_BYTES );

    char address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server accepted client %s %.16" PRIx64 " in slot %d\n", 
        netcode_address_to_string( address, address_string ), client_id, client_index );

    struct netcode_connection_keep_alive_packet_t packet;
    packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
    packet.client_index = client_index;
    packet.max_clients = server->max_clients;

    netcode_server_send_client_packet( server, &packet, client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.callback_context, client_index, 1 );
    }
}

// a refusal that is no part of normal operation must be visible in the logs, but at most
// every 10 seconds, so that a flood does not flood the logs too

static void netcode_server_log_refusal( struct netcode_server_t * server, double * last_logged, const char * what )
{
    if ( server->time - *last_logged >= 10.0 || server->time < *last_logged )
    {
        *last_logged = server->time;
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "server refused a connection: %s\n", what );
    }
}

static void netcode_server_send_raw( struct netcode_server_t * server, struct netcode_address_t * to, uint8_t * packet_data, int packet_bytes )
{
    if ( !netcode_server_aux_send_packet( server, to, packet_data, packet_bytes ) )
    {
        netcode_send_packet_to_address( server->config.network_simulator,
                                        server->config.callback_context,
                                        server->config.override_send_and_receive ? server->config.send_packet_override : NULL,
                                        &server->socket_holder,
                                        &server->address,
                                        to,
                                        packet_data,
                                        packet_bytes );
    }
}

static void netcode_server_send_challenge( struct netcode_server_t * server, struct netcode_address_t * from )
{
    // the cookie time is the server's monotonic time in milliseconds: no wall clock is involved

    const uint64_t timestamp = (uint64_t) ( server->time * 1000.0 );

    uint8_t packet_data[NETCODE_HANDSHAKE_CHALLENGE_BYTES];
    uint8_t * p = packet_data;

    netcode_write_uint8( &p, NETCODE_HANDSHAKE_CHALLENGE_PACKET );
    netcode_write_uint64( &p, timestamp );

    uint8_t mac[NETCODE_MAC_BYTES];
    netcode_cookie_mac( mac, server->cookie_key, from, timestamp, server->config.protocol_id );
    netcode_write_bytes( &p, mac, NETCODE_MAC_BYTES );

    netcode_write_bytes( &p, server->public_key, NETCODE_PUBLIC_KEY_BYTES );

    const uint8_t flags = server->num_connected_clients >= server->max_clients ? NETCODE_CHALLENGE_FLAG_SERVER_FULL : 0;
    netcode_write_uint8( &p, flags );

    netcode_assert( p - packet_data == NETCODE_HANDSHAKE_CHALLENGE_BYTES );

    netcode_server_send_raw( server, from, packet_data, NETCODE_HANDSHAKE_CHALLENGE_BYTES );
}

static void netcode_server_process_handshake_request( struct netcode_server_t * server, struct netcode_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    if ( packet_bytes < 1 + NETCODE_VERSION_INFO_BYTES + 8 )
        return;

    uint8_t * p = packet_data + 1;

    uint8_t version_info[NETCODE_VERSION_INFO_BYTES];
    netcode_read_bytes( &p, version_info, NETCODE_VERSION_INFO_BYTES );

    if ( !netcode_version_info_equal( version_info ) )
    {
        // answered so that the player learns to update; never larger than the request

        if ( packet_bytes >= NETCODE_HANDSHAKE_VERSION_BYTES )
        {
            uint8_t answer[NETCODE_HANDSHAKE_VERSION_BYTES];
            uint8_t * a = answer;
            netcode_write_uint8( &a, NETCODE_HANDSHAKE_VERSION_PACKET );
            netcode_write_bytes( &a, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
            netcode_server_send_raw( server, from, answer, NETCODE_HANDSHAKE_VERSION_BYTES );
        }

        return;
    }

    if ( packet_bytes != NETCODE_HANDSHAKE_REQUEST_BYTES )
        return;

    if ( netcode_read_uint64( &p ) != server->config.protocol_id )
        return;

    if ( netcode_server_find_client_index_by_address( server, from ) != -1 )
        return;

    netcode_server_send_challenge( server, from );
}

static int netcode_take_token( double * last_time, double * tokens_left, double now, double rate, double burst )
{
    double elapsed = now - *last_time;

    if ( elapsed < 0.0 )
        elapsed = 0.0;

    double tokens = *tokens_left + elapsed * rate;

    if ( tokens > burst )
        tokens = burst;

    *last_time = now;

    if ( tokens < 1.0 )
    {
        *tokens_left = tokens;
        return 0;
    }

    *tokens_left = tokens - 1.0;
    return 1;
}

/*
    One handshake (an X25519 and what the application verifies after it) per call that returns 1:
    first the application's own rule for the address (allow_handshake_callback), then the cap for all addresses together.
*/

static int netcode_server_take_handshake( struct netcode_server_t * server, NETCODE_CONST struct netcode_address_t * address )
{
    if ( server->config.allow_handshake_callback && !server->config.allow_handshake_callback( server->config.allow_handshake_context, address ) )
        return 0;

    if ( server->config.handshakes_per_second > 0.0 )
    {
        const double rate = server->config.handshakes_per_second;

        if ( !netcode_take_token( &server->handshake_rate_last_time, &server->handshake_rate_tokens, server->time, rate, 2.0 * rate ) )
            return 0;
    }

    return 1;
}

static int netcode_server_cookie_used( struct netcode_server_t * server, NETCODE_CONST uint8_t * mac )
{
    int i;
    for ( i = 0; i < NETCODE_USED_COOKIES; i++ )
    {
        if ( memcmp( server->used_cookies[i], mac, NETCODE_MAC_BYTES ) == 0 )
            return 1;
    }

    return 0;
}

static void netcode_server_process_handshake_response( struct netcode_server_t * server, struct netcode_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    if ( packet_bytes != NETCODE_HANDSHAKE_RESPONSE_BYTES )
        return;

    // the client repeats its response until it hears from the connection it made

    if ( netcode_server_find_client_index_by_address( server, from ) != -1 )
        return;

    uint8_t * p = packet_data + 1;
    uint8_t * cookie = p;

    const uint64_t timestamp = netcode_read_uint64( &p );
    uint8_t * mac = p;

    uint8_t expected_mac[NETCODE_MAC_BYTES];
    netcode_cookie_mac( expected_mac, server->cookie_key, from, timestamp, server->config.protocol_id );

    if ( sodium_memcmp( mac, expected_mac, NETCODE_MAC_BYTES ) != 0 )
    {
        /*
            Not ours: e.g. a client that took a forged challenge from someone else would otherwise send this
            until it gives up - a fresh challenge to the address (smaller than this response) puts it back on track.
        */

        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server answered a cookie that is not for this address with a new challenge\n" );
        netcode_server_send_challenge( server, from );
        return;
    }

    const uint64_t now = (uint64_t) ( server->time * 1000.0 );

    if ( timestamp > now || now - timestamp > (uint64_t) NETCODE_COOKIE_SECONDS * 1000 )
    {
        // ours but stale, e.g. a client that stalled: a fresh challenge costs nothing and is smaller than this response

        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server answered a stale cookie with a new challenge\n" );
        netcode_server_send_challenge( server, from );
        return;
    }

    if ( netcode_server_cookie_used( server, mac ) )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. the cookie was already used\n" );
        return;
    }

    if ( server->num_connected_clients >= server->max_clients )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. server is full\n" );
        return;
    }

    if ( !netcode_server_take_handshake( server, from ) )
    {
        netcode_server_log_refusal( server, &server->rate_limit_last_logged, "a handshake was refused (the application's limit for its address, or too many handshakes for all)" );
        return;
    }

    uint8_t plaintext[NETCODE_RESPONSE_PLAINTEXT_BYTES];

    if ( crypto_box_seal_open( plaintext,
                               packet_data + 1 + NETCODE_COOKIE_BYTES,
                               NETCODE_HANDSHAKE_RESPONSE_BYTES - 1 - NETCODE_COOKIE_BYTES,
                               server->x25519_public_key,
                               server->x25519_secret_key ) != 0 )
    {
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. failed to open the sealed box\n" );
        return;
    }

    uint8_t * q = plaintext;

    // the cookie inside is what binds the sealed box to this address: a recorded response can not be resent from another

    if ( sodium_memcmp( q, cookie, NETCODE_COOKIE_BYTES ) != 0 )
    {
        sodium_memzero( plaintext, sizeof( plaintext ) );
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. the sealed cookie differs\n" );
        return;
    }

    q += NETCODE_COOKIE_BYTES;

    uint8_t * connection_secret = q;
    q += NETCODE_CONNECTION_SECRET_BYTES;

    uint8_t * session_signature = q;
    q += NETCODE_SIGNATURE_BYTES;

    uint8_t * user_data = q;

    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
    netcode_derive_packet_keys( connection_secret, client_to_server_key, server_to_client_key );

    if ( !netcode_encryption_manager_add_encryption_mapping( &server->encryption_manager,
                                                             from,
                                                             server_to_client_key,
                                                             client_to_server_key,
                                                             server->time,
                                                             -1.0,
                                                             server->config.timeout_seconds ) )
    {
        sodium_memzero( plaintext, sizeof( plaintext ) );
        sodium_memzero( client_to_server_key, NETCODE_KEY_BYTES );
        sodium_memzero( server_to_client_key, NETCODE_KEY_BYTES );
        netcode_server_log_refusal( server, &server->table_full_last_logged, "the encryption mapping table is full (a leak)" );
        return;
    }

    sodium_memzero( client_to_server_key, NETCODE_KEY_BYTES );
    sodium_memzero( server_to_client_key, NETCODE_KEY_BYTES );

    memcpy( server->used_cookies[server->used_cookie_next], mac, NETCODE_MAC_BYTES );
    server->used_cookie_next = ( server->used_cookie_next + 1 ) % NETCODE_USED_COOKIES;

    const int encryption_index = netcode_encryption_manager_find_encryption_mapping( &server->encryption_manager, from, server->time );
    const int client_index = netcode_server_find_free_client_index( server );

    netcode_assert( encryption_index != -1 );
    netcode_assert( client_index != -1 );

    if ( encryption_index == -1 || client_index == -1 )
    {
        sodium_memzero( plaintext, sizeof( plaintext ) );
        return;
    }

    uint64_t client_id;

    do
    {
        netcode_random_bytes( (uint8_t*) &client_id, 8 );
    }
    while ( client_id == 0 || netcode_server_find_client_index_by_id( server, client_id ) != -1 );

    netcode_connection_binding( server->client_binding[client_index], server->config.protocol_id, server->public_key, connection_secret, cookie );
    memcpy( server->client_session_signature[client_index], session_signature, NETCODE_SIGNATURE_BYTES );

    netcode_server_connect_client( server, client_index, from, client_id, encryption_index, server->config.timeout_seconds, user_data );

    sodium_memzero( plaintext, sizeof( plaintext ) );
}

void netcode_server_process_packet_internal( struct netcode_server_t * server, 
                                             struct netcode_address_t * from, 
                                             void * packet, 
                                             uint64_t sequence,
                                             int client_index )
{
    netcode_assert( server );
    netcode_assert( packet );

    (void) from;
    (void) sequence;

    uint8_t packet_type = ( (uint8_t*) packet ) [0];

    switch ( packet_type )
    {
        case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
        {
            if ( client_index != -1 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server received connection keep alive packet from client %d\n", client_index );
                server->client_last_packet_receive_time[client_index] = server->time;
                if ( !server->client_confirmed[client_index] )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server confirmed connection with client %d\n", client_index );
                    server->client_confirmed[client_index] = 1;
                }
            }
        }
        break;

        case NETCODE_CONNECTION_PAYLOAD_PACKET:
        {
            if ( client_index != -1 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server received connection payload packet from client %d\n", client_index );
                server->client_last_packet_receive_time[client_index] = server->time;
                if ( !server->client_confirmed[client_index] )
                {
                    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server confirmed connection with client %d\n", client_index );
                    server->client_confirmed[client_index] = 1;
                }
                netcode_packet_queue_push( &server->client_packet_queue[client_index], packet, sequence );
                return;
            }
        }
        break;

        case NETCODE_CONNECTION_DISCONNECT_PACKET:
        {
            if ( client_index != -1 )
            {
                netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server received disconnect packet from client %d\n", client_index );
                netcode_server_disconnect_client_internal( server, client_index, 0, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT );
           }
        }
        break;

        default:
            break;
    }

    server->config.free_function( server->config.allocator_context, packet );
}

void netcode_server_read_and_process_packet( struct netcode_server_t * server,
                                             struct netcode_address_t * from,
                                             uint8_t * packet_data,
                                             int packet_bytes,
                                             uint8_t * allowed_packets )
{
    if ( !server->running )
        return;

    if ( packet_bytes <= 1 )
        return;

    if ( server->config.auxiliary_command_function != NULL ) {
		if (server->config.auxiliary_command_function(
			server->config.auxiliary_command_context,
			from,
			packet_data,
			packet_bytes
		)) {
			return;
		}
	}

    if ( packet_data[0] == NETCODE_HANDSHAKE_REQUEST_PACKET )
    {
        if ( ( server->flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS ) == 0 )
            netcode_server_process_handshake_request( server, from, packet_data, packet_bytes );

        return;
    }

    if ( packet_data[0] == NETCODE_HANDSHAKE_RESPONSE_PACKET )
    {
        if ( ( server->flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS ) == 0 )
            netcode_server_process_handshake_response( server, from, packet_data, packet_bytes );

        return;
    }

    if ( packet_data[0] < 0x10 )
        return;

    const int client_index = netcode_server_find_client_index_by_address( server, from );

    if ( client_index == -1 )
    {
        char address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];
        netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server could not process packet because no client is connected from %s\n", netcode_address_to_string( from, address_string ) );
        return;
    }

    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );

    uint8_t * read_packet_key = netcode_encryption_manager_get_receive_key( &server->encryption_manager, server->client_encryption_index[client_index] );

    if ( !read_packet_key )
        return;

    uint64_t sequence;

    void * packet = netcode_read_packet( packet_data,
                                         packet_bytes,
                                         &sequence,
                                         read_packet_key,
                                         server->config.protocol_id,
                                         allowed_packets,
                                         &server->client_replay_protection[client_index],
                                         server->config.allocator_context,
                                         server->config.allocate_function );

    if ( !packet )
        return;

    netcode_server_process_packet_internal( server, from, packet, sequence, client_index );
}

void netcode_server_process_packet( struct netcode_server_t * server, struct netcode_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 0, sizeof( allowed_packets ) );
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;

    netcode_server_read_and_process_packet( server, from, packet_data, packet_bytes, allowed_packets );
}

void netcode_server_receive_packets( struct netcode_server_t * server )
{
    netcode_assert( server );

    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 0, sizeof( allowed_packets ) );
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;

    if ( !server->config.network_simulator )
    {
        // process packets received from socket

        while ( 1 )
        {
            struct netcode_address_t from;
            memset( &from, 0, sizeof(from) );

            uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];
            
            int packet_bytes = 0;
            
            if ( server->config.override_send_and_receive )
            {
                packet_bytes = server->config.receive_packet_override( server->config.callback_context, &from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }
            else
            {
                if (server->socket_holder.ipv4.handle != 0)
                    packet_bytes = netcode_socket_receive_packet( &server->socket_holder.ipv4, &from, packet_data, NETCODE_MAX_PACKET_BYTES );

                if ( packet_bytes == 0 && server->socket_holder.ipv6.handle != 0)
                    packet_bytes = netcode_socket_receive_packet( &server->socket_holder.ipv6, &from, packet_data, NETCODE_MAX_PACKET_BYTES );

                if ( packet_bytes == 0 && server->config.aux_receive_packet != NULL )
                    packet_bytes = server->config.aux_receive_packet( server->config.callback_context, &from, packet_data, NETCODE_MAX_PACKET_BYTES );
            }

            if ( packet_bytes == 0 )
                break;

            netcode_server_read_and_process_packet( server, &from, packet_data, packet_bytes, allowed_packets );
        }
    }
    else
    {
        // process packets received from network simulator

        int num_packets_received = netcode_network_simulator_receive_packets( server->config.network_simulator, 
                                                                              &server->address, 
                                                                              NETCODE_SERVER_MAX_RECEIVE_PACKETS, 
                                                                              server->receive_packet_data, 
                                                                              server->receive_packet_bytes, 
                                                                              server->receive_from );

        int i;
        for ( i = 0; i < num_packets_received; i++ )
        {
            netcode_server_read_and_process_packet( server, 
                                                    &server->receive_from[i], 
                                                    server->receive_packet_data[i], 
                                                    server->receive_packet_bytes[i],
                                                    allowed_packets );

            server->config.free_function( server->config.allocator_context, server->receive_packet_data[i] );
        }
    }
}

void netcode_server_send_packets( struct netcode_server_t * server )
{
    netcode_assert( server );

    if ( !server->running )
        return;

    int i;
    for ( i = 0; i < server->max_clients; i++ )
    {
        if ( server->client_connected[i] && !server->client_loopback[i] &&
             ( server->client_last_packet_send_time[i] + ( 1.0 / NETCODE_PACKET_SEND_RATE ) <= server->time ) )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server sent connection keep alive packet to client %d\n", i );
            struct netcode_connection_keep_alive_packet_t packet;
            packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            packet.client_index = i;
            packet.max_clients = server->max_clients;
            netcode_server_send_client_packet( server, &packet, i );
        }
    }
}

void netcode_server_check_for_timeouts( struct netcode_server_t * server )
{
    netcode_assert( server );

    if ( !server->running )
        return;

    int i;
    for ( i = 0; i < server->max_clients; i++ )
    {
        if ( !server->client_connected[i] )
            continue;

        if ( server->client_timeout[i] <= 0 )
            continue;

        if ( server->client_loopback[i] )
            continue;

        if ( ( server->time - server->client_last_packet_receive_time[i] ) >= 1.0f )
        {
            netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server has not received a packet from client %d for %.2f seconds\n", i, server->time - server->client_last_packet_receive_time[i] );
        }

        if ( server->client_last_packet_receive_time[i] + server->client_timeout[i] <= server->time )
        {
            netcode_printf( NETCODE_LOG_LEVEL_INFO, "server timed out client %d\n", i );
            netcode_server_disconnect_client_internal( server, i, 0, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT );
        }
    }
}

int netcode_server_client_connected( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );

    if ( !server->running )
        return 0;

    if ( client_index < 0 || client_index >= server->max_clients )
        return 0;

    return server->client_connected[client_index];
}

int netcode_server_client_disconnect_reason( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );

    if ( !server->running )
        return NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;

    if ( client_index < 0 || client_index >= server->max_clients )
        return NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;

    return server->client_disconnect_reason[client_index];
}

uint64_t netcode_server_client_id( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );

    if ( !server->running )
        return 0;

    if ( client_index < 0 || client_index >= server->max_clients )
        return 0;

    return server->client_id[client_index];
}

struct netcode_address_t * netcode_server_client_address( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );

    if (!server->running)
        return NULL;

    if (client_index < 0 || client_index >= server->max_clients)
        return NULL;

    return &server->client_address[client_index];
}

uint64_t netcode_server_next_packet_sequence( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    if ( !server->running )
        return 0;
    if ( client_index < 0 || client_index >= server->max_clients )
        return 0;
    if ( !server->client_connected[client_index] )
        return 0;
    return server->client_sequence[client_index];
}

void netcode_server_send_packet( struct netcode_server_t * server, int client_index, NETCODE_CONST uint8_t * packet_data, int packet_bytes )
{
    netcode_assert( server );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_SIZE );

    // zero byte payloads are not valid on the wire and would silently vanish at the receiver

    if ( packet_bytes <= 0 || packet_bytes > NETCODE_MAX_PACKET_SIZE )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: payload packet size is out of range (%d)\n", packet_bytes );
        return;
    }

    if ( !server->running )
        return;

    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );

    if ( client_index < 0 || client_index >= server->max_clients )
        return;

    if ( !server->client_connected[client_index] )
        return;

    if ( !server->client_loopback[client_index] )
    {
        uint8_t buffer[NETCODE_MAX_PAYLOAD_BYTES*2];

        struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) buffer;

        packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        packet->payload_bytes = packet_bytes;
        memcpy( packet->payload_data, packet_data, packet_bytes );

        if ( !server->client_confirmed[client_index] )
        {
            struct netcode_connection_keep_alive_packet_t keep_alive_packet;
            keep_alive_packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            keep_alive_packet.client_index = client_index;
            keep_alive_packet.max_clients = server->max_clients;
            netcode_server_send_client_packet( server, &keep_alive_packet, client_index );
        }

        netcode_server_send_client_packet( server, packet, client_index );
    }
    else
    {
        netcode_assert( server->config.send_loopback_packet_callback );

        server->config.send_loopback_packet_callback( server->config.callback_context,
                                                      client_index, 
                                                      packet_data, 
                                                      packet_bytes, 
                                                      server->client_sequence[client_index]++ );

        server->client_last_packet_send_time[client_index] = server->time;
    }
}

uint8_t * netcode_server_receive_packet( struct netcode_server_t * server, int client_index, int * packet_bytes, uint64_t * packet_sequence )
{
    netcode_assert( server );
    netcode_assert( packet_bytes );

    netcode_assert( client_index >= 0 );

    if ( !server->running )
        return NULL;

    netcode_assert( client_index < server->max_clients );

    if ( client_index < 0 || client_index >= server->max_clients )
        return NULL;

    if ( !server->client_connected[client_index] )
        return NULL;

    struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*)
        netcode_packet_queue_pop( &server->client_packet_queue[client_index], packet_sequence );
    
    if ( packet )
    {
        netcode_assert( packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
        *packet_bytes = packet->payload_bytes;
        netcode_assert( *packet_bytes >= 0 );
        netcode_assert( *packet_bytes <= NETCODE_MAX_PAYLOAD_BYTES );
        return (uint8_t*) &packet->payload_data;
    }
    else
    {
        return NULL;
    }
}

void netcode_server_free_packet( struct netcode_server_t * server, void * packet )
{
    netcode_assert( server );
    netcode_assert( packet );
    (void) server;
    int offset = offsetof( struct netcode_connection_payload_packet_t, payload_data );
    server->config.free_function( server->config.allocator_context, ( (uint8_t*) packet ) - offset );
}

int netcode_server_num_connected_clients( struct netcode_server_t * server )
{
    netcode_assert( server );
    return server->num_connected_clients;
}

void * netcode_server_client_user_data( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    if ( !server->running )
        return NULL;
    if ( client_index < 0 || client_index >= server->max_clients )
        return NULL;
    return server->client_user_data[client_index];
}

NETCODE_CONST uint8_t * netcode_server_client_binding( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );
    if ( !server->running || client_index < 0 || client_index >= server->max_clients )
        return NULL;
    return server->client_binding[client_index];
}

NETCODE_CONST uint8_t * netcode_server_client_session_signature( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );
    if ( !server->running || client_index < 0 || client_index >= server->max_clients )
        return NULL;
    return server->client_session_signature[client_index];
}

NETCODE_CONST uint8_t * netcode_server_public_key( struct netcode_server_t * server )
{
    netcode_assert( server );
    return server->public_key;
}

int netcode_server_running( struct netcode_server_t * server )
{
    netcode_assert( server );
    return server->running;
}

int netcode_server_max_clients( struct netcode_server_t * server )
{
    return server->max_clients;
}

void netcode_server_update( struct netcode_server_t * server, double time )
{
    netcode_assert( server );
    server->time = time;
    netcode_server_receive_packets( server );
    netcode_server_send_packets( server );
    netcode_server_check_for_timeouts( server );
}

void netcode_server_connect_loopback_client( struct netcode_server_t * server, int client_index, uint64_t client_id, NETCODE_CONST uint8_t * user_data )
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    netcode_assert( server->running );

    // the server sends to a loopback client only through this callback. without it the
    // first send would call a null pointer, so refuse the slot at all, in every build.

    netcode_assert( server->config.send_loopback_packet_callback );

    if ( !server->config.send_loopback_packet_callback )
    {
        netcode_printf( NETCODE_LOG_LEVEL_ERROR, "error: a loopback client requires send_loopback_packet_callback\n" );
        return;
    }

    if ( !server->running )
        return;

    if ( client_index < 0 || client_index >= server->max_clients )
        return;

    netcode_assert( !server->client_connected[client_index] );

    if ( server->client_connected[client_index] )
        return;

    server->num_connected_clients++;

    netcode_assert( server->num_connected_clients <= server->max_clients );

    server->client_loopback[client_index] = 1;
    server->client_connected[client_index] = 1;
    server->client_confirmed[client_index] = 1;
    server->client_encryption_index[client_index] = -1;
    server->client_id[client_index] = client_id;
    server->client_sequence[client_index] = 0;
    server->client_disconnect_reason[client_index] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    memset( &server->client_address[client_index], 0, sizeof( struct netcode_address_t ) );
    server->client_last_packet_send_time[client_index] = server->time;
    server->client_last_packet_receive_time[client_index] = server->time;

    if ( user_data )
    {
        memcpy( server->client_user_data[client_index], user_data, NETCODE_USER_DATA_BYTES );
    }
    else
    {
        memset( server->client_user_data[client_index], 0, NETCODE_USER_DATA_BYTES );
    }

    memset( server->client_binding[client_index], 0, NETCODE_BINDING_BYTES );
    memset( server->client_session_signature[client_index], 0, NETCODE_SIGNATURE_BYTES );

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server connected loopback client %.16" PRIx64 " in slot %d\n", client_id, client_index );

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.callback_context, client_index, 1 );
    }
}

void netcode_server_disconnect_loopback_client( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    netcode_assert( server->running );

    if ( !server->running )
        return;

    if ( client_index < 0 || client_index >= server->max_clients )
        return;

    netcode_assert( server->client_connected[client_index] );
    netcode_assert( server->client_loopback[client_index] );

    if ( !server->client_connected[client_index] || !server->client_loopback[client_index] )
        return;

    netcode_printf( NETCODE_LOG_LEVEL_INFO, "server disconnected loopback client %d\n", client_index );

    server->client_disconnect_reason[client_index] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT;

    if ( server->config.connect_disconnect_callback )
    {
        server->config.connect_disconnect_callback( server->config.callback_context, client_index, 0 );
    }

    netcode_server_reset_client_slot( server, client_index );
}

int netcode_server_client_loopback( struct netcode_server_t * server, int client_index )
{
    netcode_assert( server );
    netcode_assert( server->running );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    if ( !server->running )
        return 0;
    if ( client_index < 0 || client_index >= server->max_clients )
        return 0;
    return server->client_loopback[client_index];
}

void netcode_server_process_loopback_packet( struct netcode_server_t * server, int client_index, NETCODE_CONST uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence )
{
    netcode_assert( server );
    netcode_assert( client_index >= 0 );
    netcode_assert( client_index < server->max_clients );
    netcode_assert( packet_data );
    netcode_assert( packet_bytes > 0 );
    netcode_assert( packet_bytes <= NETCODE_MAX_PACKET_SIZE );
    netcode_assert( server->running );

    if ( !server->running )
        return;

    if ( client_index < 0 || client_index >= server->max_clients )
        return;

    netcode_assert( server->client_connected[client_index] );
    netcode_assert( server->client_loopback[client_index] );

    if ( !server->client_connected[client_index] || !server->client_loopback[client_index] )
        return;

    if ( packet_bytes <= 0 || packet_bytes > NETCODE_MAX_PACKET_SIZE )
        return;

    struct netcode_connection_payload_packet_t * packet = netcode_create_payload_packet( packet_bytes, server->config.allocator_context, server->config.allocate_function );
    if ( !packet )
        return;

    memcpy( packet->payload_data, packet_data, packet_bytes );

    netcode_printf( NETCODE_LOG_LEVEL_DEBUG, "server processing loopback packet from client %d\n", client_index );

    server->client_last_packet_receive_time[client_index] = server->time;

    netcode_packet_queue_push( &server->client_packet_queue[client_index], packet, packet_sequence );
}

uint16_t netcode_server_get_port( struct netcode_server_t * server )
{
    netcode_assert( server );
    return server->address.type == NETCODE_ADDRESS_IPV4 ? server->socket_holder.ipv4.address.port : server->socket_holder.ipv6.address.port;
}

// ----------------------------------------------------------------

// ---------------------------------------------------------------

#if NETCODE_PLATFORM == NETCODE_PLATFORM_MAC

// MacOS

#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

void netcode_sleep( double time )
{
    struct timespec ts;
    ts.tv_sec = (time_t) time;
    ts.tv_nsec = (long) ((time - (double) ( ts.tv_sec )) * 1000000000.0);
    nanosleep( &ts, NULL );
}

static uint64_t start = 0;
static mach_timebase_info_data_t timebase_info;

double netcode_time()
{
    if ( start == 0 )
    {
        mach_timebase_info( &timebase_info );
        start = mach_absolute_time();
        return 0.0;
    }
    uint64_t current = mach_absolute_time();
    return ( (double) ( current - start ) ) * ( (double) timebase_info.numer ) / ( (double) timebase_info.denom ) / 1000000000.0;
}

#elif NETCODE_PLATFORM == NETCODE_PLATFORM_UNIX

// linux and other unix systems (openbsd, freebsd etc.)

#include <unistd.h>

// linux has CLOCK_MONOTONIC_RAW, but other unix systems only have CLOCK_MONOTONIC

#ifdef CLOCK_MONOTONIC_RAW
#define NETCODE_MONOTONIC_CLOCK CLOCK_MONOTONIC_RAW
#else
#define NETCODE_MONOTONIC_CLOCK CLOCK_MONOTONIC
#endif

void netcode_sleep( double time )
{
    struct timespec ts;
    ts.tv_sec = (time_t) time;
    ts.tv_nsec = (long) ((time - (double) ( ts.tv_sec )) * 1000000000.0);
    nanosleep( &ts, NULL );
}

double netcode_time()
{
    static double start = -1;
    if ( start == -1 )
    {
        struct timespec ts;
        clock_gettime( NETCODE_MONOTONIC_CLOCK, &ts );
        start = ts.tv_sec + ( (double) ( ts.tv_nsec ) ) / 1000000000.0;
        return 0.0;
    }
    struct timespec ts;
    clock_gettime( NETCODE_MONOTONIC_CLOCK, &ts );
    double current = ts.tv_sec + ( (double) ( ts.tv_nsec ) ) / 1000000000.0;
    return current - start;
}

#elif defined(__EMSCRIPTEN__)

#elif NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

// windows

#ifndef NOMINMAX
#define NOMINMAX
#endif // #ifndef NOMINMAX
#include <windows.h>

void netcode_sleep( double time )
{
    int milliseconds = (int) ( time * 1000 );
    Sleep( milliseconds );
}

static int timer_initialized = 0;
static LARGE_INTEGER timer_frequency;
static LARGE_INTEGER timer_start;

double netcode_time()
{
    if ( !timer_initialized )
    {
        QueryPerformanceFrequency( &timer_frequency );
        QueryPerformanceCounter( &timer_start );
        timer_initialized = 1;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter( &now );
    return ( (double) ( now.QuadPart - timer_start.QuadPart ) ) / ( (double) ( timer_frequency.QuadPart ) );
}

#elif defined(__EMSCRIPTEN__)

#else

#error unsupported platform!

#endif

// ---------------------------------------------------------------

#if NETCODE_ENABLE_TESTS

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>

static void check_handler( NETCODE_CONST char * condition, 
                           NETCODE_CONST char * function,
                           NETCODE_CONST char * file,
                           int line )
{
    printf( "check failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
#ifdef NETCODE_DEBUG
    #if defined( __GNUC__ )
        __builtin_trap();
    #elif defined( _MSC_VER )
        __debugbreak();
    #endif
#endif
    exit( 1 );
}

static uint8_t test_server_secret_key[NETCODE_SECRET_KEY_BYTES];
static uint8_t test_server_public_key[NETCODE_PUBLIC_KEY_BYTES];
static uint8_t test_session_secret_key[NETCODE_SECRET_KEY_BYTES];
static uint8_t test_session_public_key[NETCODE_PUBLIC_KEY_BYTES];

#define check( condition )                                                                                      \
do                                                                                                              \
{                                                                                                               \
    if ( !(condition) )                                                                                         \
    {                                                                                                           \
        check_handler( #condition, (NETCODE_CONST char*) __FUNCTION__, (char*) __FILE__, __LINE__ );            \
    }                                                                                                           \
} while(0)

static void test_crypto_aead_vectors()
{
    // Known-answer test for the two AEAD primitives netcode relies on, exercising
    // whichever implementation the running CPU selects (reference / SSSE3 / AVX2 for
    // ChaCha20, donna / SSE2 for Poly1305). Expected ciphertext was generated from
    // libsodium reference output and is unchanged across 1.0.20 -> 1.0.22. Do not
    // edit these arrays by hand: a golden failure here means the vendored crypto no
    // longer agrees with upstream, which would break every other netcode
    // implementation on the wire.
    //
    // Declared static on purpose. yojimbo vendors this file and compiles it with
    // NETCODE_ENABLE_TESTS=1 while defining its own test_crypto_aead_vectors in
    // test.cpp; internal linkage keeps the two from colliding.

    static const uint8_t kat_key[32] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
        0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
        0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
    };
    static const uint8_t kat_ad[12] = {
        0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,
    };
    static const uint8_t kat_msg[58] = {
        0x79,0x6f,0x6a,0x69,0x6d,0x62,0x6f,0x20,0x76,0x65,0x6e,0x64,0x6f,0x72,0x65,0x64,0x20,0x6c,0x69,0x62,
        0x73,0x6f,0x64,0x69,0x75,0x6d,0x20,0x41,0x45,0x41,0x44,0x20,0x6b,0x6e,0x6f,0x77,0x6e,0x2d,0x61,0x6e,
        0x73,0x77,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,0x76,0x65,0x63,0x74,0x6f,0x72,0x21,0x21,
    };
    static const uint8_t kat_npub_ietf[12] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,
    };
    static const uint8_t kat_ct_ietf[74] = {
        0xd5,0xae,0xb1,0x85,0x15,0x8b,0x07,0xb3,0x01,0x15,0xf0,0x59,
        0xb4,0x4e,0x9d,0x45,0x91,0x58,0xab,0xff,0xaf,0xbd,0x81,0x4f,
        0xbf,0x52,0xc2,0x4c,0xa1,0x5e,0x60,0x5f,0x58,0x63,0x31,0x96,
        0xda,0x90,0x07,0x63,0xb9,0x0c,0x21,0x46,0xf2,0xe4,0x65,0x96,
        0x7a,0x81,0x7f,0xa2,0x5d,0xd1,0x79,0xf6,0x9b,0x18,0x5d,0xe0,
        0xb6,0x57,0x93,0xbe,0x8c,0xb5,0xa9,0x75,0x98,0xa4,0x6f,0xd5,
        0xbe,0x9d,
    };
    static const uint8_t kat_npub_xchacha[24] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
        0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    };
    static const uint8_t kat_ct_xchacha[74] = {
        0x2b,0x24,0x83,0x2a,0x6c,0x9e,0x21,0x02,0x2a,0x14,0x32,0x56,
        0x4b,0x27,0x37,0x92,0x24,0x40,0xa9,0x92,0xd3,0x53,0xa7,0xa5,
        0x64,0xd3,0x8e,0x0c,0x75,0x79,0x75,0x3f,0xca,0x82,0xfa,0x85,
        0xf0,0xa6,0xac,0x08,0x9a,0x25,0xf1,0x8f,0x42,0x20,0x70,0x8e,
        0x38,0x25,0xd1,0x08,0x45,0x81,0x75,0x18,0xe4,0xd1,0x88,0xbd,
        0x92,0xfa,0x84,0xdc,0xd6,0xa3,0x9a,0x67,0x52,0x91,0x62,0xf4,
        0x86,0x7b,
    };

    uint8_t c[128];
    uint8_t m[128];
    unsigned long long clen = 0;
    unsigned long long mlen = 0;

    // ChaCha20-Poly1305 (IETF) -- the construction netcode uses on the wire

    check( crypto_aead_chacha20poly1305_ietf_encrypt( c, &clen, kat_msg, sizeof( kat_msg ), kat_ad, sizeof( kat_ad ), NULL, kat_npub_ietf, kat_key ) == 0 );
    check( clen == sizeof( kat_ct_ietf ) );
    check( memcmp( c, kat_ct_ietf, (size_t) clen ) == 0 );
    check( crypto_aead_chacha20poly1305_ietf_decrypt( m, &mlen, NULL, c, clen, kat_ad, sizeof( kat_ad ), kat_npub_ietf, kat_key ) == 0 );
    check( mlen == sizeof( kat_msg ) );
    check( memcmp( m, kat_msg, (size_t) mlen ) == 0 );

    // a tampered tag must be rejected. this is the path ACQUIRE_FENCE guards: the
    // plaintext must not be produced before authentication has completed.

    c[0] ^= 0x01;
    check( crypto_aead_chacha20poly1305_ietf_decrypt( m, &mlen, NULL, c, clen, kat_ad, sizeof( kat_ad ), kat_npub_ietf, kat_key ) != 0 );

    // XChaCha20-Poly1305

    check( crypto_aead_xchacha20poly1305_ietf_encrypt( c, &clen, kat_msg, sizeof( kat_msg ), kat_ad, sizeof( kat_ad ), NULL, kat_npub_xchacha, kat_key ) == 0 );
    check( clen == sizeof( kat_ct_xchacha ) );
    check( memcmp( c, kat_ct_xchacha, (size_t) clen ) == 0 );
    check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, &mlen, NULL, c, clen, kat_ad, sizeof( kat_ad ), kat_npub_xchacha, kat_key ) == 0 );
    check( mlen == sizeof( kat_msg ) );
    check( memcmp( m, kat_msg, (size_t) mlen ) == 0 );
    c[0] ^= 0x01;
    check( crypto_aead_xchacha20poly1305_ietf_decrypt( m, &mlen, NULL, c, clen, kat_ad, sizeof( kat_ad ), kat_npub_xchacha, kat_key ) != 0 );

    // the constant-time comparison that checks the Poly1305 tag. libsodium 1.0.21
    // hardened crypto_verify_n against the compiler optimising it into something
    // branchy; these assertions pin its contract.

    uint8_t a[64], b[64];
    int i;
    for ( i = 0; i < 64; i++ ) { a[i] = (uint8_t) i; b[i] = (uint8_t) i; }
    check( crypto_verify_16( a, b ) == 0 );
    check( crypto_verify_32( a, b ) == 0 );
    check( crypto_verify_64( a, b ) == 0 );
    for ( i = 0; i < 8; i++ )
    {
        b[0] = (uint8_t) ( a[0] ^ ( 1u << i ) );
        check( crypto_verify_16( a, b ) == -1 );
        check( crypto_verify_32( a, b ) == -1 );
        check( crypto_verify_64( a, b ) == -1 );
    }
    b[0] = a[0];
    b[63] = (uint8_t) ( a[63] ^ 0x80 );
    check( crypto_verify_64( a, b ) == -1 );
}

static void test_queue()
{
    struct netcode_packet_queue_t queue;

    netcode_packet_queue_init( &queue, NULL, NULL, NULL );

    check( queue.num_packets == 0 );
    check( queue.start_index == 0 );

    // attempting to pop a packet off an empty queue should return NULL

    check( netcode_packet_queue_pop( &queue, NULL ) == NULL );

    // add some packets to the queue and make sure they pop off in the correct order
    {
        #define NUM_PACKETS 100

        void * packets[NUM_PACKETS];

        int i;
        for ( i = 0; i < NUM_PACKETS; i++ )
        {
            packets[i] = malloc( (i+1) * 256 );
            check( netcode_packet_queue_push( &queue, packets[i], (uint64_t) i ) == 1 );
        }

        check( queue.num_packets == NUM_PACKETS );

        for ( i = 0; i < NUM_PACKETS; i++ )
        {
            uint64_t sequence = 0;
            void * packet = netcode_packet_queue_pop( &queue, &sequence );
            check( sequence == (uint64_t) i ) ;
            check( packet == packets[i] );
            free( packet );
        }
    }

    // after all entries are popped off, the queue is empty, so calls to pop should return NULL

    check( queue.num_packets == 0 );

    check( netcode_packet_queue_pop( &queue, NULL ) == NULL );

    // test that the packet queue can be filled to max capacity

    void * packets[NETCODE_PACKET_QUEUE_SIZE];

    int i;
    for ( i = 0; i < NETCODE_PACKET_QUEUE_SIZE; i++ )
    {
        packets[i] = malloc( i * 256 );
        check( netcode_packet_queue_push( &queue, packets[i], (uint64_t) i ) == 1 );
    }

    check( queue.num_packets == NETCODE_PACKET_QUEUE_SIZE );

    // when the queue is full, attempting to push a packet should fail and return 0

    check( netcode_packet_queue_push( &queue, malloc( 100 ), 0 ) == 0 );

    // make sure all packets pop off in the correct order

    for ( i = 0; i < NETCODE_PACKET_QUEUE_SIZE; i++ )
    {
        uint64_t sequence = 0;
        void * packet = netcode_packet_queue_pop( &queue, &sequence );
        check( sequence == (uint64_t) i );
        check( packet == packets[i] );
        free( packet );
    }

    // add some packets again

    for ( i = 0; i < NETCODE_PACKET_QUEUE_SIZE; i++ )
    {
        packets[i] = malloc( i * 256 );
        check( netcode_packet_queue_push( &queue, packets[i], (uint64_t) i ) == 1 );
    }

    // clear the queue and make sure that all packets are freed

    netcode_packet_queue_clear( &queue );

    check( queue.start_index == 0 );
    check( queue.num_packets == 0 );
    for ( i = 0; i < NETCODE_PACKET_QUEUE_SIZE; i++ )
        check( queue.packet_data[i] == NULL );
}

static void test_endian()
{
    uint32_t value = 0x11223344;

    char * bytes = (char*) &value;

#if NETCODE_LITTLE_ENDIAN

    check( bytes[0] == 0x44 );
    check( bytes[1] == 0x33 );
    check( bytes[2] == 0x22 );
    check( bytes[3] == 0x11 );

#else // #if NETCODE_LITTLE_ENDIAN

    check( bytes[3] == 0x44 );
    check( bytes[2] == 0x33 );
    check( bytes[1] == 0x22 );
    check( bytes[0] == 0x11 );

#endif // #if NETCODE_LITTLE_ENDIAN
}

static void test_sequence()
{
    check( netcode_sequence_number_bytes_required( 0 ) == 1 );
    check( netcode_sequence_number_bytes_required( 0x11 ) == 1 );
    check( netcode_sequence_number_bytes_required( 0x1122 ) == 2 );
    check( netcode_sequence_number_bytes_required( 0x112233 ) == 3 );
    check( netcode_sequence_number_bytes_required( 0x11223344 ) == 4 );
    check( netcode_sequence_number_bytes_required( 0x1122334455 ) == 5 );
    check( netcode_sequence_number_bytes_required( 0x112233445566 ) == 6 );
    check( netcode_sequence_number_bytes_required( 0x11223344556677 ) == 7 );
    check( netcode_sequence_number_bytes_required( 0x1122334455667788 ) == 8 );
}

static void test_address()
{
    {
        struct netcode_address_t address;
        check( netcode_parse_address( "", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[]", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[]:", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( ":", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "12", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "123", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1234", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1234.0.12313.0000", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1234.0.12313.0000.0.0.0.0.0", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( ".", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "..", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "...", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "....", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( ".....", &address ) == NETCODE_ERROR );
    }

    // ports must be all digits in [0,65535]. out of range and non-numeric ports must not silently truncate

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "127.0.0.1:65535", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 65535 );
        check( netcode_parse_address( "[::1]:65535", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 65535 );
        check( netcode_parse_address( "127.0.0.1:65536", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "127.0.0.1:99999", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "127.0.0.1:", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "127.0.0.1:40k", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[::1]:65536", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[::1]:", &address ) == NETCODE_ERROR );
        check( netcode_parse_address( "[::1]:40k", &address ) == NETCODE_ERROR );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "107.77.207.77", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 0 );
        check( address.data.ipv4[0] == 107 );
        check( address.data.ipv4[1] == 77 );
        check( address.data.ipv4[2] == 207 );
        check( address.data.ipv4[3] == 77 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "127.0.0.1", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 0 );
        check( address.data.ipv4[0] == 127 );
        check( address.data.ipv4[1] == 0 );
        check( address.data.ipv4[2] == 0 );
        check( address.data.ipv4[3] == 1 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "107.77.207.77:40000", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 40000 );
        check( address.data.ipv4[0] == 107 );
        check( address.data.ipv4[1] == 77 );
        check( address.data.ipv4[2] == 207 );
        check( address.data.ipv4[3] == 77 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "127.0.0.1:40000", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 40000 );
        check( address.data.ipv4[0] == 127 );
        check( address.data.ipv4[1] == 0 );
        check( address.data.ipv4[2] == 0 );
        check( address.data.ipv4[3] == 1 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "fe80::202:b3ff:fe1e:8329", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.data.ipv6[0] == 0xfe80 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0202 );
        check( address.data.ipv6[5] == 0xb3ff );
        check( address.data.ipv6[6] == 0xfe1e );
        check( address.data.ipv6[7] == 0x8329 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "::", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.data.ipv6[0] == 0x0000 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "::1", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.data.ipv6[0] == 0x0000 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "::0", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.data.ipv6[0] == 0x0000 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[::1]", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.data.ipv6[0] == 0x0000 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[::0]", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.data.ipv6[0] == 0x0000 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[fe80::1]", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.data.ipv6[0] == 0xfe80 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[fe80::202:b3ff:fe1e:8329]:40000", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 40000 );
        check( address.data.ipv6[0] == 0xfe80 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0202 );
        check( address.data.ipv6[5] == 0xb3ff );
        check( address.data.ipv6[6] == 0xfe1e );
        check( address.data.ipv6[7] == 0x8329 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[::]:40000", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 40000 );
        check( address.data.ipv6[0] == 0x0000 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[::1]:5", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 5 );
        check( address.data.ipv6[0] == 0x0000 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[fe80::1]:5", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 5 );
        check( address.data.ipv6[0] == 0xfe80 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[::1]:40000", &address ) == NETCODE_OK );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 40000 );
        check( address.data.ipv6[0] == 0x0000 );
        check( address.data.ipv6[1] == 0x0000 );
        check( address.data.ipv6[2] == 0x0000 );
        check( address.data.ipv6[3] == 0x0000 );
        check( address.data.ipv6[4] == 0x0000 );
        check( address.data.ipv6[5] == 0x0000 );
        check( address.data.ipv6[6] == 0x0000 );
        check( address.data.ipv6[7] == 0x0001 );
    }
}

#define TEST_PROTOCOL_ID            0x1122334455667788ULL
#define TEST_CLIENT_ID              0x1ULL
#define TEST_SERVER_PORT            40000
#define TEST_CONNECT_TOKEN_EXPIRY   30
#define TEST_TIMEOUT_SECONDS        15










void test_connection_keep_alive_packet()
{
    // setup a connection keep alive packet

    struct netcode_connection_keep_alive_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
    input_packet.client_index = 10;
    input_packet.max_clients = 16;

    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key( packet_key );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );
    
    struct netcode_connection_keep_alive_packet_t * output_packet = (struct netcode_connection_keep_alive_packet_t*) 
        netcode_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, allowed_packet_types, NULL, NULL, NULL );

    check( output_packet );

    // make sure the read packet matches what was written
    
    check( output_packet->packet_type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET );
    check( output_packet->client_index == input_packet.client_index );
    check( output_packet->max_clients == input_packet.max_clients );

    free( output_packet );
}

void test_connection_payload_packet()
{
    // setup a connection payload packet

    struct netcode_connection_payload_packet_t * input_packet = netcode_create_payload_packet( NETCODE_MAX_PAYLOAD_BYTES, NULL, NULL );

    check( input_packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
    check( input_packet->payload_bytes == NETCODE_MAX_PAYLOAD_BYTES );

    netcode_random_bytes( input_packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES );
    
    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key( packet_key );

    int bytes_written = netcode_write_packet( input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    struct netcode_connection_payload_packet_t * output_packet = (struct netcode_connection_payload_packet_t*) 
        netcode_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, allowed_packet_types, NULL, NULL, NULL );

    check( output_packet );

    // make sure the read packet matches what was written
    
    check( output_packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
    check( output_packet->payload_bytes == input_packet->payload_bytes );
    check( memcmp( output_packet->payload_data, input_packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES ) == 0 );

    free( input_packet );
    free( output_packet );
}

void test_connection_disconnect_packet()
{
    // setup a connection disconnect packet

    struct netcode_connection_disconnect_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key( packet_key );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, packet_key, TEST_PROTOCOL_ID );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    struct netcode_connection_disconnect_packet_t * output_packet = (struct netcode_connection_disconnect_packet_t*) 
        netcode_read_packet( buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, allowed_packet_types, NULL, NULL, NULL );

    check( output_packet );

    // make sure the read packet matches what was written
    
    check( output_packet->packet_type == NETCODE_CONNECTION_DISCONNECT_PACKET );

    free( output_packet );
}


void test_encryption_manager()
{
    struct netcode_encryption_manager_t encryption_manager;

    netcode_encryption_manager_reset( &encryption_manager );

    double time = 100.0;

    // generate some test encryption mappings

    struct encryption_mapping_t
    {
        struct netcode_address_t address;
        uint8_t send_key[NETCODE_KEY_BYTES];
        uint8_t receive_key[NETCODE_KEY_BYTES];
    };

    #define NUM_ENCRYPTION_MAPPINGS 5

    struct encryption_mapping_t encryption_mapping[NUM_ENCRYPTION_MAPPINGS];
    memset( encryption_mapping, 0, sizeof( encryption_mapping ) );
    int i;
    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        encryption_mapping[i].address.type = NETCODE_ADDRESS_IPV6;
        encryption_mapping[i].address.data.ipv6[7] = 1;
        encryption_mapping[i].address.port = ( uint16_t) ( 20000 + i );
        netcode_generate_key( encryption_mapping[i].send_key );
        netcode_generate_key( encryption_mapping[i].receive_key );
    }

    // add the encryption mappings to the manager and make sure they can be looked up by address

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        check( encryption_index == -1 );

        check( netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index ) == NULL );
        check( netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index ) == NULL );

        check( netcode_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                                  &encryption_mapping[i].address, 
                                                                  encryption_mapping[i].send_key, 
                                                                  encryption_mapping[i].receive_key, 
                                                                  time, 
                                                                  -1.0,
                                                                  TEST_TIMEOUT_SECONDS ) );

        encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check( send_key );
        check( receive_key );

        check( memcmp( send_key, encryption_mapping[i].send_key, NETCODE_KEY_BYTES ) == 0 );
        check( memcmp( receive_key, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES ) == 0 );
    }

    // removing an encryption mapping that doesn't exist should return 0
    {
        struct netcode_address_t address;
        address.type = NETCODE_ADDRESS_IPV6;
        address.data.ipv6[7] = 1;
        address.port = 50000;

        check( netcode_encryption_manager_remove_encryption_mapping( &encryption_manager, &address, time ) == 0 );
    }

    // remove the first and last encryption mappings

    check( netcode_encryption_manager_remove_encryption_mapping( &encryption_manager, &encryption_mapping[0].address, time ) == 1 );

    check( netcode_encryption_manager_remove_encryption_mapping( &encryption_manager, &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address, time ) == 1 );

    // make sure the encryption mappings that were removed can no longer be looked up by address

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        if ( i != 0 && i != NUM_ENCRYPTION_MAPPINGS - 1 )
        {
            check( send_key );
            check( receive_key );

            check( memcmp( send_key, encryption_mapping[i].send_key, NETCODE_KEY_BYTES ) == 0 );
            check( memcmp( receive_key, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES ) == 0 );
        }
        else
        {
            check( !send_key );
            check( !receive_key );
        }
    }

    // add the encryption mappings back in
    
    check( netcode_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                              &encryption_mapping[0].address, 
                                                              encryption_mapping[0].send_key, 
                                                              encryption_mapping[0].receive_key, 
                                                              time, 
                                                              -1.0,
                                                              TEST_TIMEOUT_SECONDS ) );
    
    check( netcode_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                              &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address, 
                                                              encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].send_key, 
                                                              encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].receive_key, 
                                                              time, 
                                                              -1.0,
                                                              TEST_TIMEOUT_SECONDS ) );

    // all encryption mappings should be able to be looked up by address again

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check( send_key );
        check( receive_key );

        check( memcmp( send_key, encryption_mapping[i].send_key, NETCODE_KEY_BYTES ) == 0 );
        check( memcmp( receive_key, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES ) == 0 );
    }

    // check that encryption mappings time out properly

    time += TEST_TIMEOUT_SECONDS * 2;

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check( !send_key );
        check( !receive_key );
    }

    // add the same encryption mappings after timeout

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        check( encryption_index == -1 );

        check( netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index ) == NULL );
        check( netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index ) == NULL );

        check( netcode_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                                  &encryption_mapping[i].address, 
                                                                  encryption_mapping[i].send_key, 
                                                                  encryption_mapping[i].receive_key, 
                                                                  time, 
                                                                  -1.0,
                                                                  TEST_TIMEOUT_SECONDS ) );

        encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check( send_key );
        check( receive_key );

        check( memcmp( send_key, encryption_mapping[i].send_key, NETCODE_KEY_BYTES ) == 0 );
        check( memcmp( receive_key, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES ) == 0 );
    }

    // reset the encryption mapping and verify that all encryption mappings have been removed

    netcode_encryption_manager_reset( &encryption_manager );

    for ( i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++ )
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[i].address, time );

        uint8_t * send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check( !send_key );
        check( !receive_key );
    }

    // test the expire time for encryption mapping works as expected

    check( netcode_encryption_manager_add_encryption_mapping( &encryption_manager, 
                                                              &encryption_mapping[0].address, 
                                                              encryption_mapping[0].send_key, 
                                                              encryption_mapping[0].receive_key, 
                                                              time, 
                                                              time + 1.0,
                                                              TEST_TIMEOUT_SECONDS ) );

    int encryption_index = netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[0].address, time );

    check( encryption_index != -1 );

    check( netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[0].address, time + 1.1f ) == -1 );

    netcode_encryption_manager_set_expire_time( &encryption_manager, encryption_index, -1.0 );

    check( netcode_encryption_manager_find_encryption_mapping( &encryption_manager, &encryption_mapping[0].address, time ) == encryption_index );
}

void test_replay_protection()
{
    struct netcode_replay_protection_t replay_protection;

    int i;
    for ( i = 0; i < 2; i++ )
    {
        netcode_replay_protection_reset( &replay_protection );

        check( replay_protection.most_recent_sequence == 0 );

        // the first time we receive packets, they should not be already received

        #define MAX_SEQUENCE ( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE * 4 )

        uint64_t sequence;
        for ( sequence = 0; sequence < MAX_SEQUENCE; ++sequence )
        {
            check( netcode_replay_protection_already_received( &replay_protection, sequence ) == 0 );
            netcode_replay_protection_advance_sequence( &replay_protection, sequence );
        }

        // old packets outside buffer should be considered already received

        check( netcode_replay_protection_already_received( &replay_protection, 0 ) == 1 );

        // packets received a second time should be flagged already received

        for ( sequence = MAX_SEQUENCE - 10; sequence < MAX_SEQUENCE; ++sequence )
        {
            check( netcode_replay_protection_already_received( &replay_protection, sequence ) == 1 );
        }

        // jumping ahead to a much higher sequence should be considered not already received

        check( netcode_replay_protection_already_received( &replay_protection, MAX_SEQUENCE + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE ) == 0 );

        // old packets should be considered already received

        for ( sequence = 0; sequence < MAX_SEQUENCE; ++sequence )
        {
            check( netcode_replay_protection_already_received( &replay_protection, sequence ) == 1 );
        }
    }

    // sequence numbers near UINT64_MAX must not be falsely rejected as replays.
    // "sequence + buffer size" overflowed in the already received check and treated
    // the top of the sequence space as ancient packets. found by fuzz_read_packet.

    netcode_replay_protection_reset( &replay_protection );

    check( netcode_replay_protection_already_received( &replay_protection, UINT64_MAX - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE ) == 0 );
    netcode_replay_protection_advance_sequence( &replay_protection, UINT64_MAX - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE );

    check( netcode_replay_protection_already_received( &replay_protection, UINT64_MAX - 1 ) == 0 );
    netcode_replay_protection_advance_sequence( &replay_protection, UINT64_MAX - 1 );

    // and a replayed packet up there is still caught

    check( netcode_replay_protection_already_received( &replay_protection, UINT64_MAX - 1 ) == 1 );

    // while packets that fell out of the window are rejected as before

    check( netcode_replay_protection_already_received( &replay_protection, UINT64_MAX - 1 - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE ) == 1 );
}

static int num_ignored_asserts = 0;

static void test_runtime_guards_assert_handler( NETCODE_CONST char * condition, NETCODE_CONST char * function, NETCODE_CONST char * file, int line )
{
    (void) condition;
    (void) function;
    (void) file;
    (void) line;
    num_ignored_asserts++;
}

void test_runtime_guards()
{
    // out of range arguments to public entry points must not crash or corrupt memory in
    // release builds, where asserts compile out. install an assert handler that continues
    // instead of aborting so this test also runs in debug builds.

    netcode_set_assert_function( test_runtime_guards_assert_handler );

    // no private key needed: nothing in this test decrypts anything

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;

    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

    check( server );

    // starting with an out of range number of clients must not start the server

    netcode_server_start( server, 0 );
    check( !netcode_server_running( server ) );

    netcode_server_start( server, -1 );
    check( !netcode_server_running( server ) );

    netcode_server_start( server, NETCODE_MAX_CLIENTS + 1 );
    check( !netcode_server_running( server ) );

    netcode_server_start( server, 1 );
    check( netcode_server_running( server ) );
    check( netcode_server_max_clients( server ) == 1 );

    // out of range client indices must return cleanly. max clients is 1, so 1 is out of range

    check( netcode_server_client_user_data( server, -1 ) == NULL );
    check( netcode_server_client_user_data( server, 1 ) == NULL );
    check( netcode_server_client_user_data( server, NETCODE_MAX_CLIENTS ) == NULL );

    check( netcode_server_next_packet_sequence( server, -1 ) == 0 );
    check( netcode_server_next_packet_sequence( server, 1 ) == 0 );

    check( netcode_server_client_loopback( server, -1 ) == 0 );
    check( netcode_server_client_loopback( server, 1 ) == 0 );

    int packet_bytes = 0;
    uint64_t packet_sequence = 0;
    check( netcode_server_receive_packet( server, -1, &packet_bytes, &packet_sequence ) == NULL );
    check( netcode_server_receive_packet( server, 1, &packet_bytes, &packet_sequence ) == NULL );

    uint8_t payload[NETCODE_MAX_PACKET_SIZE];
    memset( payload, 0, sizeof( payload ) );

    netcode_server_send_packet( server, -1, payload, NETCODE_MAX_PACKET_SIZE );
    netcode_server_send_packet( server, 1, payload, NETCODE_MAX_PACKET_SIZE );

    netcode_server_disconnect_client( server, -1 );
    netcode_server_disconnect_client( server, 1 );

    netcode_server_connect_loopback_client( server, -1, 1, NULL );
    netcode_server_connect_loopback_client( server, 1, 1, NULL );

    netcode_server_disconnect_loopback_client( server, -1 );
    netcode_server_disconnect_loopback_client( server, 1 );

    netcode_server_process_loopback_packet( server, -1, payload, NETCODE_MAX_PACKET_SIZE, 0 );
    netcode_server_process_loopback_packet( server, 1, payload, NETCODE_MAX_PACKET_SIZE, 0 );

    // none of the above may have connected anybody or torn anything down

    check( netcode_server_running( server ) );
    check( netcode_server_num_connected_clients( server ) == 0 );

    netcode_server_destroy( server );

    netcode_set_assert_function( netcode_default_assert_handler );
}

void test_init_and_defaults()
{
    // netcode_init is reference counted, so multiple subsystems in the same
    // application can call netcode_init and netcode_term independently.
    // the test runner has already called netcode_init once.

    check( netcode.initialized == 1 );
    check( netcode_init() == NETCODE_OK );
    check( netcode.initialized == 2 );
    netcode_term();
    check( netcode.initialized == 1 );

    // a zeroed config must give working defaults instead of crashing on a NULL allocator

    {
        struct netcode_client_config_t client_config;
        memset( &client_config, 0, sizeof( client_config ) );

        // port 0 asks the OS for an ephemeral port. This test only checks that a zeroed
        // config yields working defaults -- it never connects -- so a fixed port buys
        // nothing and makes the test fail whenever anything else on the machine happens
        // to hold that port. Observed on a windows CI runner, 2026-07-26.
        struct netcode_client_t * client = netcode_client_create( "127.0.0.1:0", &client_config, 0.0 );

        check( client );

        netcode_client_destroy( client );
    }

    {
        struct netcode_server_config_t server_config;
        memset( &server_config, 0, sizeof( server_config ) );

        // a zeroed config has no key, and a server without a valid key is refused

        check( netcode_server_create( "127.0.0.1:0", &server_config, 0.0 ) == NULL );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_INVALID_PRIVATE_KEY );

        memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

        // ephemeral here too, and for the same reason: nothing connects to this server.
        struct netcode_server_t * server = netcode_server_create( "127.0.0.1:0", &server_config, 0.0 );

        check( server );

        netcode_server_destroy( server );
    }
}

static void * test_failing_allocate_function( void * context, size_t bytes )
{
    (void) context;
    (void) bytes;
    return NULL;
}

static int test_simulator_allocations_fail = 0;

static void * test_toggle_allocate_function( void * context, size_t bytes )
{
    (void) context;
    if ( test_simulator_allocations_fail )
        return NULL;
    return malloc( bytes );
}

static void test_toggle_free_function( void * context, void * pointer )
{
    (void) context;
    free( pointer );
}

static void test_override_send_packet( void * context, struct netcode_address_t * to, NETCODE_CONST uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    (void) to;
    (void) packet_data;
    (void) packet_bytes;
}

static int test_override_receive_packet( void * context, struct netcode_address_t * from, uint8_t * packet_data, int max_packet_bytes )
{
    (void) context;
    (void) from;
    (void) packet_data;
    (void) max_packet_bytes;
    return 0;
}

void test_client_create_error()
{
    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

    // successful create leaves the create error as NONE

    {
        struct netcode_client_t * client = netcode_client_create( "0.0.0.0:50000", &client_config, 0.0 );

        check( client );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_NONE );

        netcode_client_destroy( client );
    }

    // bad first address

    check( netcode_client_create( "not an address", &client_config, 0.0 ) == NULL );
    check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED );

    // bad second address

    check( netcode_client_create_dual( "0.0.0.0:50000", "not an address", &client_config, 0.0 ) == NULL );
    check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED );

    // the network simulator requires binding to a specific port

    {
        struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

        struct netcode_client_config_t simulator_config;
        netcode_default_client_config( &simulator_config );
    simulator_config.protocol_id = TEST_PROTOCOL_ID;
    simulator_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
        simulator_config.network_simulator = network_simulator;

        check( netcode_client_create( "0.0.0.0", &simulator_config, 0.0 ) == NULL );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT );

        netcode_network_simulator_destroy( network_simulator );
    }

    // binding a second client to a port already in use fails at socket creation (ipv4)

    {
        struct netcode_client_t * first_client = netcode_client_create( "127.0.0.1:50000", &client_config, 0.0 );

        check( first_client );

        check( netcode_client_create( "127.0.0.1:50000", &client_config, 0.0 ) == NULL );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED );

        netcode_client_destroy( first_client );
    }

    // and the same over ipv6 reports the ipv6 error

    {
        struct netcode_client_t * first_client = netcode_client_create( "[::1]:50000", &client_config, 0.0 );

        check( first_client );

        check( netcode_client_create( "[::1]:50000", &client_config, 0.0 ) == NULL );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED );

        netcode_client_destroy( first_client );
    }

    // client struct allocation failure

    {
        struct netcode_client_config_t failing_config;
        netcode_default_client_config( &failing_config );
    failing_config.protocol_id = TEST_PROTOCOL_ID;
    failing_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
        failing_config.allocate_function = test_failing_allocate_function;

        check( netcode_client_create( "0.0.0.0:50000", &failing_config, 0.0 ) == NULL );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED );
    }

    // override_send_and_receive with either override callback missing is refused at create time,
    // rather than calling a null pointer on the first update

    {
        struct netcode_client_config_t override_config;
        netcode_default_client_config( &override_config );
    override_config.protocol_id = TEST_PROTOCOL_ID;
    override_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
        override_config.override_send_and_receive = 1;
        override_config.send_packet_override = test_override_send_packet;

        check( netcode_client_create( "0.0.0.0:50000", &override_config, 0.0 ) == NULL );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );

        override_config.send_packet_override = NULL;
        override_config.receive_packet_override = test_override_receive_packet;

        check( netcode_client_create( "0.0.0.0:50000", &override_config, 0.0 ) == NULL );
        check( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );
    }
}

void test_server_create_error()
{
    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

    // successful create leaves the create error as NONE

    {
        struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

        check( server );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_NONE );

        netcode_server_destroy( server );
    }

    // bad first address

    check( netcode_server_create( "not an address", &server_config, 0.0 ) == NULL );
    check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED );

    // bad second address

    check( netcode_server_create_dual( "127.0.0.1:40000", "not an address", &server_config, 0.0 ) == NULL );
    check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED );

    // a port already in use is reported as a bind failure, distinct from other socket errors (ipv4)

    {
        struct netcode_server_t * first_server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

        check( first_server );

        check( netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 ) == NULL );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED );

        netcode_server_destroy( first_server );
    }

    // and the same over ipv6 reports the ipv6 bind error

    {
        struct netcode_server_t * first_server = netcode_server_create( "[::1]:40000", &server_config, 0.0 );

        check( first_server );

        check( netcode_server_create( "[::1]:40000", &server_config, 0.0 ) == NULL );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED );

        netcode_server_destroy( first_server );
    }

    // server struct allocation failure

    {
        struct netcode_server_config_t failing_config;
        netcode_default_server_config( &failing_config );
    failing_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &failing_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
        failing_config.allocate_function = test_failing_allocate_function;

        check( netcode_server_create( "127.0.0.1:40000", &failing_config, 0.0 ) == NULL );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED );
    }

    // override_send_and_receive with either override callback missing is refused at create time,
    // rather than calling a null pointer on the first update

    {
        struct netcode_server_config_t override_config;
        netcode_default_server_config( &override_config );
    override_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &override_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
        override_config.override_send_and_receive = 1;
        override_config.send_packet_override = test_override_send_packet;

        check( netcode_server_create( "127.0.0.1:40000", &override_config, 0.0 ) == NULL );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );

        override_config.send_packet_override = NULL;
        override_config.receive_packet_override = test_override_receive_packet;

        check( netcode_server_create( "127.0.0.1:40000", &override_config, 0.0 ) == NULL );
        check( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );
    }
}

void test_network_simulator_allocation_failure()
{
    // a failed allocation in the simulator must drop the packet, not memcpy into null

    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, test_toggle_allocate_function, test_toggle_free_function );

    check( network_simulator );

    struct netcode_address_t from;
    struct netcode_address_t to;

    check( netcode_parse_address( "127.0.0.1:50000", &from ) == NETCODE_OK );
    check( netcode_parse_address( "127.0.0.1:50001", &to ) == NETCODE_OK );

    uint8_t packet_data[256];
    int i;
    for ( i = 0; i < 256; i++ )
    {
        packet_data[i] = (uint8_t) i;
    }

    test_simulator_allocations_fail = 1;

    netcode_network_simulator_send_packet( network_simulator, &from, &to, packet_data, sizeof( packet_data ) );

    test_simulator_allocations_fail = 0;

    netcode_network_simulator_update( network_simulator, 0.0 );

    uint8_t * receive_packet_data[16];
    int receive_packet_bytes[16];
    struct netcode_address_t receive_from[16];

    check( netcode_network_simulator_receive_packets( network_simulator, &to, 16, receive_packet_data, receive_packet_bytes, receive_from ) == 0 );

    // and the simulator still works once the allocator recovers

    netcode_network_simulator_send_packet( network_simulator, &from, &to, packet_data, sizeof( packet_data ) );

    netcode_network_simulator_update( network_simulator, 0.0 );

    check( netcode_network_simulator_receive_packets( network_simulator, &to, 16, receive_packet_data, receive_packet_bytes, receive_from ) == 1 );

    // a received packet buffer belongs to the caller, so free it before the simulator goes

    test_toggle_free_function( NULL, receive_packet_data[0] );

    netcode_network_simulator_destroy( network_simulator );
}

void test_network_simulator_determinism()
{
    // the network simulator has its own seeded rng, so two simulators given
    // identical inputs must drop, delay and duplicate identically

    #define DETERMINISM_NUM_PACKETS 100
    #define DETERMINISM_MAX_RECEIVE 256

    struct netcode_network_simulator_t * simulator_a = netcode_network_simulator_create( NULL, NULL, NULL );
    struct netcode_network_simulator_t * simulator_b = netcode_network_simulator_create( NULL, NULL, NULL );

    check( simulator_a );
    check( simulator_b );

    simulator_a->latency_milliseconds = 100.0f;
    simulator_a->jitter_milliseconds = 50.0f;
    simulator_a->packet_loss_percent = 25.0f;
    simulator_a->duplicate_packet_percent = 25.0f;

    simulator_b->latency_milliseconds = 100.0f;
    simulator_b->jitter_milliseconds = 50.0f;
    simulator_b->packet_loss_percent = 25.0f;
    simulator_b->duplicate_packet_percent = 25.0f;

    struct netcode_address_t from;
    struct netcode_address_t to;
    check( netcode_parse_address( "127.0.0.1:40000", &from ) == NETCODE_OK );
    check( netcode_parse_address( "127.0.0.1:50000", &to ) == NETCODE_OK );

    int i, j;
    uint8_t packet_data[256];
    for ( i = 0; i < DETERMINISM_NUM_PACKETS; i++ )
    {
        for ( j = 0; j < (int) sizeof( packet_data ); j++ )
        {
            packet_data[j] = (uint8_t) ( i + j );
        }
        netcode_network_simulator_send_packet( simulator_a, &from, &to, packet_data, sizeof( packet_data ) );
        netcode_network_simulator_send_packet( simulator_b, &from, &to, packet_data, sizeof( packet_data ) );
    }

    int total_received = 0;

    double time;
    for ( time = 0.0; time < 2.0; time += 0.01 )
    {
        netcode_network_simulator_update( simulator_a, time );
        netcode_network_simulator_update( simulator_b, time );

        uint8_t * packet_data_a[DETERMINISM_MAX_RECEIVE];
        uint8_t * packet_data_b[DETERMINISM_MAX_RECEIVE];
        int packet_bytes_a[DETERMINISM_MAX_RECEIVE];
        int packet_bytes_b[DETERMINISM_MAX_RECEIVE];
        struct netcode_address_t from_a[DETERMINISM_MAX_RECEIVE];
        struct netcode_address_t from_b[DETERMINISM_MAX_RECEIVE];

        int num_packets_a = netcode_network_simulator_receive_packets( simulator_a, &to, DETERMINISM_MAX_RECEIVE, packet_data_a, packet_bytes_a, from_a );
        int num_packets_b = netcode_network_simulator_receive_packets( simulator_b, &to, DETERMINISM_MAX_RECEIVE, packet_data_b, packet_bytes_b, from_b );

        check( num_packets_a == num_packets_b );

        for ( i = 0; i < num_packets_a; i++ )
        {
            check( packet_bytes_a[i] == packet_bytes_b[i] );
            check( memcmp( packet_data_a[i], packet_data_b[i], packet_bytes_a[i] ) == 0 );
            free( packet_data_a[i] );
            free( packet_data_b[i] );
        }

        total_received += num_packets_a;
    }

    check( total_received > 0 );

    netcode_network_simulator_destroy( simulator_a );
    netcode_network_simulator_destroy( simulator_b );
}

void test_client_create()
{
    {
        struct netcode_client_config_t client_config;
        netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

        struct netcode_client_t * client = netcode_client_create( "127.0.0.1:40000", &client_config, 0.0 );

        struct netcode_address_t test_address;
        netcode_parse_address( "127.0.0.1:40000", &test_address );

        check( client );
        check( client->socket_holder.ipv4.handle != 0 );
        check( client->socket_holder.ipv6.handle == 0 );
        check( netcode_address_equal( &client->address, &test_address ) );

        netcode_client_destroy( client );
    }

    {
        struct netcode_client_config_t client_config;
        netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

        struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, 0.0 );

        struct netcode_address_t test_address;
        netcode_parse_address( "[::]:50000", &test_address );

        check( client );
        check( client->socket_holder.ipv4.handle == 0 );
        check( client->socket_holder.ipv6.handle != 0 );
        check( netcode_address_equal( &client->address, &test_address ) );

        netcode_client_destroy( client );
    }

    {
        struct netcode_client_config_t client_config;
        netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

        struct netcode_client_t * client = netcode_client_create_dual( "127.0.0.1:40000", "[::]:50000", &client_config, 0.0 );

        struct netcode_address_t test_address;
        netcode_parse_address( "127.0.0.1:40000", &test_address );

        check( client );
        check( client->socket_holder.ipv4.handle != 0 );
        check( client->socket_holder.ipv6.handle != 0 );
        check( netcode_address_equal( &client->address, &test_address ) );

        netcode_client_destroy( client );
    }

    {
        struct netcode_client_config_t client_config;
        netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

        struct netcode_client_t * client = netcode_client_create_dual( "[::]:50000", "127.0.0.1:40000", &client_config, 0.0 );

        struct netcode_address_t test_address;
        netcode_parse_address( "[::]:50000", &test_address );

        check( client );
        check( client->socket_holder.ipv4.handle != 0 );
        check( client->socket_holder.ipv6.handle != 0 );
        check( netcode_address_equal( &client->address, &test_address ) );

        netcode_client_destroy( client );
    }
}

void test_server_create()
{
    {
        struct netcode_server_config_t server_config;
        netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

        struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

        struct netcode_address_t test_address;
        netcode_parse_address( "127.0.0.1:40000", &test_address );

        check( server );
        check( server->socket_holder.ipv4.handle != 0 );
        check( server->socket_holder.ipv6.handle == 0 );
        check( netcode_address_equal( &server->address, &test_address ) );

        netcode_server_destroy( server );
    }

    {
        struct netcode_server_config_t server_config;
        netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

        struct netcode_server_t * server = netcode_server_create( "[::1]:50000", &server_config, 0.0 );

        struct netcode_address_t test_address;
        netcode_parse_address( "[::1]:50000", &test_address );

        check( server );
        check( server->socket_holder.ipv4.handle == 0 );
        check( server->socket_holder.ipv6.handle != 0 );
        check( netcode_address_equal( &server->address, &test_address ) );

        netcode_server_destroy( server );
    }

    {
        struct netcode_server_config_t server_config;
        netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

        struct netcode_server_t * server = netcode_server_create_dual( "127.0.0.1:40000", "[::1]:50000", &server_config, 0.0 );

        struct netcode_address_t test_address;
        netcode_parse_address( "127.0.0.1:40000", &test_address );

        check( server );
        check( server->socket_holder.ipv4.handle != 0 );
        check( server->socket_holder.ipv6.handle != 0 );
        check( netcode_address_equal( &server->address, &test_address ) );

        netcode_server_destroy( server );
    }

    {
        struct netcode_server_config_t server_config;
        netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

        struct netcode_server_t * server = netcode_server_create_dual( "[::1]:50000", "127.0.0.1:40000", &server_config, 0.0 );

        struct netcode_address_t test_address;
        netcode_parse_address( "[::1]:50000", &test_address );

        check( server );
        check( server->socket_holder.ipv4.handle != 0 );
        check( server->socket_holder.ipv6.handle != 0 );
        check( netcode_address_equal( &server->address, &test_address ) );

        netcode_server_destroy( server );
    }
}

void test_server_restart_global_sequence()
{
    // global packets (challenge, denied) share per-token server to client keys with
    // per-client packets, so the global sequence must stay in the top half of the
    // sequence space or a stopped and restarted server reuses AEAD nonces. regression
    // test: netcode_server_stop zeroes the global sequence, start must re-seed it.

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

    check( server );
    check( server->global_sequence == 1ULL << 63 );

    netcode_server_start( server, 1 );

    check( server->global_sequence == 1ULL << 63 );

    server->global_sequence += 1000;        // as if the server had sent some global packets

    netcode_server_stop( server );

    netcode_server_start( server, 1 );

    check( server->global_sequence == 1ULL << 63 );

    netcode_server_destroy( server );
}

static uint8_t private_key[NETCODE_KEY_BYTES] = { 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
                                                  0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
                                                  0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
                                                  0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };


static void test_init_keys()
{
    check( crypto_sign_seed_keypair( test_server_public_key, test_server_secret_key, private_key ) == 0 );

    uint8_t session_seed[32];
    int i;
    for ( i = 0; i < 32; i++ )
        session_seed[i] = (uint8_t) ( private_key[i] ^ 0x5a );

    check( crypto_sign_seed_keypair( test_session_public_key, test_session_secret_key, session_seed ) == 0 );
}

static void test_connect( struct netcode_client_t * client, int num_server_addresses, NETCODE_CONST char ** server_addresses, uint8_t * user_data )
{
    struct netcode_address_t addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    int i;
    for ( i = 0; i < num_server_addresses; i++ )
    {
        check( netcode_parse_address( server_addresses[i], &addresses[i] ) == NETCODE_OK );
    }

    netcode_client_connect( client, num_server_addresses, addresses, test_server_public_key, test_session_secret_key, user_data );
}

void test_client_server_connect()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    int server_num_packets_received = 0;
    int client_num_packets_received = 0;

    uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
    int i;
    for ( i = 0; i < NETCODE_MAX_PACKET_SIZE; i++ )
        packet_data[i] = (uint8_t) i;

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        netcode_client_send_packet( client, packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_server_send_packet( server, 0, packet_data, NETCODE_MAX_PACKET_SIZE );

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet( client, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            client_num_packets_received++;
            netcode_client_free_packet( client, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet( server, 0, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            server_num_packets_received++;
            netcode_server_free_packet( server, packet );
        }

        if ( client_num_packets_received >= 10 && server_num_packets_received >= 10 )
        {
            if ( netcode_server_client_connected( server, 0 ) )
            {
                netcode_server_disconnect_client( server, 0 );
            }
        }

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( client_num_packets_received >= 10 && server_num_packets_received >= 10 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void client_server_socket_connect_to( NETCODE_CONST char * client_address, NETCODE_CONST char * client_address2, NETCODE_CONST char * server_address, NETCODE_CONST char * server_address2, NETCODE_CONST char * connect_address )
{
    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

    struct netcode_client_t * client = netcode_client_create_dual( client_address, client_address2, &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;

    struct netcode_server_t * server = netcode_server_create_dual( server_address, server_address2, &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &connect_address, user_data );

    while ( 1 )
    {
        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        // this test runs over real sockets while advancing virtual time, so it must yield
        // real time each iteration or the virtual timeouts can expire before the OS delivers
        // a single loopback packet

        netcode_sleep( 0.01 );

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );
}

void client_server_socket_connect( NETCODE_CONST char * client_address, NETCODE_CONST char * client_address2, NETCODE_CONST char * server_address, NETCODE_CONST char * server_address2 )
{
    client_server_socket_connect_to( client_address, client_address2, server_address, server_address2, server_address );
}

void test_client_server_ipv4_socket_connect()
{
    client_server_socket_connect("0.0.0.0:50000", NULL        , "127.0.0.1:40000", NULL         );
    client_server_socket_connect("0.0.0.0:50000", NULL        , "127.0.0.1:40000", "[::1]:40000");
    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", NULL         );
    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000");
}

void test_client_server_ipv6_socket_connect()
{
    client_server_socket_connect("[::]:50000"   , NULL        , "[::1]:40000", NULL             );
    client_server_socket_connect("[::]:50000"   , NULL        , "[::1]:40000", "127.0.0.1:40000");
    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", NULL             );
    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000");
}

void test_client_server_dual_socket_connect()
{
    // dual stack client connects to dual stack server over ipv4

    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000");

    // dual stack client connects to dual stack server over ipv6

    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000");

    // dual stack client connects to the second address of a dual stack server (ipv6, then ipv4)

    client_server_socket_connect_to("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000", "[::1]:40000");

    client_server_socket_connect_to("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000", "127.0.0.1:40000");
}

void test_client_server_keep_alive()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    // connect client to server

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // pump the client and server long enough that they would timeout without keep alive packets

    int num_iterations = (int) ( 1.25f * TEST_TIMEOUT_SECONDS / delta_time ) + 1;

    int i;
    for ( i = 0; i < num_iterations; i++ )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void test_client_server_multiple_clients()
{
    #define NUM_START_STOP_ITERATIONS 3

    int max_clients[NUM_START_STOP_ITERATIONS] = { 2, 32, 5 };

    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    int i;
    for ( i = 0; i < NUM_START_STOP_ITERATIONS; i++ )
    {
        // start the server with max # of clients for this iteration

        netcode_server_start( server, max_clients[i] );

        // create # of client objects for this iteration and connect to server

        struct netcode_client_t ** client = (struct netcode_client_t **) malloc( sizeof( struct netcode_client_t* ) * max_clients[i] );

        check( client );

        int j;
        for ( j = 0; j < max_clients[i]; j++ )
        {
            char client_address[NETCODE_MAX_ADDRESS_STRING_LENGTH];
            snprintf( client_address, sizeof(client_address), "[::]:%d", 50000 + j );

            struct netcode_client_config_t client_config;
            netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
            client_config.network_simulator = network_simulator;

            client[j] = netcode_client_create( client_address, &client_config, time );

            check( client[j] );

            uint64_t client_id = j;
            netcode_random_bytes( (uint8_t*) &client_id, 8 );

            NETCODE_CONST char * server_address = "[::1]:40000";

            uint8_t user_data[NETCODE_USER_DATA_BYTES];
            netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

            
            test_connect( client[j], 1, &server_address, user_data );
        }

        // make sure all clients can connect

        while ( 1 )
        {
            netcode_network_simulator_update( network_simulator, time );

            for ( j = 0; j < max_clients[i]; j++ )
            {
                netcode_client_update( client[j], time );
            }

            netcode_server_update( server, time );

            int num_connected_clients = 0;

            for ( j = 0; j < max_clients[i]; j++ )
            {
                if ( netcode_client_state( client[j] ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
                    break;

                if ( netcode_client_state( client[j] ) == NETCODE_CLIENT_STATE_CONNECTED )
                    num_connected_clients++;
            }

            if ( num_connected_clients == max_clients[i] )
                break;

            time += delta_time;
        }

        check( netcode_server_num_connected_clients( server ) == max_clients[i] );

        for ( j = 0; j < max_clients[i]; j++ )
        {
            check( netcode_client_state( client[j] ) == NETCODE_CLIENT_STATE_CONNECTED );
            check( netcode_server_client_connected( server, j ) == 1 );
        }

        // make sure all clients can exchange packets with the server

        int * server_num_packets_received = (int*) malloc( sizeof(int) * max_clients[i] );
        int * client_num_packets_received = (int*) malloc( sizeof(int) * max_clients[i] );

        memset( server_num_packets_received, 0, sizeof(int) * max_clients[i] );
        memset( client_num_packets_received, 0, sizeof(int) * max_clients[i] );

        uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
        for ( j = 0; j < NETCODE_MAX_PACKET_SIZE; j++ )
            packet_data[j] = (uint8_t) j;

        while ( 1 )
        {
            netcode_network_simulator_update( network_simulator, time );

            for ( j = 0; j < max_clients[i]; j++ )
            {
                netcode_client_update( client[j], time );
            }

            netcode_server_update( server, time );

            for ( j = 0; j < max_clients[i]; j++ )
            {
                netcode_client_send_packet( client[j], packet_data, NETCODE_MAX_PACKET_SIZE );
            }

            for ( j = 0; j < max_clients[i]; j++ )
            {
                netcode_server_send_packet( server, j, packet_data, NETCODE_MAX_PACKET_SIZE );
            }

            for ( j = 0; j < max_clients[i]; j++ )
            {
                while ( 1 )             
                {
                    int packet_bytes;
                    uint64_t packet_sequence;
                    uint8_t * packet = netcode_client_receive_packet( client[j], &packet_bytes, &packet_sequence );
                    if ( !packet )
                        break;
                    (void) packet_sequence;
                    netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                    netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
                    client_num_packets_received[j]++;
                    netcode_client_free_packet( client[j], packet );
                }
            }

            for ( j = 0; j < max_clients[i]; j++ )
            {
                while ( 1 )             
                {
                    int packet_bytes;
                    uint64_t packet_sequence;
                    void * packet = netcode_server_receive_packet( server, j, &packet_bytes, &packet_sequence );
                    if ( !packet )
                        break;
                    (void) packet_sequence;
                    netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                    netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
                    server_num_packets_received[j]++;
                    netcode_server_free_packet( server, packet );
                }
            }

            int num_clients_ready = 0;

            for ( j = 0; j < max_clients[i]; j++ )
            {
                if ( client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1 )
                {
                    num_clients_ready++;
                }
            }

            if ( num_clients_ready == max_clients[i] )
                break;

            for ( j = 0; j < max_clients[i]; j++ )
            {
                if ( netcode_client_state( client[j] ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
                    break;
            }

            time += delta_time;
        }

        int num_clients_ready = 0;

        for ( j = 0; j < max_clients[i]; j++ )
        {
            if ( client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1 )
            {
                num_clients_ready++;
            }
        }

        check( num_clients_ready == max_clients[i] );

        free( server_num_packets_received );
        free( client_num_packets_received );
        
        netcode_network_simulator_reset( network_simulator );

        for ( j = 0; j < max_clients[i]; j++ )
        {
            netcode_client_destroy( client[j] );
        }

        free( client );

        netcode_server_stop( server );
    }

    netcode_server_destroy( server );

    netcode_network_simulator_destroy( network_simulator );
}

void test_client_server_multiple_servers()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address[] = { "10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000" };

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 3, server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    int server_num_packets_received = 0;
    int client_num_packets_received = 0;

    uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
    int i;
    for ( i = 0; i < NETCODE_MAX_PACKET_SIZE; i++ )
        packet_data[i] = (uint8_t) i;

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        netcode_client_send_packet( client, packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_server_send_packet( server, 0, packet_data, NETCODE_MAX_PACKET_SIZE );

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet( client, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            client_num_packets_received++;
            netcode_client_free_packet( client, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet( server, 0, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            server_num_packets_received++;
            netcode_server_free_packet( server, packet );
        }

        if ( client_num_packets_received >= 10 && server_num_packets_received >= 10 )
        {
            if ( netcode_server_client_connected( server, 0 ) )
            {
                netcode_server_disconnect_client( server, 0 );
            }
        }

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( client_num_packets_received >= 10 && server_num_packets_received >= 10 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}



void test_client_error_connection_timed_out()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    // connect a client to the server

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // now disable updating the server and verify that the client times out

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void test_client_error_connection_response_timeout()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    server->flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS;

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED  )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void test_client_error_connection_request_timeout()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 60.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    server->flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS;

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED  )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void test_client_error_connection_denied()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // now attempt to connect a second client. the connection should be denied.

    struct netcode_client_t * client2 = netcode_client_create( "[::]:50001", &client_config, time );

    check( client2 );

    uint64_t client_id2 = 0;
    netcode_random_bytes( (uint8_t*) &client_id2, 8 );

    uint8_t user_data2[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data2, NETCODE_USER_DATA_BYTES);

    
    test_connect( client2, 1, &server_address, user_data2 );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_client_update( client2, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client2 ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_state( client2 ) == NETCODE_CLIENT_STATE_CONNECTION_DENIED );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );
    
    netcode_client_destroy( client2 );

    netcode_network_simulator_destroy( network_simulator );
}

void test_client_side_disconnect()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // disconnect client side and verify that the server sees that client disconnect cleanly, rather than timing out.

    netcode_client_disconnect( client );

    int i;
    for ( i = 0; i < 10; i++ )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_server_client_connected( server, 0 ) == 0 )
            break;

        time += delta_time;
    }

    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void test_server_side_disconnect()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // disconnect server side and verify that the client disconnects cleanly, rather than timing out.

    netcode_server_disconnect_client( server, 0 );

    int i;
    for ( i = 0; i < 10; i++ )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_DISCONNECTED );
    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void test_server_client_disconnect_reason()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    // no disconnect has happened yet, so the client slot reason is none

    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    // stop updating the client so it goes silent. the server should time it out
    // and record that as the disconnect reason, distinct from a clean disconnect

    int i;
    for ( i = 0; i < 200; i++ )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_server_update( server, time );

        if ( !netcode_server_client_connected( server, 0 ) )
            break;

        time += delta_time;
    }

    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT );

    // reconnect. a new client connecting to the slot clears the reason back to none

    netcode_client_disconnect( client );

    // catch the client's internal clock up to the current time before reconnecting, since it
    // was deliberately not updated above. otherwise the first update after connect sees the
    // whole timeout leg as elapsed time and immediately times out the connection request.
    netcode_client_update( client, time );

    netcode_network_simulator_reset( network_simulator );

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_disconnect_reason( server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void test_client_reconnect()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // disconnect client on the server-side and wait until client sees the disconnect

    netcode_network_simulator_reset( network_simulator );

    netcode_server_disconnect_client( server, 0 );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_DISCONNECTED );
    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );

    // now reconnect the client and verify they connect

    netcode_network_simulator_reset( network_simulator );

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}






/*
    A client and a server wired directly to each other through the send and receive overrides.
    Packets are handed straight to the other side, so the handshake is exercised with no sockets,
    no network simulator and no randomness at all. The wire can drop the first packets the server
    sends, which is what makes the client retransmit its connection request, and it keeps a copy
    of the first payload packet the client sends so it can be replayed later.
*/

struct test_wire_t
{
    struct netcode_client_t * client;
    struct netcode_server_t * server;
    struct netcode_address_t client_address;
    struct netcode_address_t server_address;
    int shutting_down;
    int drop_server_packets;
    int num_connection_requests;
    uint8_t payload_packet[NETCODE_MAX_PACKET_BYTES];
    int payload_packet_bytes;
    uint8_t response_packet[NETCODE_MAX_PACKET_BYTES];
    int response_packet_bytes;
    uint8_t last_server_packet[NETCODE_MAX_PACKET_BYTES];
    int last_server_packet_bytes;
};

static struct test_wire_t test_wire;

static void test_wire_client_send_packet( void * context, struct netcode_address_t * to, NETCODE_CONST uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    (void) to;

    // the wire is down once either end is being destroyed. the disconnect packets they send
    // on the way out have nowhere to go, exactly as an application shutting down would find

    if ( test_wire.shutting_down )
        return;

    if ( packet_data[0] == NETCODE_HANDSHAKE_REQUEST_PACKET )
    {
        test_wire.num_connection_requests++;
    }

    if ( packet_data[0] == NETCODE_HANDSHAKE_RESPONSE_PACKET && test_wire.response_packet_bytes == 0 )
    {
        memcpy( test_wire.response_packet, packet_data, packet_bytes );
        test_wire.response_packet_bytes = packet_bytes;
    }

    if ( ( packet_data[0] & 0xF ) == NETCODE_CONNECTION_PAYLOAD_PACKET && test_wire.payload_packet_bytes == 0 )
    {
        memcpy( test_wire.payload_packet, packet_data, packet_bytes );
        test_wire.payload_packet_bytes = packet_bytes;
    }

    netcode_server_process_packet( test_wire.server, &test_wire.client_address, (uint8_t*) packet_data, packet_bytes );
}

static void test_wire_server_send_packet( void * context, struct netcode_address_t * to, NETCODE_CONST uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    (void) to;

    if ( test_wire.shutting_down )
        return;

    if ( test_wire.drop_server_packets > 0 )
    {
        test_wire.drop_server_packets--;
        return;
    }

    memcpy( test_wire.last_server_packet, packet_data, packet_bytes );
    test_wire.last_server_packet_bytes = packet_bytes;

    netcode_client_process_packet( test_wire.client, &test_wire.server_address, (uint8_t*) packet_data, packet_bytes );
}

static int test_wire_receive_packet( void * context, struct netcode_address_t * from, uint8_t * packet_data, int max_packet_bytes )
{
    (void) context;
    (void) from;
    (void) packet_data;
    (void) max_packet_bytes;
    return 0;
}

static void test_wire_create( int drop_server_packets )
{
    memset( &test_wire, 0, sizeof( test_wire ) );

    test_wire.drop_server_packets = drop_server_packets;

    check( netcode_parse_address( "[::1]:50000", &test_wire.client_address ) == NETCODE_OK );
    check( netcode_parse_address( "[::1]:40000", &test_wire.server_address ) == NETCODE_OK );

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.override_send_and_receive = 1;
    client_config.send_packet_override = test_wire_client_send_packet;
    client_config.receive_packet_override = test_wire_receive_packet;

    test_wire.client = netcode_client_create( "[::1]:50000", &client_config, 0.0 );

    check( test_wire.client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.override_send_and_receive = 1;
    server_config.send_packet_override = test_wire_server_send_packet;
    server_config.receive_packet_override = test_wire_receive_packet;

    test_wire.server = netcode_server_create( "[::1]:40000", &server_config, 0.0 );

    check( test_wire.server );

    netcode_server_start( test_wire.server, 1 );
}

static void test_wire_destroy()
{
    test_wire.shutting_down = 1;
    netcode_server_destroy( test_wire.server );
    netcode_client_destroy( test_wire.client );
    memset( &test_wire, 0, sizeof( test_wire ) );
}

static void test_connect( struct netcode_client_t * client, int num_server_addresses, NETCODE_CONST char ** server_addresses, uint8_t * user_data );

static void test_wire_connect_client( double * time, double delta_time )
{
    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    test_connect( test_wire.client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_client_update( test_wire.client, *time );

        netcode_server_update( test_wire.server, *time );

        if ( netcode_client_state( test_wire.client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        *time += delta_time;
    }
}






#if NETCODE_ENABLE_NONCE_AUDIT


#endif // #if NETCODE_ENABLE_NONCE_AUDIT

struct test_loopback_context_t
{
    struct netcode_client_t * client;
    struct netcode_server_t * server;
    int num_loopback_packets_sent_to_client;
    int num_loopback_packets_sent_to_server;
};

void client_send_loopback_packet_callback( void * _context, int client_index, NETCODE_CONST uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence )
{
    (void) packet_sequence;
    check( _context );
    check( client_index == 0 );
    check( packet_data );
    check( packet_bytes == NETCODE_MAX_PACKET_SIZE );
    int i;
    for ( i = 0; i < packet_bytes; i++ )
    {
        check( packet_data[i] == (uint8_t) i );
    }
    struct test_loopback_context_t * context = (struct test_loopback_context_t*) _context;
    context->num_loopback_packets_sent_to_server++;
    netcode_server_process_loopback_packet( context->server, client_index, packet_data, packet_bytes, packet_sequence );
}

void server_send_loopback_packet_callback( void * _context, int client_index, NETCODE_CONST uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence )
{
    (void) packet_sequence;
    check( _context );
    check( client_index == 0 );
    check( packet_data );
    check( packet_bytes == NETCODE_MAX_PACKET_SIZE );
    int i;
    for ( i = 0; i < packet_bytes; i++ )
    {
        check( packet_data[i] == (uint8_t) i );
    }
    struct test_loopback_context_t * context = (struct test_loopback_context_t*) _context;
    context->num_loopback_packets_sent_to_client++;
    netcode_client_process_loopback_packet( context->client, packet_data, packet_bytes, packet_sequence );
}

void test_disable_timeout()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = -1;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create( "[::]:50000", &client_config, time );

    check( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = -1;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    netcode_server_start( server, 1 );

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( client ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    int server_num_packets_received = 0;
    int client_num_packets_received = 0;

    uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
    int i;
    for ( i = 0; i < NETCODE_MAX_PACKET_SIZE; i++ )
        packet_data[i] = (uint8_t) i;

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( client, time );

        netcode_server_update( server, time );

        netcode_client_send_packet( client, packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_server_send_packet( server, 0, packet_data, NETCODE_MAX_PACKET_SIZE );

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet( client, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            client_num_packets_received++;
            netcode_client_free_packet( client, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet( server, 0, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            server_num_packets_received++;
            netcode_server_free_packet( server, packet );
        }

        if ( client_num_packets_received >= 10 && server_num_packets_received >= 10 )
        {
            if ( netcode_server_client_connected( server, 0 ) )
            {
                netcode_server_disconnect_client( server, 0 );
            }
        }

        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += 1000.0f;        // normally this would timeout the client
    }

    check( client_num_packets_received >= 10 && server_num_packets_received >= 10 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

void test_loopback()
{
    struct test_loopback_context_t context;
    memset( &context, 0, sizeof( context ) );

    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create( NULL, NULL, NULL );

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    // start the server

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    server_config.callback_context = &context;
    server_config.send_loopback_packet_callback = server_send_loopback_packet_callback;

    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &server_config, time );

    check( server );

    int max_clients = 2;

    netcode_server_start( server, max_clients );

    context.server = server;

    // connect a loopback client in slot 0

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    client_config.callback_context = &context;
    client_config.send_loopback_packet_callback = client_send_loopback_packet_callback;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * loopback_client = netcode_client_create( "[::]:50000", &client_config, time );
    check( loopback_client );
    netcode_client_connect_loopback( loopback_client, 0, max_clients );
    context.client = loopback_client;

    check( netcode_client_index( loopback_client ) == 0 );
    check( netcode_client_loopback( loopback_client ) == 1 );
    check( netcode_client_max_clients( loopback_client ) == max_clients );
    check( netcode_client_state( loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

    uint64_t client_id = 0;
    netcode_random_bytes( (uint8_t*) &client_id, 8 );
    netcode_server_connect_loopback_client( server, 0, client_id, NULL );

    check( netcode_server_client_loopback( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    // connect a regular client in the other slot

    struct netcode_client_t * regular_client = netcode_client_create( "[::]:50001", &client_config, time );

    check( regular_client );

    NETCODE_CONST char * server_address = "[::1]:40000";
    netcode_random_bytes( (uint8_t*) &client_id, 8 );

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    
    test_connect( regular_client, 1, &server_address, user_data );

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( regular_client, time );

        netcode_server_update( server, time );

        if ( netcode_client_state( regular_client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        if ( netcode_client_state( regular_client ) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check( netcode_client_state( regular_client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_client_index( regular_client ) == 1 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 1 ) == 1 );
    check( netcode_server_client_loopback( server, 0 ) == 1 );
    check( netcode_server_client_loopback( server, 1 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 2 );

    // test that we can exchange packets for the regular client and the loopback client

    int loopback_client_num_packets_received = 0;
    int loopback_server_num_packets_received = 0;
    int regular_server_num_packets_received = 0;
    int regular_client_num_packets_received = 0;

    uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
    int i;
    for ( i = 0; i < NETCODE_MAX_PACKET_SIZE; i++ )
        packet_data[i] = (uint8_t) i;

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( regular_client, time );

        netcode_server_update( server, time );

        netcode_client_send_packet( loopback_client, packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_client_send_packet( regular_client, packet_data, NETCODE_MAX_PACKET_SIZE );
        
        netcode_server_send_packet( server, 0, packet_data, NETCODE_MAX_PACKET_SIZE );
        
        netcode_server_send_packet( server, 1, packet_data, NETCODE_MAX_PACKET_SIZE );

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet( loopback_client, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            loopback_client_num_packets_received++;
            netcode_client_free_packet( loopback_client, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet( regular_client, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            regular_client_num_packets_received++;
            netcode_client_free_packet( regular_client, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet( server, 0, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            loopback_server_num_packets_received++;
            netcode_server_free_packet( server, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet( server, 1, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            regular_server_num_packets_received++;
            netcode_server_free_packet( server, packet );
        }

        if ( loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
             regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10 )
            break;

        if ( netcode_client_state( regular_client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( loopback_client_num_packets_received >= 10 );
    check( loopback_server_num_packets_received >= 10 );
    check( regular_client_num_packets_received >= 10 );
    check( regular_server_num_packets_received >= 10 );
    check( context.num_loopback_packets_sent_to_client >= 10 );
    check( context.num_loopback_packets_sent_to_server >= 10 );

    // verify that we can disconnect the loopback client

    check( netcode_server_client_loopback( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 2 );

    netcode_server_disconnect_loopback_client( server, 0 );    

    check( netcode_server_client_loopback( server, 0 ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 1 );

    netcode_client_disconnect_loopback( loopback_client );

    check( netcode_client_state( loopback_client ) == NETCODE_CLIENT_STATE_DISCONNECTED );

    // verify that we can reconnect the loopback client

    netcode_random_bytes( (uint8_t*) &client_id, 8 );
    netcode_server_connect_loopback_client( server, 0, client_id, NULL );

    check( netcode_server_client_loopback( server, 0 ) == 1 );
    check( netcode_server_client_loopback( server, 1 ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 1 ) == 1 );
    check( netcode_server_num_connected_clients( server ) == 2 );

    netcode_client_connect_loopback( loopback_client, 0, max_clients );
    
    check( netcode_client_index( loopback_client ) == 0 );
    check( netcode_client_loopback( loopback_client ) == 1 );
    check( netcode_client_max_clients( loopback_client ) == max_clients );
    check( netcode_client_state( loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

    // verify that we can exchange packets for both regular and loopback client post reconnect

    loopback_server_num_packets_received = 0;
    loopback_client_num_packets_received = 0;
    regular_server_num_packets_received = 0;
    regular_client_num_packets_received = 0;
    context.num_loopback_packets_sent_to_client = 0;
    context.num_loopback_packets_sent_to_server = 0;

    while ( 1 )
    {
        netcode_network_simulator_update( network_simulator, time );

        netcode_client_update( regular_client, time );

        netcode_server_update( server, time );

        netcode_client_send_packet( loopback_client, packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_client_send_packet( regular_client, packet_data, NETCODE_MAX_PACKET_SIZE );
        
        netcode_server_send_packet( server, 0, packet_data, NETCODE_MAX_PACKET_SIZE );
        
        netcode_server_send_packet( server, 1, packet_data, NETCODE_MAX_PACKET_SIZE );

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet( loopback_client, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            loopback_client_num_packets_received++;
            netcode_client_free_packet( loopback_client, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet( regular_client, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            regular_client_num_packets_received++;
            netcode_client_free_packet( regular_client, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet( server, 0, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            loopback_server_num_packets_received++;
            netcode_server_free_packet( server, packet );
        }

        while ( 1 )             
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet( server, 1, &packet_bytes, &packet_sequence );
            if ( !packet )
                break;
            (void) packet_sequence;
            netcode_assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
            regular_server_num_packets_received++;
            netcode_server_free_packet( server, packet );
        }

        if ( loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
             regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10 )
            break;

        if ( netcode_client_state( regular_client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;

        time += delta_time;
    }

    check( loopback_client_num_packets_received >= 10 );
    check( loopback_server_num_packets_received >= 10 );
    check( regular_client_num_packets_received >= 10 );
    check( regular_server_num_packets_received >= 10 );
    check( context.num_loopback_packets_sent_to_client >= 10 );
    check( context.num_loopback_packets_sent_to_server >= 10 );

    // verify the regular client times out but loopback client doesn't

    time += 100000.0;

    netcode_server_update( server, time );

    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 1 ) == 0 );

    netcode_client_update( loopback_client, time );

    check( netcode_client_state( loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

    // verify that disconnect all clients leaves loopback clients alone

    netcode_server_disconnect_all_clients( server );

    check( netcode_server_client_connected( server, 0 ) == 1 );
    check( netcode_server_client_connected( server, 1 ) == 0 );
    check( netcode_server_client_loopback( server, 0 ) == 1 );

    // clean up

    netcode_client_destroy( regular_client );

    netcode_client_destroy( loopback_client );

    netcode_server_destroy( server );

    netcode_network_simulator_destroy( network_simulator );
}

#if NETCODE_PACKET_TAGGING

void test_packet_tagging()
{
    // IMPORTANT: Packet tagging is off by default because it doesn't play well with some older home routers
    // See https://learn.microsoft.com/en-us/gaming/gdk/_content/gc/networking/overviews/qos-packet-tagging
    // However, I really recommend providing players with a way to turn it on, since it can significantly reduce
    // jitter playing over Wi-Fi.

    netcode_enable_packet_tagging();

    {
        NETCODE_CONST char * server_address = "127.0.0.1:40000";

        struct netcode_server_config_t server_config;
        netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

        struct netcode_server_t * server = netcode_server_create( server_address, &server_config, 0.0 );

        check( server );

        struct netcode_client_config_t client_config;
        netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

        struct netcode_client_t * client = netcode_client_create( "127.0.0.1:50000", &client_config, 0.0 );

        check( client );

        uint64_t client_id = 0;
        netcode_random_bytes( (uint8_t*) &client_id, 8 );

        uint8_t user_data[NETCODE_USER_DATA_BYTES];
        netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

        
        test_connect( client, 1, &server_address, user_data );

        netcode_client_destroy( client );

        netcode_server_destroy( server );
    }

    {
        NETCODE_CONST char * server_address = "[::1]:40000";

        struct netcode_server_config_t server_config;
        netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

        struct netcode_server_t * server = netcode_server_create( server_address, &server_config, 0.0 );

        check( server );

        struct netcode_client_config_t client_config;
        netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

        struct netcode_client_t * client = netcode_client_create( "[::1]:50000", &client_config, 0.0 );

        check( client );

        uint64_t client_id = 0;
        netcode_random_bytes( (uint8_t*) &client_id, 8 );

        uint8_t user_data[NETCODE_USER_DATA_BYTES];
        netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

        
        test_connect( client, 1, &server_address, user_data );

        netcode_client_destroy( client );

        netcode_server_destroy( server );
    }
}

#endif // #if NETCODE_PACKET_TAGGING

void test_loopback_callback_required()
{
    // entering loopback with send_loopback_packet_callback unset would call a null pointer
    // on the next send. both sides must refuse to enter loopback instead. the guard asserts
    // as well as returning, so install the handler that continues to run this in debug.

    netcode_set_assert_function( test_runtime_guards_assert_handler );

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.timeout_seconds = TEST_TIMEOUT_SECONDS;

    struct netcode_client_t * client = netcode_client_create( "0.0.0.0:50000", &client_config, 0.0 );

    check( client );

    netcode_client_connect_loopback( client, 0, 1 );

    check( netcode_client_loopback( client ) == 0 );
    check( netcode_client_state( client ) == NETCODE_CLIENT_STATE_DISCONNECTED );

    uint8_t payload[NETCODE_MAX_PACKET_SIZE];
    memset( payload, 0, sizeof( payload ) );

    netcode_client_send_packet( client, payload, NETCODE_MAX_PACKET_SIZE );

    netcode_client_destroy( client );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.timeout_seconds = TEST_TIMEOUT_SECONDS;
    memcpy( &server_config.private_key, test_server_secret_key, NETCODE_SECRET_KEY_BYTES );

    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

    check( server );

    netcode_server_start( server, 1 );

    netcode_server_connect_loopback_client( server, 0, 1, NULL );

    check( netcode_server_client_loopback( server, 0 ) == 0 );
    check( netcode_server_client_connected( server, 0 ) == 0 );
    check( netcode_server_num_connected_clients( server ) == 0 );

    netcode_server_send_packet( server, 0, payload, NETCODE_MAX_PACKET_SIZE );

    netcode_server_destroy( server );

    netcode_set_assert_function( netcode_default_assert_handler );
}


// ----------------------------------------------------------------
// Hypersomnia: the handshake without connect tokens
// ----------------------------------------------------------------

static void test_wire_run( double * time, double delta_time, double seconds )
{
    const double end = *time + seconds;

    while ( *time < end )
    {
        netcode_client_update( test_wire.client, *time );
        netcode_server_update( test_wire.server, *time );
        *time += delta_time;
    }
}

void test_handshake_binding_and_signature()
{
    test_wire_create( 0 );

    double time = 0.0;

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    test_connect( test_wire.client, 1, &server_address, user_data );

    while ( netcode_client_state( test_wire.client ) > NETCODE_CLIENT_STATE_DISCONNECTED &&
            netcode_client_state( test_wire.client ) != NETCODE_CLIENT_STATE_CONNECTED )
    {
        netcode_client_update( test_wire.client, time );
        netcode_server_update( test_wire.server, time );
        time += 0.1;
    }

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_client_connected( test_wire.server, 0 ) );

    // what the server got in the sealed box is exactly what the client gave

    check( memcmp( netcode_server_client_user_data( test_wire.server, 0 ), user_data, NETCODE_USER_DATA_BYTES ) == 0 );

    // the session signature verifies over the binding with the session key, and with nothing else

    NETCODE_CONST uint8_t * binding = netcode_server_client_binding( test_wire.server, 0 );
    NETCODE_CONST uint8_t * signature = netcode_server_client_session_signature( test_wire.server, 0 );

    check( crypto_sign_verify_detached( signature, binding, NETCODE_BINDING_BYTES, test_session_public_key ) == 0 );
    check( crypto_sign_verify_detached( signature, binding, NETCODE_BINDING_BYTES, test_server_public_key ) != 0 );

    // the client learned the very key the server holds

    check( netcode_client_server_public_key( test_wire.client ) != NULL );
    check( memcmp( netcode_client_server_public_key( test_wire.client ), test_server_public_key, NETCODE_PUBLIC_KEY_BYTES ) == 0 );
    check( memcmp( netcode_server_public_key( test_wire.server ), test_server_public_key, NETCODE_PUBLIC_KEY_BYTES ) == 0 );

    // payloads go both ways under the derived keys

    uint8_t payload[100];
    netcode_random_bytes( payload, sizeof( payload ) );

    int received_by_server = 0;
    int received_by_client = 0;

    int iteration;
    for ( iteration = 0; iteration < 10; iteration++ )
    {
        netcode_client_send_packet( test_wire.client, payload, sizeof( payload ) );
        netcode_server_send_packet( test_wire.server, 0, payload, sizeof( payload ) );

        netcode_client_update( test_wire.client, time );
        netcode_server_update( test_wire.server, time );
        time += 0.1;

        while ( 1 )
        {
            int bytes;
            uint64_t sequence;
            uint8_t * packet = netcode_server_receive_packet( test_wire.server, 0, &bytes, &sequence );
            if ( !packet )
                break;
            check( bytes == (int) sizeof( payload ) && memcmp( packet, payload, sizeof( payload ) ) == 0 );
            received_by_server++;
            netcode_server_free_packet( test_wire.server, packet );
        }

        while ( 1 )
        {
            int bytes;
            uint64_t sequence;
            uint8_t * packet = netcode_client_receive_packet( test_wire.client, &bytes, &sequence );
            if ( !packet )
                break;
            check( bytes == (int) sizeof( payload ) && memcmp( packet, payload, sizeof( payload ) ) == 0 );
            received_by_client++;
            netcode_client_free_packet( test_wire.client, packet );
        }
    }

    check( received_by_server >= 9 );
    check( received_by_client >= 9 );

    test_wire_destroy();
}

void test_handshake_without_session_key()
{
    test_wire_create( 0 );

    double time = 0.0;

    struct netcode_address_t address;
    check( netcode_parse_address( "[::1]:40000", &address ) == NETCODE_OK );

    // by address: no expected key, no session key, no user data

    netcode_client_connect( test_wire.client, 1, &address, NULL, NULL, NULL );

    test_wire_run( &time, 0.1, 2.0 );

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );

    uint8_t zeros[NETCODE_SIGNATURE_BYTES];
    memset( zeros, 0, sizeof( zeros ) );

    check( memcmp( netcode_server_client_session_signature( test_wire.server, 0 ), zeros, NETCODE_SIGNATURE_BYTES ) == 0 );
    check( memcmp( netcode_client_server_public_key( test_wire.client ), test_server_public_key, NETCODE_PUBLIC_KEY_BYTES ) == 0 );

    test_wire_destroy();
}

void test_handshake_server_key_mismatch()
{
    test_wire_create( 0 );

    double time = 0.0;

    struct netcode_address_t address;
    check( netcode_parse_address( "[::1]:40000", &address ) == NETCODE_OK );

    uint8_t other_key[NETCODE_PUBLIC_KEY_BYTES];
    memcpy( other_key, test_session_public_key, NETCODE_PUBLIC_KEY_BYTES );

    netcode_client_connect( test_wire.client, 1, &address, other_key, test_session_secret_key, NULL );

    test_wire_run( &time, 0.1, NETCODE_DEFAULT_CONNECT_TIMEOUT_SECONDS + 1.0 );

    // never connected, and told why instead of just timing out

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_SERVER_KEY_MISMATCH );
    check( netcode_server_num_connected_clients( test_wire.server ) == 0 );
    check( test_wire.response_packet_bytes == 0 );

    test_wire_destroy();
}

void test_handshake_response_replay()
{
    test_wire_create( 0 );

    double time = 0.0;

    test_wire_connect_client( &time, 0.1 );

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( test_wire.response_packet_bytes == NETCODE_HANDSHAKE_RESPONSE_BYTES );

    // a recorded response sent from another address: its cookie is for the client's address only

    struct netcode_address_t other_address;
    check( netcode_parse_address( "10.0.0.1:50000", &other_address ) == NETCODE_OK );

    netcode_server_process_packet( test_wire.server, &other_address, test_wire.response_packet, test_wire.response_packet_bytes );

    check( netcode_server_num_connected_clients( test_wire.server ) == 1 );
    check( netcode_server_find_client_index_by_address( test_wire.server, &other_address ) == -1 );

    // and from the client's own address once the client left: the cookie was used

    netcode_server_disconnect_client( test_wire.server, 0 );
    check( netcode_server_num_connected_clients( test_wire.server ) == 0 );

    netcode_server_process_packet( test_wire.server, &test_wire.client_address, test_wire.response_packet, test_wire.response_packet_bytes );

    check( netcode_server_num_connected_clients( test_wire.server ) == 0 );

    // a response tampered with in the sealed part does not open

    test_wire.response_packet[test_wire.response_packet_bytes - 1] ^= 1;
    netcode_server_process_packet( test_wire.server, &test_wire.client_address, test_wire.response_packet, test_wire.response_packet_bytes );
    check( netcode_server_num_connected_clients( test_wire.server ) == 0 );

    test_wire_destroy();
}

void test_handshake_forged_challenge()
{
    test_wire_create( 0 );

    // a forged challenge (the server's key is public) with a garbage cookie must not keep the client from connecting

    test_wire.server->flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS;

    NETCODE_CONST char * server_address = "[::1]:40000";
    test_connect( test_wire.client, 1, &server_address, NULL );

    double time = 0.0;

    netcode_client_update( test_wire.client, time );
    netcode_server_update( test_wire.server, time );

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE );
    check( test_wire.last_server_packet[0] == NETCODE_HANDSHAKE_CHALLENGE_PACKET );

    uint8_t forged[NETCODE_MAX_PACKET_BYTES];
    memcpy( forged, test_wire.last_server_packet, test_wire.last_server_packet_bytes );
    netcode_random_bytes( forged + 1, NETCODE_COOKIE_BYTES );
    netcode_client_process_packet( test_wire.client, &test_wire.server_address, forged, test_wire.last_server_packet_bytes );

    test_wire.server->flags = 0;

    int iterations = 0;

    while ( netcode_client_state( test_wire.client ) != NETCODE_CLIENT_STATE_CONNECTED && iterations < 100 )
    {
        time += 0.1;
        netcode_client_update( test_wire.client, time );
        netcode_server_update( test_wire.server, time );
        iterations++;
    }

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );

    test_wire_destroy();
}

void test_handshake_forged_challenge_other_key()
{
    // joined by address (no key pinned): a forged challenge with another key, arriving first, must not keep the client out

    test_wire_create( 0 );

    // the real server does not answer the request yet, so the forged challenge is the first

    test_wire.server->flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS;

    struct netcode_address_t server_address;
    check( netcode_parse_address( "[::1]:40000", &server_address ) == NETCODE_OK );
    netcode_client_connect( test_wire.client, 1, &server_address, NULL, test_session_secret_key, NULL );

    double time = 0.0;

    netcode_client_update( test_wire.client, time );
    netcode_server_update( test_wire.server, time );

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );

    test_wire.server->flags = 0;

    uint8_t forged[1 + NETCODE_COOKIE_BYTES + NETCODE_PUBLIC_KEY_BYTES + 1];
    forged[0] = NETCODE_HANDSHAKE_CHALLENGE_PACKET;
    netcode_random_bytes( forged + 1, NETCODE_COOKIE_BYTES );

    uint8_t other_public[crypto_sign_PUBLICKEYBYTES];
    uint8_t other_secret[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair( other_public, other_secret );
    memcpy( forged + 1 + NETCODE_COOKIE_BYTES, other_public, NETCODE_PUBLIC_KEY_BYTES );
    forged[sizeof( forged ) - 1] = 0;

    netcode_client_process_packet( test_wire.client, &test_wire.server_address, forged, (int) sizeof( forged ) );
    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE );

    int iterations = 0;

    while ( netcode_client_state( test_wire.client ) != NETCODE_CLIENT_STATE_CONNECTED && iterations < 100 )
    {
        time += 0.1;
        netcode_client_update( test_wire.client, time );
        netcode_server_update( test_wire.server, time );
        iterations++;
    }

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );

    test_wire_destroy();
}

void test_handshake_stale_cookie()
{
    test_wire_create( 0 );

    double time = 0.0;

    // a client that stalls past the cookie's lifetime is answered with a fresh challenge and still connects

    netcode_client_destroy( test_wire.client );

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    client_config.protocol_id = TEST_PROTOCOL_ID;
    client_config.connect_timeout_seconds = NETCODE_COOKIE_SECONDS * 3;
    client_config.override_send_and_receive = 1;
    client_config.send_packet_override = test_wire_client_send_packet;
    client_config.receive_packet_override = test_wire_receive_packet;

    test_wire.client = netcode_client_create( "[::1]:50000", &client_config, 0.0 );
    check( test_wire.client );

    test_wire.server->flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS;

    NETCODE_CONST char * server_address = "[::1]:40000";
    test_connect( test_wire.client, 1, &server_address, NULL );

    // the client got a challenge and repeats its response, which the server ignores for a while

    netcode_client_update( test_wire.client, time );
    netcode_server_update( test_wire.server, time );

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE );

    // only the client's time moves on, as when a stalled response arrives late

    test_wire.server->flags = 0;

    netcode_server_update( test_wire.server, NETCODE_COOKIE_SECONDS + 1.0 );

    time = 0.1;

    int iterations = 0;

    while ( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE && iterations < 100 )
    {
        netcode_client_update( test_wire.client, time );
        netcode_server_update( test_wire.server, NETCODE_COOKIE_SECONDS + 1.0 + time );
        time += 0.1;
        iterations++;
    }

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check( netcode_server_num_connected_clients( test_wire.server ) == 1 );

    test_wire_destroy();
}

void test_handshake_version_mismatch()
{
    test_wire_create( 0 );

    double time = 0.0;

    // the server answers a request of another version with its version, no larger than the request

    uint8_t request[NETCODE_HANDSHAKE_REQUEST_BYTES];
    memset( request, 0, sizeof( request ) );
    uint8_t * p = request;
    netcode_write_uint8( &p, NETCODE_HANDSHAKE_REQUEST_PACKET );
    netcode_write_bytes( &p, (uint8_t*) "NETCODE 1.02", NETCODE_VERSION_INFO_BYTES );
    netcode_write_uint64( &p, TEST_PROTOCOL_ID );

    test_wire.last_server_packet_bytes = 0;
    netcode_server_process_packet( test_wire.server, &test_wire.client_address, request, sizeof( request ) );

    check( test_wire.last_server_packet_bytes == NETCODE_HANDSHAKE_VERSION_BYTES );
    check( test_wire.last_server_packet[0] == NETCODE_HANDSHAKE_VERSION_PACKET );
    check( memcmp( test_wire.last_server_packet + 1, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES ) == 0 );

    // a client that hears of another version from its server says so when it gives up

    test_wire.server->flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS;

    NETCODE_CONST char * server_address = "[::1]:40000";
    test_connect( test_wire.client, 1, &server_address, NULL );

    uint8_t version_packet[NETCODE_HANDSHAKE_VERSION_BYTES];
    p = version_packet;
    netcode_write_uint8( &p, NETCODE_HANDSHAKE_VERSION_PACKET );
    netcode_write_bytes( &p, (uint8_t*) "HYPERSOMNIA4", NETCODE_VERSION_INFO_BYTES );

    netcode_client_process_packet( test_wire.client, &test_wire.server_address, version_packet, sizeof( version_packet ) );

    test_wire_run( &time, 0.1, NETCODE_DEFAULT_CONNECT_TIMEOUT_SECONDS + 1.0 );

    check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_VERSION_MISMATCH );

    test_wire_destroy();
}

static int test_allow_handshake_refused_port = 0;

static int test_allow_handshake( void * context, NETCODE_CONST struct netcode_address_t * address )
{
    (void) context;
    return address->port != test_allow_handshake_refused_port;
}

void test_handshake_rate_limit()
{
    test_wire_create( 0 );

    struct netcode_server_t * server = test_wire.server;

    // the application's rule decides for each address

    test_allow_handshake_refused_port = 2000;
    server->config.allow_handshake_callback = test_allow_handshake;

    struct netcode_address_t a, refused, c;
    check( netcode_parse_address( "10.0.0.1:1000", &a ) == NETCODE_OK );
    check( netcode_parse_address( "10.0.0.1:2000", &refused ) == NETCODE_OK );
    check( netcode_parse_address( "10.0.0.3:1000", &c ) == NETCODE_OK );

    check( netcode_server_take_handshake( server, &a ) );
    check( !netcode_server_take_handshake( server, &refused ) );

    // all addresses together: a burst of twice the rate, then nothing until it refills

    server->config.allow_handshake_callback = NULL;
    server->config.handshakes_per_second = 1.0;
    server->handshake_rate_tokens = 2.0;
    server->handshake_rate_last_time = server->time;

    check( netcode_server_take_handshake( server, &a ) );
    check( netcode_server_take_handshake( server, &c ) );
    check( !netcode_server_take_handshake( server, &a ) );

    server->time += 1.0;
    check( netcode_server_take_handshake( server, &c ) );

    test_wire_destroy();
}

/*
    The bug class that matters most: a server that quietly stops taking anyone after enough
    connections. Nothing a client does before its handshake completes may keep state on the server,
    and every connection must give back what it took.
*/

void test_handshake_nothing_accumulates()
{
    test_wire_create( 0 );

    double time = 0.0;

    // thousands of abandoned handshakes from distinct addresses: requests, and responses that never open

    int i;
    for ( i = 0; i < 20000; i++ )
    {
        struct netcode_address_t from;
        memset( &from, 0, sizeof( from ) );
        from.type = NETCODE_ADDRESS_IPV4;
        from.data.ipv4[0] = 10;
        from.data.ipv4[1] = (uint8_t) ( i >> 16 );
        from.data.ipv4[2] = (uint8_t) ( i >> 8 );
        from.data.ipv4[3] = (uint8_t) i;
        from.port = (uint16_t) ( 1000 + i );

        uint8_t request[NETCODE_HANDSHAKE_REQUEST_BYTES];
        memset( request, 0, sizeof( request ) );
        uint8_t * p = request;
        netcode_write_uint8( &p, NETCODE_HANDSHAKE_REQUEST_PACKET );
        netcode_write_bytes( &p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &p, TEST_PROTOCOL_ID );

        netcode_server_process_packet( test_wire.server, &from, request, sizeof( request ) );

        uint8_t response[NETCODE_HANDSHAKE_RESPONSE_BYTES];
        netcode_random_bytes( response, sizeof( response ) );
        response[0] = NETCODE_HANDSHAKE_RESPONSE_PACKET;

        netcode_server_process_packet( test_wire.server, &from, response, sizeof( response ) );
    }

    check( netcode_server_num_connected_clients( test_wire.server ) == 0 );
    check( test_wire.server->encryption_manager.num_encryption_mappings == 0 );

    // and many complete connections, one after another: each gives back its slot and its mapping

    for ( i = 0; i < 300; i++ )
    {
        test_wire_connect_client( &time, 0.1 );

        check( netcode_client_state( test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );
        check( netcode_server_num_connected_clients( test_wire.server ) == 1 );

        if ( i % 2 )
        {
            netcode_client_disconnect( test_wire.client );
            netcode_server_update( test_wire.server, time );
        }
        else
        {
            netcode_server_disconnect_client( test_wire.server, 0 );
            netcode_client_disconnect( test_wire.client );
        }

        time += 0.1;

        check( netcode_server_num_connected_clients( test_wire.server ) == 0 );
        check( test_wire.server->encryption_manager.num_encryption_mappings == 0 );
    }

    test_wire_destroy();
}


#define RUN_TEST( test_function )                                           \
    do                                                                      \
    {                                                                       \
        printf( #test_function "\n" );                                      \
        test_function();                                                    \
    }                                                                       \
    while (0)

void netcode_test()
{
    test_init_keys();

    //while ( 1 )
    {
        RUN_TEST( test_crypto_aead_vectors );
        RUN_TEST( test_queue );
        RUN_TEST( test_endian );
        RUN_TEST( test_address );
        RUN_TEST( test_sequence );
        RUN_TEST( test_connection_keep_alive_packet );
        RUN_TEST( test_connection_payload_packet );
        RUN_TEST( test_connection_disconnect_packet );
        RUN_TEST( test_encryption_manager );
        RUN_TEST( test_replay_protection );
        RUN_TEST( test_runtime_guards );
        RUN_TEST( test_init_and_defaults );
        RUN_TEST( test_client_create_error );
        RUN_TEST( test_server_create_error );
        RUN_TEST( test_network_simulator_determinism );
        RUN_TEST( test_network_simulator_allocation_failure );
        RUN_TEST( test_client_create );
        RUN_TEST( test_server_create );
        RUN_TEST( test_server_restart_global_sequence );
        RUN_TEST( test_client_server_connect );
        RUN_TEST( test_client_server_ipv4_socket_connect );
        RUN_TEST( test_client_server_ipv6_socket_connect );
        RUN_TEST( test_client_server_dual_socket_connect );
        RUN_TEST( test_client_server_keep_alive );
        RUN_TEST( test_client_server_multiple_clients );
        RUN_TEST( test_client_server_multiple_servers );
        RUN_TEST( test_client_error_connection_timed_out );
        RUN_TEST( test_client_error_connection_response_timeout );
        RUN_TEST( test_client_error_connection_request_timeout );
        RUN_TEST( test_client_error_connection_denied );
        RUN_TEST( test_client_side_disconnect );
        RUN_TEST( test_server_side_disconnect );
        RUN_TEST( test_server_client_disconnect_reason );
        RUN_TEST( test_client_reconnect );
        RUN_TEST( test_disable_timeout );
        RUN_TEST( test_loopback );
        RUN_TEST( test_loopback_callback_required );
        RUN_TEST( test_handshake_binding_and_signature );
        RUN_TEST( test_handshake_without_session_key );
        RUN_TEST( test_handshake_server_key_mismatch );
        RUN_TEST( test_handshake_response_replay );
        RUN_TEST( test_handshake_stale_cookie );
        RUN_TEST( test_handshake_forged_challenge );
        RUN_TEST( test_handshake_forged_challenge_other_key );
        RUN_TEST( test_handshake_version_mismatch );
        RUN_TEST( test_handshake_rate_limit );
        RUN_TEST( test_handshake_nothing_accumulates );
#if NETCODE_PACKET_TAGGING
        RUN_TEST( test_packet_tagging );
#endif // #if NETCODE_PACKET_TAGGING
#if NETCODE_ENABLE_NONCE_AUDIT
#endif // #if NETCODE_ENABLE_NONCE_AUDIT
    }
}

#endif // #if NETCODE_ENABLE_TESTS
