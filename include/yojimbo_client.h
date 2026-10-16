/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2026, Más Bandwidth LLC.

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

#ifndef YOJIMBO_CLIENT_H
#define YOJIMBO_CLIENT_H

#include "yojimbo_config.h"
#include "yojimbo_address.h"
#include "yojimbo_base_client.h"

struct netcode_client_t;
struct netcode_address_t;
class client_adapter;

namespace yojimbo
{
    /**
        The reason this client was last disconnected.

        This lets you distinguish what to show the player and what to do next: a denied connection (eg. server full),
        an expired or invalid connect token (eg. matchmaking took too long, or a client/server version mismatch),
        a timeout, or a protocol error such as a message that failed to serialize.

        Cleared to YOJIMBO_CLIENT_DISCONNECT_REASON_NONE when a new connect attempt starts. The first reason recorded
        for a disconnect wins, so a specific error is never overwritten by the generic disconnect that follows it.

        @see BaseClient::GetDisconnectReason
     */

    enum ClientDisconnectReason
    {
        YOJIMBO_CLIENT_DISCONNECT_REASON_NONE = 0,                          ///< No disconnect has happened yet (or a new connect attempt is in progress).
        YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED,                      ///< You called Client::Disconnect. A deliberate local disconnect.
        YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER,            ///< The server disconnected us. The server was stopped, or it kicked this client.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED,                 ///< The server denied the connection request. For example, the server is full.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT,      ///< No response from the server to our connection request. Server not running, unreachable, or wrong address.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT,     ///< No response from the server to our challenge response while establishing the connection.
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT,              ///< The established connection timed out. We stopped hearing from the server.
        YOJIMBO_CLIENT_DISCONNECT_REASON_SERVER_KEY_MISMATCH,               ///< The server presented another public key than the one expected (e.g. from the server list).
        YOJIMBO_CLIENT_DISCONNECT_REASON_VERSION_MISMATCH,                  ///< The server runs another version of the protocol.
        YOJIMBO_CLIENT_DISCONNECT_REASON_MATCH_IN_PROGRESS,                 ///< The server takes no one new now (a match in progress).
        YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE,               ///< A message from the server failed to serialize read. Usually a client/server protocol version mismatch, or a bug in a message serialize function.
        YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC,                            ///< A channel desynced and cannot recover. See CHANNEL_ERROR_DESYNC.
        YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL,                   ///< A channel send queue filled up. See CHANNEL_ERROR_SEND_QUEUE_FULL.
        YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED,                   ///< The server sent block data on a channel that is configured with blocks disabled.
        YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE,                 ///< Tried to send a message too large to ever fit into a packet. See CHANNEL_ERROR_MESSAGE_TOO_LARGE.
        YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,                     ///< The client memory budget was exhausted. Consider increasing ClientServerConfig::clientMemory.
        YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED,                ///< A connection packet from the server failed to deserialize.
    };

    /// Helper function to convert a client disconnect reason to a user friendly string.

    inline const char * GetClientDisconnectReasonString( int reason )
    {
        switch ( reason )
        {
            case YOJIMBO_CLIENT_DISCONNECT_REASON_NONE:                             return "none";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED:                     return "disconnected";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER:           return "disconnected by server";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED:                return "connection denied";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT:     return "connection request timed out";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT:    return "connection response timed out";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT:             return "connection timed out";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_SERVER_KEY_MISMATCH:              return "server key mismatch";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_VERSION_MISMATCH:                 return "version mismatch";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_MATCH_IN_PROGRESS:                return "match in progress";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE:              return "failed to serialize";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC:                           return "desync";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL:                  return "send queue full";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED:                  return "blocks disabled";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE:                return "message too large";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY:                    return "out of memory";
            case YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED:               return "read packet failed";
            default:
                yojimbo_assert( false );
                return "(unknown)";
        }
    }

    /**
        Client implementation
     */

    class Client : public BaseClient
    {
    public:

        /**
            The client constructor.
            @param allocator The allocator for all memory used by the client.
            @param address The address the client should bind to.
            @param config The client/server configuration.
            @param adapter The adapter to the game program. Specifies the allocator and the message factory to use.
            @param time The current time in seconds. See ClientInterface::AdvanceTime
         */

        explicit Client( Allocator & allocator, const Address & address, const ClientServerConfig & config, Adapter & adapter, double time, client_adapter* parent = NULL );

        ~Client();

        /**
            Connect to the first server address that answers, in order.
            @param expectedServerPublicKey The server's Ed25519 public key (ServerPublicKeyBytes), or NULL to take the one it presents.
            @param sessionSecretKey The Ed25519 secret key (ServerSecretKeyBytes) the connection binding is signed with, or NULL.
            @param userData UserDataBytes handed to the server sealed, or NULL for zeros.
            @returns True if the connect attempt started. False if the client ran out of memory or could not open its socket. In every false case nothing stays allocated.
         */

        bool Connect( const Address serverAddresses[], int numServerAddresses, const uint8_t * expectedServerPublicKey, const uint8_t * sessionSecretKey, const uint8_t * userData );

        /// The public key the server presented, or NULL before the handshake got that far.

        const uint8_t * GetServerPublicKey() const;

        /// Which of the addresses given to Connect the client is on (0 - the first).

        int GetServerAddressIndex() const;

        void Disconnect() YOJIMBO_OVERRIDE;

        void SendPackets() YOJIMBO_OVERRIDE;

        void ReceivePackets() YOJIMBO_OVERRIDE;

        void AdvanceTime( double time ) YOJIMBO_OVERRIDE;

        int GetClientIndex() const YOJIMBO_OVERRIDE;

        uint64_t GetClientId() const YOJIMBO_OVERRIDE { return m_clientId; }

        bool ConnectLoopback( int clientIndex, uint64_t clientId, int maxClients ) YOJIMBO_OVERRIDE;

        void DisconnectLoopback() YOJIMBO_OVERRIDE;

        bool IsLoopback() const YOJIMBO_OVERRIDE;

        void ProcessLoopbackPacket( const uint8_t * packetData, int packetBytes, uint64_t packetSequence ) YOJIMBO_OVERRIDE;

        /**
            Gets the local address the client socket is bound to (with the actual port, when port 0 was passed in).
            Under custom packet I/O (Adapter::UseCustomPacketIO) there is no socket: this is the
            constructor-supplied synthetic address, unchanged.
         */

        const Address & GetAddress() const { return m_boundAddress; }

		netcode_client_t* GetClientDetail() const { return m_client; }
		client_adapter* GetParent() const { return m_parent; }

    private:

        void CreateClient( const Address & address );

        void DestroyClient();

        void StateChangeCallbackFunction( int previous, int current );

        static void StaticStateChangeCallbackFunction( void * context, int previous, int current );

        void TransmitPacketFunction( uint16_t packetSequence, uint8_t * packetData, int packetBytes ) YOJIMBO_OVERRIDE;

        int ProcessPacketFunction( uint16_t packetSequence, uint8_t * packetData, int packetBytes ) YOJIMBO_OVERRIDE;

        void SendLoopbackPacketCallbackFunction( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence );

        static void StaticSendLoopbackPacketCallbackFunction( void * context, int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence );

        static void StaticSendPacketOverride( void * context, netcode_address_t * to, const uint8_t * packetData, int packetBytes );

        static int StaticReceivePacketOverride( void * context, netcode_address_t * from, uint8_t * packetData, int maxPacketBytes );

        ClientServerConfig m_config;                    ///< Client/server configuration.
        netcode_client_t * m_client;                    ///< netcode client data.
        Address m_address;                              ///< Original address passed to ctor.
        Address m_boundAddress;                         ///< Address after socket bind, eg. with valid port. Custom packet I/O: stays the ctor-supplied synthetic address (no socket bind).
        uint64_t m_clientId;                            ///< The globally unique client id (set on each call to connect)
        bool m_disconnecting;                           ///< True while Disconnect tears the client down. Makes a reentrant Disconnect from an adapter callback during teardown a harmless no-op.

		client_adapter* m_parent;
    };
}

#endif // #ifndef YOJIMBO_CLIENT_H
