/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2024, Mas Bandwidth LLC.

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

#include "yojimbo.h"
#include "yojimbo_utils.h"

#ifdef _MSC_VER
#define SODIUM_STATIC
#endif // #ifdef _MSC_VER

#include <sodium.h>

#if YOJIMBO_DEBUG_MEMORY_LEAKS
#include <map>
#endif // YOJIMBO_DEBUG_MEMORY_LEAKS

static yojimbo::Allocator * g_defaultAllocator = NULL;

namespace yojimbo
{
    Allocator & GetDefaultAllocator()
    {
        yojimbo_assert( g_defaultAllocator );
        return *g_defaultAllocator;
    }
}

extern "C" int netcode_init();
extern "C" int reliable_init();
extern "C" void netcode_term();
extern "C" void reliable_term();

#define NETCODE_OK 1
#define RELIABLE_OK 1

bool InitializeYojimbo()
{
    g_defaultAllocator = new yojimbo::DefaultAllocator();

    if ( netcode_init() != NETCODE_OK )
        return false;

    if ( reliable_init() != RELIABLE_OK )
        return false;

    return sodium_init() != -1;
}

void ShutdownYojimbo()
{
    reliable_term();

    netcode_term();

    yojimbo_assert( g_defaultAllocator );
    delete g_defaultAllocator;
    g_defaultAllocator = NULL;
}

// ---------------------------------------------------------------------------------

#ifdef _MSC_VER
#include <malloc.h>
#endif // #ifdef _MSC_VER
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>

// ---------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------

#include "yojimbo.h"
#include "netcode.h"
#include "reliable.h"
#include <stdarg.h>
#include <stdio.h>

static void default_assert_handler( const char * condition, const char * function, const char * file, int line )
{
    // We use YOJIMBO_LOG_LEVEL_NONE because it's lower than YOJIMBO_LOG_LEVEL_ERROR, so even if you suppress errors (by setting
    // yojimbo_log_level(YOJIMBO_LOG_LEVEL_NONE)), this will still be logged.
    yojimbo_printf( YOJIMBO_LOG_LEVEL_NONE, "assert failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    #if defined( __GNUC__ )
    __builtin_trap();
    #elif defined( _MSC_VER )
    __debugbreak();
    #endif
}

static int log_level = 0;
static int (*printf_function)( const char *, ... ) = printf;
void (*yojimbo_assert_function)( const char *, const char *, const char * file, int line ) = default_assert_handler;

void yojimbo_log_level( int level )
{
    log_level = level;
    netcode_log_level( level );
    reliable_log_level( level );
}

void yojimbo_set_printf_function( int (*function)( const char *, ... ) )
{
    yojimbo_assert( function );
    printf_function = function;
    netcode_set_printf_function( function );
    reliable_set_printf_function( function );
}

void yojimbo_set_assert_function( void (*function)( const char *, const char *, const char * file, int line ) )
{
    yojimbo_assert_function = function;
    netcode_set_assert_function( function );
    reliable_set_assert_function( function );
}

#if YOJIMBO_ENABLE_LOGGING

void yojimbo_printf( int level, const char * format, ... ) 
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

#else // #if YOJIMBO_ENABLE_LOGGING

void yojimbo_printf( int level, const char * format, ... ) 
{
    (void) level;
    (void) format;
}

#endif // #if YOJIMBO_ENABLE_LOGGING

#if __APPLE__

// ===============================
//              MacOS
// ===============================

#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

void yojimbo_sleep( double time )
{
    usleep( (int) ( time * 1000000 ) );
}

double yojimbo_time()
{
    static uint64_t start = 0;

    static mach_timebase_info_data_t timebase_info;

    if ( start == 0 )
    {
        mach_timebase_info( &timebase_info );
        start = mach_absolute_time();
        return 0.0;
    }

    uint64_t current = mach_absolute_time();

    if ( current < start )
        current = start;

    return ( double( current - start ) * double( timebase_info.numer ) / double( timebase_info.denom ) ) / 1000000000.0;
}

#elif __linux

// ===============================
//              Linux
// ===============================

#include <unistd.h>
#include <time.h>

void yojimbo_sleep( double time )
{
    usleep( (int) ( time * 1000000 ) );
}

double yojimbo_time()
{
    static double start = -1;

    if ( start == -1 )
    {
        timespec ts;
        clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
        start = ts.tv_sec + double( ts.tv_nsec ) / 1000000000.0;
        return 0.0;
    }

    timespec ts;
    clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
    double current = ts.tv_sec + double( ts.tv_nsec ) / 1000000000.0;
    if ( current < start )
        current = start;
    return current - start;
}

#elif defined(_WIN32)

// ===============================
//             Windows
// ===============================

#define NOMINMAX
#include <windows.h>

void yojimbo_sleep( double time )
{
    const int milliseconds = time * 1000;
    Sleep( milliseconds );
}

static bool timer_initialized = false;
static LARGE_INTEGER timer_frequency;
static LARGE_INTEGER timer_start;

double yojimbo_time()
{
    if ( !timer_initialized )
    {
        QueryPerformanceFrequency( &timer_frequency );
        QueryPerformanceCounter( &timer_start );
        timer_initialized = true;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter( &now );
    if ( now.QuadPart < timer_start.QuadPart )
        now.QuadPart = timer_start.QuadPart;
    return double( now.QuadPart - timer_start.QuadPart ) / double( timer_frequency.QuadPart );
}

#else

#error unsupported platform!

#endif

// ---------------------------------------------------------------------------------

namespace yojimbo
{
    void ChannelPacketData::Initialize()
    {
        channelIndex = 0;
        blockMessage = 0;
        messageFailedToSerialize = 0;
        message.numMessages = 0;
        initialized = 1;
    }

    void ChannelPacketData::Free( MessageFactory & messageFactory )
    {
        yojimbo_assert( initialized );
        Allocator & allocator = messageFactory.GetAllocator();
        if ( !blockMessage )
        {
            if ( message.numMessages > 0 )
            {
                for ( int i = 0; i < message.numMessages; ++i )
                {
                    if ( message.messages[i] )
                    {
                        messageFactory.ReleaseMessage( message.messages[i] );
                    }
                }
                YOJIMBO_FREE( allocator, message.messages );
            }
        }
        else
        {
            if ( block.message )
            {
                messageFactory.ReleaseMessage( block.message );
                block.message = NULL;
            }
            YOJIMBO_FREE( allocator, block.fragmentData );
        }
        initialized = 0;
    }

    template <typename Stream> bool SerializeOrderedMessages( Stream & stream, 
                                                              MessageFactory & messageFactory, 
                                                              int & numMessages, 
                                                              Message ** & messages, 
                                                              int maxMessagesPerPacket )
    {
        const int maxMessageType = messageFactory.GetNumTypes() - 1;

        bool hasMessages = Stream::IsWriting && numMessages != 0;

        serialize_bool( stream, hasMessages );

        if ( hasMessages )
        {
            serialize_int( stream, numMessages, 1, maxMessagesPerPacket );

            int * messageTypes = (int*) alloca( sizeof( int ) * numMessages );

            uint16_t * messageIds = (uint16_t*) alloca( sizeof( uint16_t ) * numMessages );

            memset( messageTypes, 0, sizeof( int ) * numMessages );
            memset( messageIds, 0, sizeof( uint16_t ) * numMessages );

            if ( Stream::IsWriting )
            {
                yojimbo_assert( messages );

                for ( int i = 0; i < numMessages; ++i )
                {
                    yojimbo_assert( messages[i] );
                    messageTypes[i] = messages[i]->GetType();
                    messageIds[i] = messages[i]->GetId();
                }
            }
            else
            {
                Allocator & allocator = messageFactory.GetAllocator();

                messages = (Message**) YOJIMBO_ALLOCATE( allocator, sizeof( Message* ) * numMessages );

                for ( int i = 0; i < numMessages; ++i )
                {
                    messages[i] = NULL;
                }
            }

            serialize_bits( stream, messageIds[0], 16 );

            for ( int i = 1; i < numMessages; ++i )
                serialize_sequence_relative( stream, messageIds[i-1], messageIds[i] );

            for ( int i = 0; i < numMessages; ++i )
            {
                if ( maxMessageType > 0 )
                {
                    serialize_int( stream, messageTypes[i], 0, maxMessageType );
                }
                else
                {
                    messageTypes[i] = 0;
                }

                if ( Stream::IsReading )
                {
                    messages[i] = messageFactory.CreateMessage( messageTypes[i] );

                    if ( !messages[i] )
                    {
                        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create message of type %d (SerializeOrderedMessages)\n", messageTypes[i] );
                        return false;
                    }

                    messages[i]->SetId( messageIds[i] );
                }

                yojimbo_assert( messages[i] );

                if ( !messages[i]->SerializeInternal( stream ) )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message of type %d (SerializeOrderedMessages)\n", messageTypes[i] );
                    return false;
                }
            }
        }

        return true;
    }

    template <typename Stream> bool SerializeMessageBlock( Stream & stream, MessageFactory & messageFactory, BlockMessage * blockMessage, int maxBlockSize )
    {
        int blockSize = Stream::IsWriting ? blockMessage->GetBlockSize() : 0;

        serialize_int( stream, blockSize, 1, maxBlockSize );

        uint8_t * blockData;

        if ( Stream::IsReading )
        {
            Allocator & allocator = messageFactory.GetAllocator();
            blockData = (uint8_t*) YOJIMBO_ALLOCATE( allocator, blockSize );
            if ( !blockData )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate message block (SerializeMessageBlock)\n" );
                return false;
            }
            blockMessage->AttachBlock( allocator, blockData, blockSize );
        }                   
        else
        {
            blockData = blockMessage->GetBlockData();
        } 

        serialize_bytes( stream, blockData, blockSize );

        return true;
    }

    template <typename Stream> bool SerializeUnorderedMessages( Stream & stream, 
                                                                MessageFactory & messageFactory, 
                                                                int & numMessages, 
                                                                Message ** & messages, 
                                                                int maxMessagesPerPacket, 
                                                                int maxBlockSize )
    {
        const int maxMessageType = messageFactory.GetNumTypes() - 1;

        bool hasMessages = Stream::IsWriting && numMessages != 0;

        serialize_bool( stream, hasMessages );

        if ( hasMessages )
        {
            serialize_int( stream, numMessages, 1, maxMessagesPerPacket );

            int * messageTypes = (int*) alloca( sizeof( int ) * numMessages );

            memset( messageTypes, 0, sizeof( int ) * numMessages );

            if ( Stream::IsWriting )
            {
                yojimbo_assert( messages );

                for ( int i = 0; i < numMessages; ++i )
                {
                    yojimbo_assert( messages[i] );
                    messageTypes[i] = messages[i]->GetType();
                }
            }
            else
            {
                Allocator & allocator = messageFactory.GetAllocator();

                messages = (Message**) YOJIMBO_ALLOCATE( allocator, sizeof( Message* ) * numMessages );

                for ( int i = 0; i < numMessages; ++i )
                    messages[i] = NULL;
            }

            for ( int i = 0; i < numMessages; ++i )
            {
                if ( maxMessageType > 0 )
                {
                    serialize_int( stream, messageTypes[i], 0, maxMessageType );
                }
                else
                {
                    messageTypes[i] = 0;
                }

                if ( Stream::IsReading )
                {
                    messages[i] = messageFactory.CreateMessage( messageTypes[i] );

                    if ( !messages[i] )
                    {
                        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create message type %d (SerializeUnorderedMessages)\n", messageTypes[i] );
                        return false;
                    }
                }

                yojimbo_assert( messages[i] );

                if ( !messages[i]->SerializeInternal( stream ) )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message type %d (SerializeUnorderedMessages)\n", messageTypes[i] );
                    return false;
                }

                if ( messages[i]->IsBlockMessage() )
                {
                    BlockMessage * blockMessage = (BlockMessage*) messages[i];
                    if ( !SerializeMessageBlock( stream, messageFactory, blockMessage, maxBlockSize ) )
                    {
                        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message block (SerializeUnorderedMessages)\n" );
                        return false;
                    }
                }
            }
        }

        return true;
    }

    template <typename Stream> bool SerializeBlockFragment( Stream & stream, 
                                                            MessageFactory & messageFactory, 
                                                            ChannelPacketData::BlockData & block, 
                                                            const ChannelConfig & channelConfig )
    {
        const int maxMessageType = messageFactory.GetNumTypes() - 1;

        if (Stream::IsReading)
        {
            block.message = NULL;
            block.fragmentData = NULL;
        }

        serialize_bits( stream, block.messageId, 16 );

        if ( channelConfig.GetMaxFragmentsPerBlock() > 1 )
        {
            serialize_int( stream, block.numFragments, 1, channelConfig.GetMaxFragmentsPerBlock() );
        }
        else
        {
            if ( Stream::IsReading )
                block.numFragments = 1;
        }

        if ( block.numFragments > 1 )
        {
            serialize_int( stream, block.fragmentId, 0, block.numFragments - 1 );
        }
        else
        {
            if ( Stream::IsReading )
                block.fragmentId = 0;
        }

        serialize_int( stream, block.fragmentSize, 1, channelConfig.blockFragmentSize );

        if ( Stream::IsReading )
        {
            block.fragmentData = (uint8_t*) YOJIMBO_ALLOCATE( messageFactory.GetAllocator(), block.fragmentSize );

            if ( !block.fragmentData )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize block fragment (SerializeBlockFragment)\n" );
                return false;
            }
        }

        serialize_bytes( stream, block.fragmentData, block.fragmentSize );

        if ( block.fragmentId == 0 )
        {
            // block message

            if ( maxMessageType > 0 )
            {
                serialize_int( stream, block.messageType, 0, maxMessageType );
            }
            else
            {
                block.messageType = 0;
            }

            if ( Stream::IsReading )
            {
                Message * message = messageFactory.CreateMessage( block.messageType );

                if ( !message )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create block message type %d (SerializeBlockFragment)\n", block.messageType );
                    return false;
                }

                if ( !message->IsBlockMessage() )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: received block fragment attached to non-block message (SerializeBlockFragment)\n" );
                    return false;
                }

                block.message = (BlockMessage*) message;
            }

            yojimbo_assert( block.message );

            if ( !block.message->SerializeInternal( stream ) )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize block message of type %d (SerializeBlockFragment)\n", block.messageType );
                return false;
            }
        }

        return true;
    }

    template <typename Stream> bool ChannelPacketData::Serialize( Stream & stream, 
                                                                  MessageFactory & messageFactory, 
                                                                  const ChannelConfig * channelConfigs, 
                                                                  int numChannels )
    {
        yojimbo_assert( initialized );

#if YOJIMBO_DEBUG_MESSAGE_BUDGET
        int startBits = stream.GetBitsProcessed();
#endif // #if YOJIMBO_DEBUG_MESSAGE_BUDGET

        if ( numChannels > 1 )
            serialize_int( stream, channelIndex, 0, numChannels - 1 );
        else
            channelIndex = 0;

        const ChannelConfig & channelConfig = channelConfigs[channelIndex];

        serialize_bool( stream, blockMessage );

        if ( !blockMessage )
        {
            switch ( channelConfig.type )
            {
                case CHANNEL_TYPE_RELIABLE_ORDERED:
                {
                    if ( !SerializeOrderedMessages( stream, messageFactory, message.numMessages, message.messages, channelConfig.maxMessagesPerPacket ) )
                    {
                        messageFailedToSerialize = 1;
                        return true;
                    }
                }
                break;

                case CHANNEL_TYPE_UNRELIABLE_UNORDERED:
                {
                    if ( !SerializeUnorderedMessages( stream, 
                                                      messageFactory, 
                                                      message.numMessages, 
                                                      message.messages, 
                                                      channelConfig.maxMessagesPerPacket, 
                                                      channelConfig.maxBlockSize ) )
                    {
                        messageFailedToSerialize = 1;
                        return true;
                    }
                }
                break;
            }

#if YOJIMBO_DEBUG_MESSAGE_BUDGET
            if ( channelConfig.packetBudget > 0 )
            {
                yojimbo_assert( stream.GetBitsProcessed() - startBits <= channelConfig.packetBudget * 8 );
            }
#endif // #if YOJIMBO_DEBUG_MESSAGE_BUDGET
        }
        else
        {
            if ( channelConfig.disableBlocks )
                return false;

            if ( !SerializeBlockFragment( stream, messageFactory, block, channelConfig ) )
                return false;
        }

        return true;
    }

    bool ChannelPacketData::SerializeInternal( ReadStream & stream, MessageFactory & messageFactory, const ChannelConfig * channelConfigs, int numChannels )
    {
        return Serialize( stream, messageFactory, channelConfigs, numChannels );
    }

    bool ChannelPacketData::SerializeInternal( WriteStream & stream, MessageFactory & messageFactory, const ChannelConfig * channelConfigs, int numChannels )
    {
        return Serialize( stream, messageFactory, channelConfigs, numChannels );
    }

    bool ChannelPacketData::SerializeInternal( MeasureStream & stream, MessageFactory & messageFactory, const ChannelConfig * channelConfigs, int numChannels )
    {
        return Serialize( stream, messageFactory, channelConfigs, numChannels );
    }

    // ------------------------------------------------------------------------------------

    Channel::Channel( Allocator & allocator, MessageFactory & messageFactory, const ChannelConfig & config, int channelIndex, double time ) : m_config( config )
    {
        yojimbo_assert( channelIndex >= 0 );
        yojimbo_assert( channelIndex < MaxChannels );
        m_channelIndex = channelIndex;
        m_allocator = &allocator;
        m_messageFactory = &messageFactory;
        m_errorLevel = CHANNEL_ERROR_NONE;
        m_time = time;
        ResetCounters();
    }

    uint64_t Channel::GetCounter( int index ) const
    {
        yojimbo_assert( index >= 0 );
        yojimbo_assert( index < CHANNEL_COUNTER_NUM_COUNTERS );
        return m_counters[index];
    }

    void Channel::ResetCounters()
    { 
        memset( m_counters, 0, sizeof( m_counters ) ); 
    }

    int Channel::GetChannelIndex() const 
    { 
        return m_channelIndex;
    }

    void Channel::SetErrorLevel( ChannelErrorLevel errorLevel )
    {
        if ( errorLevel != m_errorLevel && errorLevel != CHANNEL_ERROR_NONE )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "channel went into error state: %s\n", GetChannelErrorString( errorLevel ) );
        }
        m_errorLevel = errorLevel;
    }

    ChannelErrorLevel Channel::GetErrorLevel() const
    {
        return m_errorLevel;
    }

    // ------------------------------------------------------------------------------------

    ReliableOrderedChannel::ReliableOrderedChannel( Allocator & allocator, MessageFactory & messageFactory, const ChannelConfig & config, int channelIndex, double time ) 
        : Channel( allocator, messageFactory, config, channelIndex, time )
    {
        yojimbo_assert( config.type == CHANNEL_TYPE_RELIABLE_ORDERED );

        yojimbo_assert( ( 65536 % config.sentPacketBufferSize ) == 0 );
        yojimbo_assert( ( 65536 % config.messageSendQueueSize ) == 0 );
        yojimbo_assert( ( 65536 % config.messageReceiveQueueSize ) == 0 );

        m_sentPackets = YOJIMBO_NEW( *m_allocator, SequenceBuffer<SentPacketEntry>, *m_allocator, m_config.sentPacketBufferSize );
        m_messageSendQueue = YOJIMBO_NEW( *m_allocator, SequenceBuffer<MessageSendQueueEntry>, *m_allocator, m_config.messageSendQueueSize );
        m_messageReceiveQueue = YOJIMBO_NEW( *m_allocator, SequenceBuffer<MessageReceiveQueueEntry>, *m_allocator, m_config.messageReceiveQueueSize );
        m_sentPacketMessageIds = (uint16_t*) YOJIMBO_ALLOCATE( *m_allocator, sizeof( uint16_t ) * m_config.maxMessagesPerPacket * m_config.sentPacketBufferSize );

        if ( !config.disableBlocks )
        {
            m_sendBlock = YOJIMBO_NEW( *m_allocator, SendBlockData, *m_allocator, m_config.GetMaxFragmentsPerBlock() ); 
            m_receiveBlock = YOJIMBO_NEW( *m_allocator, ReceiveBlockData, *m_allocator, m_config.maxBlockSize, m_config.GetMaxFragmentsPerBlock() );
        }
        else
        {
            m_sendBlock = NULL;
            m_receiveBlock = NULL;
        }

        Reset();
    }

    ReliableOrderedChannel::~ReliableOrderedChannel()
    {
        Reset();

        YOJIMBO_DELETE( *m_allocator, SendBlockData, m_sendBlock );
        YOJIMBO_DELETE( *m_allocator, ReceiveBlockData, m_receiveBlock );
        YOJIMBO_DELETE( *m_allocator, SequenceBuffer<SentPacketEntry>, m_sentPackets );
        YOJIMBO_DELETE( *m_allocator, SequenceBuffer<MessageSendQueueEntry>, m_messageSendQueue );
        YOJIMBO_DELETE( *m_allocator, SequenceBuffer<MessageReceiveQueueEntry>, m_messageReceiveQueue );
        
        YOJIMBO_FREE( *m_allocator, m_sentPacketMessageIds );

        m_sentPacketMessageIds = NULL;
    }

    void ReliableOrderedChannel::Reset()
    {
        SetErrorLevel( CHANNEL_ERROR_NONE );

        m_sendMessageId = 0;
        m_receiveMessageId = 0;
        m_oldestUnackedMessageId = 0;

        for ( int i = 0; i < m_messageSendQueue->GetSize(); ++i )
        {
            MessageSendQueueEntry * entry = m_messageSendQueue->GetAtIndex( i );
            if ( entry && entry->message )
                m_messageFactory->ReleaseMessage( entry->message );
        }

        for ( int i = 0; i < m_messageReceiveQueue->GetSize(); ++i )
        {
            MessageReceiveQueueEntry * entry = m_messageReceiveQueue->GetAtIndex( i );
            if ( entry && entry->message )
                m_messageFactory->ReleaseMessage( entry->message );
        }

        m_sentPackets->Reset();
        m_messageSendQueue->Reset();
        m_messageReceiveQueue->Reset();

        if ( m_sendBlock )
        {
            m_sendBlock->Reset();
        }

        if ( m_receiveBlock )
        {
            m_receiveBlock->Reset();
            if ( m_receiveBlock->blockMessage )
            {
                m_messageFactory->ReleaseMessage( m_receiveBlock->blockMessage );
                m_receiveBlock->blockMessage = NULL;
            }
        }

        ResetCounters();
    }

#undef SendMessage

    bool ReliableOrderedChannel::CanSendMessage() const
    {
        yojimbo_assert( m_messageSendQueue );
        return m_messageSendQueue->Available( m_sendMessageId );
    }

    void ReliableOrderedChannel::SendMessage( Message * message, void *context )
    {
        yojimbo_assert( message );
        
        yojimbo_assert( CanSendMessage() );

        if ( GetErrorLevel() != CHANNEL_ERROR_NONE )
        {
            m_messageFactory->ReleaseMessage( message );
            return;
        }

        if ( !CanSendMessage() )
        {
            // Increase your send queue size!
            SetErrorLevel( CHANNEL_ERROR_SEND_QUEUE_FULL );
            m_messageFactory->ReleaseMessage( message );
            return;
        }

        yojimbo_assert( !( message->IsBlockMessage() && m_config.disableBlocks ) );

        if ( message->IsBlockMessage() && m_config.disableBlocks )
        {
            // You tried to send a block message, but block messages are disabled for this channel!
            SetErrorLevel( CHANNEL_ERROR_BLOCKS_DISABLED );
            m_messageFactory->ReleaseMessage( message );
            return;
        }

        message->SetId( m_sendMessageId );

        MessageSendQueueEntry * entry = m_messageSendQueue->Insert( m_sendMessageId );

        yojimbo_assert( entry );

        entry->block = message->IsBlockMessage();
        entry->message = message;
        entry->measuredBits = 0;
        entry->timeLastSent = -1.0;

        if ( message->IsBlockMessage() )
        {
            yojimbo_assert( ((BlockMessage*)message)->GetBlockSize() > 0 );
            yojimbo_assert( ((BlockMessage*)message)->GetBlockSize() <= m_config.maxBlockSize );
        }

        MeasureStream measureStream;
		measureStream.SetContext( context );
        measureStream.SetAllocator( &m_messageFactory->GetAllocator() );
        message->SerializeInternal( measureStream );
        entry->measuredBits = measureStream.GetBitsProcessed();
        m_counters[CHANNEL_COUNTER_MESSAGES_SENT]++;
        m_sendMessageId++;
    }

    Message * ReliableOrderedChannel::ReceiveMessage()
    {
        if ( GetErrorLevel() != CHANNEL_ERROR_NONE )
            return NULL;

        MessageReceiveQueueEntry * entry = m_messageReceiveQueue->Find( m_receiveMessageId );
        if ( !entry )
            return NULL;

        Message * message = entry->message;
        yojimbo_assert( message );
        yojimbo_assert( message->GetId() == m_receiveMessageId );
        m_messageReceiveQueue->Remove( m_receiveMessageId );
        m_counters[CHANNEL_COUNTER_MESSAGES_RECEIVED]++;
        m_receiveMessageId++;

        return message;
    }

    void ReliableOrderedChannel::AdvanceTime( double time )
    {
        m_time = time;
    }
    
    int ReliableOrderedChannel::GetPacketData( void *context, ChannelPacketData & packetData, uint16_t packetSequence, int availableBits )
    {
        if ( !HasMessagesToSend() )
            return 0;

        if ( SendingBlockMessage() )
        {
            if (m_config.blockFragmentSize * 8 > availableBits)
                return 0;

            uint16_t messageId;
            uint16_t fragmentId;
            int fragmentBytes;
            int numFragments;
            int messageType;

            uint8_t * fragmentData = GetFragmentToSend( messageId, fragmentId, fragmentBytes, numFragments, messageType );

            if ( fragmentData )
            {
                const int fragmentBits = GetFragmentPacketData( packetData, messageId, fragmentId, fragmentData, fragmentBytes, numFragments, messageType );
                AddFragmentPacketEntry( messageId, fragmentId, packetSequence );
                return fragmentBits;
            }
        }
        else
        {
            int numMessageIds = 0;
            uint16_t * messageIds = (uint16_t*) alloca( m_config.maxMessagesPerPacket * sizeof( uint16_t ) );
            const int messageBits = GetMessagesToSend( messageIds, numMessageIds, availableBits, context );

            if ( numMessageIds > 0 )
            {
                GetMessagePacketData( packetData, messageIds, numMessageIds );
                AddMessagePacketEntry( messageIds, numMessageIds, packetSequence );
                return messageBits;
            }
        }

        return 0;
    }

    bool ReliableOrderedChannel::HasMessagesToSend() const
    {
        return m_oldestUnackedMessageId != m_sendMessageId;
    }

    int ReliableOrderedChannel::GetMessagesToSend( uint16_t * messageIds, int & numMessageIds, int availableBits, void *context )
    {
        yojimbo_assert( HasMessagesToSend() );

        numMessageIds = 0;

        if ( m_config.packetBudget > 0 )
            availableBits = yojimbo_min( m_config.packetBudget * 8, availableBits );

        const int giveUpBits = 4 * 8;
        const int messageTypeBits = bits_required( 0, m_messageFactory->GetNumTypes() - 1 );
        const int messageLimit = yojimbo_min( m_config.messageSendQueueSize, m_config.messageReceiveQueueSize );
        uint16_t previousMessageId = 0;
        int usedBits = ConservativeMessageHeaderBits;
        int giveUpCounter = 0;
        const int maxBits = availableBits;

        for ( int i = 0; i < messageLimit; ++i )
        {
            if ( availableBits - usedBits < giveUpBits )
                break;

            if ( giveUpCounter > m_config.messageSendQueueSize )
                break;

            uint16_t messageId = m_oldestUnackedMessageId + i;
            MessageSendQueueEntry * entry = m_messageSendQueue->Find( messageId );
            if ( !entry )
                continue;

            if ( entry->block )
                break;

            // Increase your max packet size!
            yojimbo_assert( entry->measuredBits <= maxBits );
            
            if ( entry->timeLastSent + m_config.messageResendTime <= m_time && availableBits >= (int) entry->measuredBits )
            {                
                int messageBits = entry->measuredBits + messageTypeBits;
                
                if ( numMessageIds == 0 )
                {
                    messageBits += 16;
                }
                else
                {
                    MeasureStream stream;
                    stream.SetContext( context );
                    stream.SetAllocator( &m_messageFactory->GetAllocator() );
                    serialize_sequence_relative_internal( stream, previousMessageId, messageId );
                    messageBits += stream.GetBitsProcessed();
                }

                if ( usedBits + messageBits > availableBits )
                {
                    giveUpCounter++;
                    continue;
                }

                usedBits += messageBits;
                messageIds[numMessageIds++] = messageId;
                previousMessageId = messageId;
                entry->timeLastSent = m_time;
            }

            if ( numMessageIds == m_config.maxMessagesPerPacket )
                break;
        }

        return usedBits;
    }

    void ReliableOrderedChannel::GetMessagePacketData( ChannelPacketData & packetData, const uint16_t * messageIds, int numMessageIds )
    {
        yojimbo_assert( messageIds );

        packetData.Initialize();
        packetData.channelIndex = GetChannelIndex();
        packetData.message.numMessages = numMessageIds;
        
        if ( numMessageIds == 0 )
            return;

        packetData.message.messages = (Message**) YOJIMBO_ALLOCATE( m_messageFactory->GetAllocator(), sizeof( Message* ) * numMessageIds );

        for ( int i = 0; i < numMessageIds; ++i )
        {
            MessageSendQueueEntry * entry = m_messageSendQueue->Find( messageIds[i] );
            yojimbo_assert( entry );
            yojimbo_assert( entry->message );
            yojimbo_assert( entry->message->GetRefCount() > 0 );
            packetData.message.messages[i] = entry->message;
            m_messageFactory->AcquireMessage( packetData.message.messages[i] );
        }
    }

    void ReliableOrderedChannel::AddMessagePacketEntry( const uint16_t * messageIds, int numMessageIds, uint16_t sequence )
    {
        SentPacketEntry * sentPacket = m_sentPackets->Insert( sequence, true );
        yojimbo_assert( sentPacket );
        if ( sentPacket )
        {
            sentPacket->acked = 0;
            sentPacket->block = 0;
            sentPacket->timeSent = m_time;
            sentPacket->messageIds = &m_sentPacketMessageIds[ ( sequence % m_config.sentPacketBufferSize ) * m_config.maxMessagesPerPacket ];
            sentPacket->numMessageIds = numMessageIds;            
            for ( int i = 0; i < numMessageIds; ++i )
            {
                sentPacket->messageIds[i] = messageIds[i];
            }
        }
    }

    void ReliableOrderedChannel::ProcessPacketMessages( int numMessages, Message ** messages )
    {
        const uint16_t minMessageId = m_receiveMessageId;
        const uint16_t maxMessageId = m_receiveMessageId + m_config.messageReceiveQueueSize - 1;

        for ( int i = 0; i < (int) numMessages; ++i )
        {
            Message * message = messages[i];

            yojimbo_assert( message );  

            const uint16_t messageId = message->GetId();

            if ( yojimbo_sequence_less_than( messageId, minMessageId ) )
                continue;

            if ( yojimbo_sequence_greater_than( messageId, maxMessageId ) )
            {
                // Did you forget to dequeue messages on the receiver?
                SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            if ( m_messageReceiveQueue->Find( messageId ) )
                continue;

            yojimbo_assert( !m_messageReceiveQueue->GetAtIndex( m_messageReceiveQueue->GetIndex( messageId ) ) );

            MessageReceiveQueueEntry * entry = m_messageReceiveQueue->Insert( messageId );
            if ( !entry )
            {
                // For some reason we can't insert the message in the receive queue
                SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            entry->message = message;

            m_messageFactory->AcquireMessage( message );
        }
    }

    void ReliableOrderedChannel::ProcessPacketData( const ChannelPacketData & packetData, uint16_t packetSequence )
    {
        if ( m_errorLevel != CHANNEL_ERROR_NONE )
            return;
        
        if ( packetData.messageFailedToSerialize )
        {
            // A message failed to serialize read for some reason, eg. mismatched read/write.
            SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
            return;
        }

        (void)packetSequence;

        if ( packetData.blockMessage )
        {
            ProcessPacketFragment( packetData.block.messageType, 
                                   packetData.block.messageId, 
                                   packetData.block.numFragments, 
                                   packetData.block.fragmentId, 
                                   packetData.block.fragmentData, 
                                   packetData.block.fragmentSize, 
                                   packetData.block.message );
        }
        else
        {
            ProcessPacketMessages( packetData.message.numMessages, packetData.message.messages );
        }
    }

    void ReliableOrderedChannel::ProcessAck( uint16_t ack )
    {
        SentPacketEntry * sentPacketEntry = m_sentPackets->Find( ack );
        if ( !sentPacketEntry )
            return;

        yojimbo_assert( !sentPacketEntry->acked );

        for ( int i = 0; i < (int) sentPacketEntry->numMessageIds; ++i )
        {
            const uint16_t messageId = sentPacketEntry->messageIds[i];
            MessageSendQueueEntry * sendQueueEntry = m_messageSendQueue->Find( messageId );
            if ( sendQueueEntry )
            {
                yojimbo_assert( sendQueueEntry->message );
                yojimbo_assert( sendQueueEntry->message->GetId() == messageId );
                m_messageFactory->ReleaseMessage( sendQueueEntry->message );
                m_messageSendQueue->Remove( messageId );
                UpdateOldestUnackedMessageId();
            }
        }

        if ( !m_config.disableBlocks && sentPacketEntry->block && m_sendBlock->active && m_sendBlock->blockMessageId == sentPacketEntry->blockMessageId )
        {        
            const int messageId = sentPacketEntry->blockMessageId;
            const int fragmentId = sentPacketEntry->blockFragmentId;

            if ( !m_sendBlock->ackedFragment->GetBit( fragmentId ) )
            {
                m_sendBlock->ackedFragment->SetBit( fragmentId );
                m_sendBlock->numAckedFragments++;
                if ( m_sendBlock->numAckedFragments == m_sendBlock->numFragments )
                {
                    m_sendBlock->active = false;
                    MessageSendQueueEntry * sendQueueEntry = m_messageSendQueue->Find( messageId );
                    yojimbo_assert( sendQueueEntry );
                    m_messageFactory->ReleaseMessage( sendQueueEntry->message );
                    m_messageSendQueue->Remove( messageId );
                    UpdateOldestUnackedMessageId();
                }
            }
        }
    }

    void ReliableOrderedChannel::UpdateOldestUnackedMessageId()
    {
        const uint16_t stopMessageId = m_messageSendQueue->GetSequence();

        while ( true )
        {
            if ( m_oldestUnackedMessageId == stopMessageId || m_messageSendQueue->Find( m_oldestUnackedMessageId ) )
            {
                break;
            }
            ++m_oldestUnackedMessageId;
        }

        yojimbo_assert( !yojimbo_sequence_greater_than( m_oldestUnackedMessageId, stopMessageId ) );
    }

    bool ReliableOrderedChannel::SendingBlockMessage()
    {
        yojimbo_assert( HasMessagesToSend() );

        MessageSendQueueEntry * entry = m_messageSendQueue->Find( m_oldestUnackedMessageId );

        return entry ? entry->block : false;
    }

    uint8_t * ReliableOrderedChannel::GetFragmentToSend( uint16_t & messageId, uint16_t & fragmentId, int & fragmentBytes, int & numFragments, int & messageType )
    {
        MessageSendQueueEntry * entry = m_messageSendQueue->Find( m_oldestUnackedMessageId );

        yojimbo_assert( entry );
        yojimbo_assert( entry->block );

        BlockMessage * blockMessage = (BlockMessage*) entry->message;

        yojimbo_assert( blockMessage );

        messageId = blockMessage->GetId();

        const int blockSize = blockMessage->GetBlockSize();

        if ( !m_sendBlock->active )
        {
            // start sending this block

            m_sendBlock->active = true;
            m_sendBlock->blockSize = blockSize;
            m_sendBlock->blockMessageId = messageId;
            m_sendBlock->numFragments = (int) ceil( blockSize / float( m_config.blockFragmentSize ) );
            m_sendBlock->numAckedFragments = 0;

            const int MaxFragmentsPerBlock = m_config.GetMaxFragmentsPerBlock();

            yojimbo_assert( m_sendBlock->numFragments > 0 );
            yojimbo_assert( m_sendBlock->numFragments <= MaxFragmentsPerBlock );

            m_sendBlock->ackedFragment->Clear();

            for ( int i = 0; i < MaxFragmentsPerBlock; ++i )
                m_sendBlock->fragmentSendTime[i] = -1.0;
        }

        numFragments = m_sendBlock->numFragments;

        // find the next fragment to send (there may not be one)

        fragmentId = 0xFFFF;

        for ( int i = 0; i < m_sendBlock->numFragments; ++i )
        {
            if ( !m_sendBlock->ackedFragment->GetBit( i ) && m_sendBlock->fragmentSendTime[i] + m_config.blockFragmentResendTime < m_time )
            {
                fragmentId = uint16_t( i );
                break;
            }
        }

        if ( fragmentId == 0xFFFF )
            return NULL;

        // allocate and return a copy of the fragment data

        messageType = blockMessage->GetType();

        fragmentBytes = m_config.blockFragmentSize;
        
        const int fragmentRemainder = blockSize % m_config.blockFragmentSize;

        if ( fragmentRemainder && fragmentId == m_sendBlock->numFragments - 1 )
            fragmentBytes = fragmentRemainder;

        uint8_t * fragmentData = (uint8_t*) YOJIMBO_ALLOCATE( m_messageFactory->GetAllocator(), fragmentBytes );

        if ( fragmentData )
        {
            memcpy( fragmentData, blockMessage->GetBlockData() + fragmentId * m_config.blockFragmentSize, fragmentBytes );

            m_sendBlock->fragmentSendTime[fragmentId] = m_time;
        }

        return fragmentData;
    }

    int ReliableOrderedChannel::GetFragmentPacketData( ChannelPacketData & packetData, 
                                                       uint16_t messageId, 
                                                       uint16_t fragmentId, 
                                                       uint8_t * fragmentData, 
                                                       int fragmentSize, 
                                                       int numFragments, 
                                                       int messageType )
    {
        packetData.Initialize();

        packetData.channelIndex = GetChannelIndex();

        packetData.blockMessage = 1;

        packetData.block.fragmentData = fragmentData;
        packetData.block.messageId = messageId;
        packetData.block.fragmentId = fragmentId;
        packetData.block.fragmentSize = fragmentSize;
        packetData.block.numFragments = numFragments;
        packetData.block.messageType = messageType;

        const int messageTypeBits = bits_required( 0, m_messageFactory->GetNumTypes() - 1 );

        int fragmentBits = ConservativeFragmentHeaderBits + fragmentSize * 8;

        if ( fragmentId == 0 )
        {
            MessageSendQueueEntry * entry = m_messageSendQueue->Find( packetData.block.messageId );

            yojimbo_assert( entry );
            yojimbo_assert( entry->message );

            packetData.block.message = (BlockMessage*) entry->message;

            m_messageFactory->AcquireMessage( packetData.block.message );

            fragmentBits += entry->measuredBits + messageTypeBits;
        }
        else
        {
            packetData.block.message = NULL;
        }

        return fragmentBits;
    }

    void ReliableOrderedChannel::AddFragmentPacketEntry( uint16_t messageId, uint16_t fragmentId, uint16_t sequence )
    {
        SentPacketEntry * sentPacket = m_sentPackets->Insert( sequence, true );
        yojimbo_assert( sentPacket );
        if ( sentPacket )
        {
            sentPacket->numMessageIds = 0;
            sentPacket->messageIds = NULL;
            sentPacket->timeSent = m_time;
            sentPacket->acked = 0;
            sentPacket->block = 1;
            sentPacket->blockMessageId = messageId;
            sentPacket->blockFragmentId = fragmentId;
        }
    }

    void ReliableOrderedChannel::ProcessPacketFragment( int messageType, 
                                                        uint16_t messageId, 
                                                        int numFragments, 
                                                        uint16_t fragmentId, 
                                                        const uint8_t * fragmentData, 
                                                        int fragmentBytes, 
                                                        BlockMessage * blockMessage )
    {  
        yojimbo_assert( !m_config.disableBlocks );

        if ( fragmentData )
        {
            const uint16_t expectedMessageId = m_messageReceiveQueue->GetSequence();
            if ( messageId != expectedMessageId )
                return;

            // start receiving a new block

            if ( !m_receiveBlock->active )
            {
                yojimbo_assert( numFragments >= 0 );
                yojimbo_assert( numFragments <= m_config.GetMaxFragmentsPerBlock() );

                m_receiveBlock->active = true;
                m_receiveBlock->numFragments = numFragments;
                m_receiveBlock->numReceivedFragments = 0;
                m_receiveBlock->messageId = messageId;
                m_receiveBlock->blockSize = 0;
                m_receiveBlock->receivedFragment->Clear();
            }

            // validate fragment

            if ( fragmentId >= m_receiveBlock->numFragments )
            {
                // The fragment id is out of range.
                SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            if ( numFragments != m_receiveBlock->numFragments )
            {
                // The number of fragments is out of range.
                SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            // receive the fragment

            if ( !m_receiveBlock->receivedFragment->GetBit( fragmentId ) )
            {
                m_receiveBlock->receivedFragment->SetBit( fragmentId );

                memcpy( m_receiveBlock->blockData + fragmentId * m_config.blockFragmentSize, fragmentData, fragmentBytes );

                if ( fragmentId == 0 )
                {
                    m_receiveBlock->messageType = messageType;
                }

                if ( fragmentId == m_receiveBlock->numFragments - 1 )
                {
                    m_receiveBlock->blockSize = ( m_receiveBlock->numFragments - 1 ) * m_config.blockFragmentSize + fragmentBytes;

                    if ( m_receiveBlock->blockSize > (uint32_t) m_config.maxBlockSize )
                    {
                        // The block size is outside range
                        SetErrorLevel( CHANNEL_ERROR_DESYNC );
                        return;
                    }
                }

                m_receiveBlock->numReceivedFragments++;

                if ( fragmentId == 0 )
                {
                    // save block message (sent with fragment 0)
                    m_receiveBlock->blockMessage = blockMessage;
                    m_messageFactory->AcquireMessage( m_receiveBlock->blockMessage );
                }

                if ( m_receiveBlock->numReceivedFragments == m_receiveBlock->numFragments )
                {
                    // finished receiving block

                    if ( m_messageReceiveQueue->GetAtIndex( m_messageReceiveQueue->GetIndex( messageId ) ) )
                    {
                        // Did you forget to dequeue messages on the receiver?
                        SetErrorLevel( CHANNEL_ERROR_DESYNC );
                        return;
                    }

                    blockMessage = m_receiveBlock->blockMessage;

                    yojimbo_assert( blockMessage );

                    uint8_t * blockData = (uint8_t*) YOJIMBO_ALLOCATE( m_messageFactory->GetAllocator(), m_receiveBlock->blockSize );

                    if ( !blockData )
                    {
                        // Not enough memory to allocate block data
                        SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
                        return;
                    }

                    memcpy( blockData, m_receiveBlock->blockData, m_receiveBlock->blockSize );

                    blockMessage->AttachBlock( m_messageFactory->GetAllocator(), blockData, m_receiveBlock->blockSize );

                    blockMessage->SetId( messageId );

                    MessageReceiveQueueEntry * entry = m_messageReceiveQueue->Insert( messageId );
                    yojimbo_assert( entry );
                    entry->message = blockMessage;
                    m_receiveBlock->active = false;
                    m_receiveBlock->blockMessage = NULL;
                }
            }
        }
    }

    // ------------------------------------------------

    UnreliableUnorderedChannel::UnreliableUnorderedChannel( Allocator & allocator, 
                                                            MessageFactory & messageFactory, 
                                                            const ChannelConfig & config, 
                                                            int channelIndex, 
                                                            double time ) 
        : Channel( allocator, 
                   messageFactory, 
                   config, 
                   channelIndex, 
                   time )
    {
        yojimbo_assert( config.type == CHANNEL_TYPE_UNRELIABLE_UNORDERED );
        m_messageSendQueue = YOJIMBO_NEW( *m_allocator, Queue<Message*>, *m_allocator, m_config.messageSendQueueSize );
        m_messageReceiveQueue = YOJIMBO_NEW( *m_allocator, Queue<Message*>, *m_allocator, m_config.messageReceiveQueueSize );
        Reset();
    }

    UnreliableUnorderedChannel::~UnreliableUnorderedChannel()
    {
        Reset();
        YOJIMBO_DELETE( *m_allocator, Queue<Message*>, m_messageSendQueue );
        YOJIMBO_DELETE( *m_allocator, Queue<Message*>, m_messageReceiveQueue );
    }

    void UnreliableUnorderedChannel::Reset()
    {
        SetErrorLevel( CHANNEL_ERROR_NONE );

        for ( int i = 0; i < m_messageSendQueue->GetNumEntries(); ++i )
            m_messageFactory->ReleaseMessage( (*m_messageSendQueue)[i] );

        for ( int i = 0; i < m_messageReceiveQueue->GetNumEntries(); ++i )
            m_messageFactory->ReleaseMessage( (*m_messageReceiveQueue)[i] );

        m_messageSendQueue->Clear();
        m_messageReceiveQueue->Clear();
  
        ResetCounters();
    }

    bool UnreliableUnorderedChannel::CanSendMessage() const
    {
        yojimbo_assert( m_messageSendQueue );
        return !m_messageSendQueue->IsFull();
    }

    bool UnreliableUnorderedChannel::HasMessagesToSend() const
    {
        yojimbo_assert( m_messageSendQueue );
        return !m_messageSendQueue->IsEmpty();
    }

    void UnreliableUnorderedChannel::SendMessage( Message * message, void *context )
    {
        yojimbo_assert( message );
        yojimbo_assert( CanSendMessage() );
		(void)context;

        if ( GetErrorLevel() != CHANNEL_ERROR_NONE )
        {
            m_messageFactory->ReleaseMessage( message );
            return;
        }

        if ( !CanSendMessage() )
        {
            SetErrorLevel( CHANNEL_ERROR_SEND_QUEUE_FULL );
            m_messageFactory->ReleaseMessage( message );
            return;
        }

        yojimbo_assert( !( message->IsBlockMessage() && m_config.disableBlocks ) );

        if ( message->IsBlockMessage() && m_config.disableBlocks )
        {
            SetErrorLevel( CHANNEL_ERROR_BLOCKS_DISABLED );
            m_messageFactory->ReleaseMessage( message );
            return;
        }

        if ( message->IsBlockMessage() )
        {
            yojimbo_assert( ((BlockMessage*)message)->GetBlockSize() > 0 );
            yojimbo_assert( ((BlockMessage*)message)->GetBlockSize() <= m_config.maxBlockSize );
        }

        m_messageSendQueue->Push( message );

        m_counters[CHANNEL_COUNTER_MESSAGES_SENT]++;
    }

    Message * UnreliableUnorderedChannel::ReceiveMessage()
    {
        if ( GetErrorLevel() != CHANNEL_ERROR_NONE )
            return NULL;

        if ( m_messageReceiveQueue->IsEmpty() )
            return NULL;

        m_counters[CHANNEL_COUNTER_MESSAGES_RECEIVED]++;

        return m_messageReceiveQueue->Pop();
    }

    void UnreliableUnorderedChannel::AdvanceTime( double time )
    {
        (void) time;
    }
    
    int UnreliableUnorderedChannel::GetPacketData( void *context, ChannelPacketData & packetData, uint16_t packetSequence, int availableBits )
    {
        (void) packetSequence;

        if ( m_messageSendQueue->IsEmpty() )
            return 0;

        if ( m_config.packetBudget > 0 )
            availableBits = yojimbo_min( m_config.packetBudget * 8, availableBits );

        const int giveUpBits = 4 * 8;

        const int messageTypeBits = bits_required( 0, m_messageFactory->GetNumTypes() - 1 );

        int usedBits = ConservativeMessageHeaderBits;
        int numMessages = 0;
        Message ** messages = (Message**) alloca( sizeof( Message* ) * m_config.maxMessagesPerPacket );

        while ( true )
        {
            if ( m_messageSendQueue->IsEmpty() )
                break;

            if ( availableBits - usedBits < giveUpBits )
                break;

            if ( numMessages == m_config.maxMessagesPerPacket )
                break;

            Message * message = m_messageSendQueue->Pop();

            yojimbo_assert( message );

            MeasureStream measureStream;
			measureStream.SetContext( context );
            measureStream.SetAllocator( &m_messageFactory->GetAllocator() );
            message->SerializeInternal( measureStream );
            
            if ( message->IsBlockMessage() )
            {
                BlockMessage * blockMessage = (BlockMessage*) message;
                SerializeMessageBlock( measureStream, *m_messageFactory, blockMessage, m_config.maxBlockSize );
            }

            const int messageBits = messageTypeBits + measureStream.GetBitsProcessed();
            
            if ( usedBits + messageBits > availableBits )
            {
                m_messageFactory->ReleaseMessage( message );
                continue;
            }

            usedBits += messageBits;        

            yojimbo_assert( usedBits <= availableBits );

            messages[numMessages++] = message;
        }

        if ( numMessages == 0 )
            return 0;

        Allocator & allocator = m_messageFactory->GetAllocator();

        packetData.Initialize();
        packetData.channelIndex = GetChannelIndex();
        packetData.message.numMessages = numMessages;
        packetData.message.messages = (Message**) YOJIMBO_ALLOCATE( allocator, sizeof( Message* ) * numMessages );
        for ( int i = 0; i < numMessages; ++i )
        {
            packetData.message.messages[i] = messages[i];
        }

        return usedBits;
    }

    void UnreliableUnorderedChannel::ProcessPacketData( const ChannelPacketData & packetData, uint16_t packetSequence )
    {
        if ( m_errorLevel != CHANNEL_ERROR_NONE )
            return;
        
        if ( packetData.messageFailedToSerialize )
        {
            SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
            return;
        }

        for ( int i = 0; i < (int) packetData.message.numMessages; ++i )
        {
            Message * message = packetData.message.messages[i];
            yojimbo_assert( message );  
            message->SetId( packetSequence );
            if ( !m_messageReceiveQueue->IsFull() )
            {
                m_messageFactory->AcquireMessage( message );
                m_messageReceiveQueue->Push( message );
            }
        }
    }

    void UnreliableUnorderedChannel::ProcessAck( uint16_t ack )
    {
        (void) ack;
    }
}

// ---------------------------------------------------------------------------------

namespace yojimbo
{
    struct ConnectionPacket
    {
        int numChannelEntries;
        ChannelPacketData * channelEntry;
        MessageFactory * messageFactory;

        ConnectionPacket()
        {
            messageFactory = NULL;
            numChannelEntries = 0;
            channelEntry = NULL;
        }

        ~ConnectionPacket()
        {
            if ( messageFactory )
            {
                for ( int i = 0; i < numChannelEntries; ++i )
                {
                    channelEntry[i].Free( *messageFactory );
                }
                YOJIMBO_FREE( messageFactory->GetAllocator(), channelEntry );
                messageFactory = NULL;
            }        
        }

        bool AllocateChannelData( MessageFactory & _messageFactory, int numEntries )
        {
            yojimbo_assert( numEntries > 0 );
            yojimbo_assert( numEntries <= MaxChannels );
            messageFactory = &_messageFactory;
            Allocator & allocator = messageFactory->GetAllocator();
            channelEntry = (ChannelPacketData*) YOJIMBO_ALLOCATE( allocator, sizeof( ChannelPacketData ) * numEntries );
            if ( channelEntry == NULL )
                return false;
            for ( int i = 0; i < numEntries; ++i )
            {
                channelEntry[i].Initialize();
            }
            numChannelEntries = numEntries;
            return true;
        }

        template <typename Stream> bool Serialize( Stream & stream, MessageFactory & messageFactory, const ConnectionConfig & connectionConfig )
        {
            const int numChannels = connectionConfig.numChannels;
            serialize_int( stream, numChannelEntries, 0, connectionConfig.numChannels );
#if YOJIMBO_DEBUG_MESSAGE_BUDGET
            yojimbo_assert( stream.GetBitsProcessed() <= ConservativePacketHeaderBits );
#endif // #if YOJIMBO_DEBUG_MESSAGE_BUDGET
            if ( numChannelEntries > 0 )
            {
                if ( Stream::IsReading )
                {
                    if ( !AllocateChannelData( messageFactory, numChannelEntries ) )
                    {
                        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate channel data (ConnectionPacket)\n" );
                        return false;
                    }
                    for ( int i = 0; i < numChannelEntries; ++i )
                    {
                        yojimbo_assert( channelEntry[i].messageFailedToSerialize == 0 );
                    }
                }
                for ( int i = 0; i < numChannelEntries; ++i )
                {
                    yojimbo_assert( channelEntry[i].messageFailedToSerialize == 0 );
                    if ( !channelEntry[i].SerializeInternal( stream, messageFactory, connectionConfig.channel, numChannels ) )
                    {
                        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize channel %d\n", i );
                        return false;
                    }
                }
            }
            return true;
        }

        bool SerializeInternal( ReadStream & stream, MessageFactory & _messageFactory, const ConnectionConfig & connectionConfig )
        {
            return Serialize( stream, _messageFactory, connectionConfig );
        }

        bool SerializeInternal( WriteStream & stream, MessageFactory & _messageFactory, const ConnectionConfig & connectionConfig )
        {
            return Serialize( stream, _messageFactory, connectionConfig );            
        }

        bool SerializeInternal( MeasureStream & stream, MessageFactory & _messageFactory, const ConnectionConfig & connectionConfig )
        {
            return Serialize( stream, _messageFactory, connectionConfig );            
        }

    private:

        ConnectionPacket( const ConnectionPacket & other );

        const ConnectionPacket & operator = ( const ConnectionPacket & other );
    };

    // ------------------------------------------------------------------------------

    Connection::Connection( Allocator & allocator, MessageFactory & messageFactory, const ConnectionConfig & connectionConfig, double time ) 
        : m_connectionConfig( connectionConfig )
    {
        m_allocator = &allocator;
        m_messageFactory = &messageFactory;
        m_errorLevel = CONNECTION_ERROR_NONE;
        memset( m_channel, 0, sizeof( m_channel ) );
        yojimbo_assert( m_connectionConfig.numChannels >= 1 );
        yojimbo_assert( m_connectionConfig.numChannels <= MaxChannels );
        for ( int channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex )
        {
            switch ( m_connectionConfig.channel[channelIndex].type )
            {
                case CHANNEL_TYPE_RELIABLE_ORDERED: 
                {
                    m_channel[channelIndex] = YOJIMBO_NEW( *m_allocator, 
                                                           ReliableOrderedChannel, 
                                                           *m_allocator, 
                                                           messageFactory, 
                                                           m_connectionConfig.channel[channelIndex],
                                                           channelIndex, 
                                                           time ); 
                }
                break;

                case CHANNEL_TYPE_UNRELIABLE_UNORDERED: 
                {
                    m_channel[channelIndex] = YOJIMBO_NEW( *m_allocator, 
                                                           UnreliableUnorderedChannel, 
                                                           *m_allocator, 
                                                           messageFactory, 
                                                           m_connectionConfig.channel[channelIndex], 
                                                           channelIndex, 
                                                           time ); 
                }
                break;

                default: 
                    yojimbo_assert( !"unknown channel type" );
            }
        }
    }

    Connection::~Connection()
    {
        yojimbo_assert( m_allocator );
        Reset();
        for ( int i = 0; i < m_connectionConfig.numChannels; ++i )
        {
            YOJIMBO_DELETE( *m_allocator, Channel, m_channel[i] );
        }
        m_allocator = NULL;
    }

    void Connection::Reset()
    {
        m_errorLevel = CONNECTION_ERROR_NONE;
        for ( int i = 0; i < m_connectionConfig.numChannels; ++i )
        {
            m_channel[i]->Reset();
        }
    }

    bool Connection::CanSendMessage( int channelIndex ) const
    {
        yojimbo_assert( channelIndex >= 0 );
        yojimbo_assert( channelIndex < m_connectionConfig.numChannels );
        return m_channel[channelIndex]->CanSendMessage();
    }

    bool Connection::HasMessagesToSend( int channelIndex ) const {
        yojimbo_assert( channelIndex >= 0 );
        yojimbo_assert( channelIndex < m_connectionConfig.numChannels );
        return m_channel[channelIndex]->HasMessagesToSend();
    }

    void Connection::SendMessage( int channelIndex, Message * message, void *context)
    {
        yojimbo_assert( channelIndex >= 0 );
        yojimbo_assert( channelIndex < m_connectionConfig.numChannels );
        return m_channel[channelIndex]->SendMessage( message, context );
    }

    Message * Connection::ReceiveMessage( int channelIndex )
    {
        yojimbo_assert( channelIndex >= 0 );
        yojimbo_assert( channelIndex < m_connectionConfig.numChannels );
        return m_channel[channelIndex]->ReceiveMessage();
    }

    void Connection::ReleaseMessage( Message * message )
    {
        yojimbo_assert( message );
        m_messageFactory->ReleaseMessage( message );
    }

    static int WritePacket( void * context, 
                            MessageFactory & messageFactory, 
                            const ConnectionConfig & connectionConfig, 
                            ConnectionPacket & packet, 
                            uint8_t * buffer, 
                            int bufferSize )
    {
        WriteStream stream( buffer, bufferSize );
        
        stream.SetContext( context );

        stream.SetAllocator( &messageFactory.GetAllocator() );
        
        if ( !packet.SerializeInternal( stream, messageFactory, connectionConfig ) )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: serialize connection packet failed (write packet)\n" );
            return 0;
        }

        stream.Flush();

        return stream.GetBytesProcessed();
    }

    bool Connection::GeneratePacket( void * context, uint16_t packetSequence, uint8_t * packetData, int maxPacketBytes, int & packetBytes )
    {
        ConnectionPacket packet;

        if ( m_connectionConfig.numChannels > 0 )
        {
            int numChannelsWithData = 0;
            bool channelHasData[MaxChannels];
            memset( channelHasData, 0, sizeof( channelHasData ) );
            ChannelPacketData channelData[MaxChannels];
            
            int availableBits = maxPacketBytes * 8 - ConservativePacketHeaderBits;
            
            for ( int channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex )
            {
                int packetDataBits = m_channel[channelIndex]->GetPacketData( context, channelData[channelIndex], packetSequence, availableBits );
                if ( packetDataBits > 0 )
                {
                    availableBits -= ConservativeChannelHeaderBits;
                    availableBits -= packetDataBits;
                    channelHasData[channelIndex] = true;
                    numChannelsWithData++;
                }
            }

            if ( numChannelsWithData > 0 )
            {
                if ( !packet.AllocateChannelData( *m_messageFactory, numChannelsWithData ) )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate channel data\n" );
                    return false;
                }

                int index = 0;

                for ( int channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex )
                {
                    if ( channelHasData[channelIndex] )
                    {
                        memcpy( &packet.channelEntry[index], &channelData[channelIndex], sizeof( ChannelPacketData ) );
                        index++;
                    }
                }
            }
        }

        packetBytes = WritePacket( context, *m_messageFactory, m_connectionConfig, packet, packetData, maxPacketBytes );

        return true;
    }

    static bool ReadPacket( void * context, 
                            MessageFactory & messageFactory, 
                            const ConnectionConfig & connectionConfig, 
                            ConnectionPacket & packet, 
                            const uint8_t * buffer, 
                            int bufferSize )
    {
        yojimbo_assert( buffer );
        yojimbo_assert( bufferSize > 0 );

        ReadStream stream( buffer, bufferSize );
        
        stream.SetContext( context );

        stream.SetAllocator( &messageFactory.GetAllocator() );
        
        if ( !packet.SerializeInternal( stream, messageFactory, connectionConfig ) )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: serialize connection packet failed (read packet)\n" );
            return false;
        }

        return true;
    }

    bool Connection::ProcessPacket( void * context, uint16_t packetSequence, const uint8_t * packetData, int packetBytes )
    {
        if ( m_errorLevel != CONNECTION_ERROR_NONE )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "failed to read packet because connection is in error state\n" );
            return false;
        }

        ConnectionPacket packet;

        if ( !ReadPacket( context, *m_messageFactory, m_connectionConfig, packet, packetData, packetBytes ) )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to read packet\n" );
            m_errorLevel = CONNECTION_ERROR_READ_PACKET_FAILED;
            return false;            
        }

        for ( int i = 0; i < packet.numChannelEntries; ++i )
        {
            const int channelIndex = packet.channelEntry[i].channelIndex;
            yojimbo_assert( channelIndex >= 0 );
            yojimbo_assert( channelIndex <= m_connectionConfig.numChannels );
            m_channel[channelIndex]->ProcessPacketData( packet.channelEntry[i], packetSequence );
            if ( m_channel[channelIndex]->GetErrorLevel() != CHANNEL_ERROR_NONE )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "failed to read packet because channel %d is in error state\n", channelIndex );
                return false;
            }
        }

        return true;
    }

    void Connection::ProcessAcks( const uint16_t * acks, int numAcks )
    {
        for ( int i = 0; i < numAcks; ++i )
        {
            for ( int channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex )
            {
                m_channel[channelIndex]->ProcessAck( acks[i] );
            }
        }
    }

    void Connection::AdvanceTime( double time )
    {
        for ( int i = 0; i < m_connectionConfig.numChannels; ++i )
        {
            m_channel[i]->AdvanceTime( time );

            if ( m_channel[i]->GetErrorLevel() != CHANNEL_ERROR_NONE )
            {
                m_errorLevel = CONNECTION_ERROR_CHANNEL;
                return;
            }
        }
        if ( m_allocator->GetErrorLevel() != ALLOCATOR_ERROR_NONE )
        {
            m_errorLevel = CONNECTION_ERROR_ALLOCATOR;
            return;
        }
        if ( m_messageFactory->GetErrorLevel() != MESSAGE_FACTORY_ERROR_NONE )
        {
            m_errorLevel = CONNECTION_ERROR_MESSAGE_FACTORY;
            return;
        }
    }
}

// ---------------------------------------------------------------------------------

namespace yojimbo
{
    BaseClient::BaseClient( Allocator & allocator, const ClientServerConfig & config, Adapter & adapter, double time ) : m_config( config )
    {
        m_allocator = &allocator;
        m_adapter = &adapter;
        m_time = time;
        m_context = NULL;
        m_clientMemory = NULL;
        m_clientAllocator = NULL;
        m_endpoint = NULL;
        m_connection = NULL;
        m_messageFactory = NULL;
        m_networkSimulator = NULL;
        m_clientState = CLIENT_STATE_DISCONNECTED;
        m_clientIndex = -1;
        m_packetBuffer = (uint8_t*) YOJIMBO_ALLOCATE( allocator, config.maxPacketSize );
    }

    BaseClient::~BaseClient()
    {
        // IMPORTANT: Please disconnect the client before destroying it
        yojimbo_assert( m_clientState <= CLIENT_STATE_DISCONNECTED );
        YOJIMBO_FREE( *m_allocator, m_packetBuffer );
        m_allocator = NULL;
    }

    void BaseClient::Disconnect()
    {
        SetClientState( CLIENT_STATE_DISCONNECTED );
    }

    void BaseClient::AdvanceTime( double time )
    {
        m_time = time;
        if ( m_endpoint )
        {
            m_connection->AdvanceTime( time );
            if ( m_connection->GetErrorLevel() != CONNECTION_ERROR_NONE )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "connection error. disconnecting client\n" );
                Disconnect();
                return;
            }
            reliable_endpoint_update( m_endpoint, m_time );
            int numAcks;
            const uint16_t * acks = reliable_endpoint_get_acks( m_endpoint, &numAcks );
            m_connection->ProcessAcks( acks, numAcks );
            reliable_endpoint_clear_acks( m_endpoint );
        }
        NetworkSimulator * networkSimulator = GetNetworkSimulator();
        if ( networkSimulator )
        {
            networkSimulator->AdvanceTime( time );
        }
    }

    void BaseClient::SetLatency( float milliseconds )
    {
        if ( m_networkSimulator )
        {
            m_networkSimulator->SetLatency( milliseconds );
        }
    }

    void BaseClient::SetJitter( float milliseconds )
    {
        if ( m_networkSimulator )
        {
            m_networkSimulator->SetJitter( milliseconds );
        }
    }

    void BaseClient::SetPacketLoss( float percent )
    {
        if ( m_networkSimulator )
        {
            m_networkSimulator->SetPacketLoss( percent );
        }
    }

    void BaseClient::SetDuplicates( float percent )
    {
        if ( m_networkSimulator )
        {
            m_networkSimulator->SetDuplicates( percent );
        }
    }

    void BaseClient::SetClientState( ClientState clientState )
    {
        m_clientState = clientState;
    }

    void BaseClient::CreateInternal()
    {
        yojimbo_assert( m_allocator );
        yojimbo_assert( m_adapter );
        yojimbo_assert( m_clientMemory == NULL );
        yojimbo_assert( m_clientAllocator == NULL );
        yojimbo_assert( m_messageFactory == NULL );
        m_clientMemory = (uint8_t*) YOJIMBO_ALLOCATE( *m_allocator, m_config.clientMemory );
        m_clientAllocator = m_adapter->CreateAllocator( *m_allocator, m_clientMemory, m_config.clientMemory );
        m_messageFactory = m_adapter->CreateMessageFactory( *m_clientAllocator );
        m_connection = YOJIMBO_NEW( *m_clientAllocator, Connection, *m_clientAllocator, *m_messageFactory, m_config, m_time );
        yojimbo_assert( m_connection );
        if ( m_config.networkSimulator )
        {
            m_networkSimulator = YOJIMBO_NEW( *m_clientAllocator, NetworkSimulator, *m_clientAllocator, m_config.maxSimulatorPackets, m_time );
        }
        reliable_config_t reliable_config;
        reliable_default_config( &reliable_config );
        strcpy( reliable_config.name, "client endpoint" );
        reliable_config.context = (void*) this;
        reliable_config.max_packet_size = m_config.maxPacketSize;
        reliable_config.fragment_above = m_config.fragmentPacketsAbove;
        reliable_config.max_fragments = m_config.maxPacketFragments;
        reliable_config.fragment_size = m_config.packetFragmentSize; 
        reliable_config.ack_buffer_size = m_config.ackedPacketsBufferSize;
        reliable_config.received_packets_buffer_size = m_config.receivedPacketsBufferSize;
        reliable_config.fragment_reassembly_buffer_size = m_config.packetReassemblyBufferSize;
        reliable_config.rtt_smoothing_factor = m_config.rttSmoothingFactor;
        reliable_config.transmit_packet_function = BaseClient::StaticTransmitPacketFunction;
        reliable_config.process_packet_function = BaseClient::StaticProcessPacketFunction;
        reliable_config.allocator_context = m_clientAllocator;
        reliable_config.allocate_function = BaseClient::StaticAllocateFunction;
        reliable_config.free_function = BaseClient::StaticFreeFunction;
        m_endpoint = reliable_endpoint_create( &reliable_config, m_time );
        reliable_endpoint_reset( m_endpoint );
    }

    void BaseClient::DestroyInternal()
    {
        yojimbo_assert( m_allocator );
        if ( m_endpoint )
        {
            reliable_endpoint_destroy( m_endpoint ); 
            m_endpoint = NULL;
        }
        YOJIMBO_DELETE( *m_clientAllocator, NetworkSimulator, m_networkSimulator );
        YOJIMBO_DELETE( *m_clientAllocator, Connection, m_connection );
        YOJIMBO_DELETE( *m_clientAllocator, MessageFactory, m_messageFactory );
        YOJIMBO_DELETE( *m_allocator, Allocator, m_clientAllocator );
        YOJIMBO_FREE( *m_allocator, m_clientMemory );
    }

    void BaseClient::StaticTransmitPacketFunction( void * context, int index, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
    {
        (void) index;
        BaseClient * client = (BaseClient*) context;
        client->TransmitPacketFunction( packetSequence, packetData, packetBytes );
    }
    
    int BaseClient::StaticProcessPacketFunction( void * context, int index, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
    {
        (void) index;
        BaseClient * client = (BaseClient*) context;
        return client->ProcessPacketFunction( packetSequence, packetData, packetBytes );
    }

    void * BaseClient::StaticAllocateFunction( void * context, uint64_t bytes )
    {
        yojimbo_assert( context );
        Allocator * allocator = (Allocator*) context;
        return YOJIMBO_ALLOCATE( *allocator, bytes );
    }
    
    void BaseClient::StaticFreeFunction( void * context, void * pointer )
    {
        yojimbo_assert( context );
        yojimbo_assert( pointer );
        Allocator * allocator = (Allocator*) context;
        YOJIMBO_FREE( *allocator, pointer );
    }

    Message * BaseClient::CreateMessage( int type )
    {
        yojimbo_assert( m_messageFactory );
        return m_messageFactory->CreateMessage( type );
    }

    uint8_t * BaseClient::AllocateBlock( int bytes )
    {
        return (uint8_t*) YOJIMBO_ALLOCATE( *m_clientAllocator, bytes );
    }

    void BaseClient::AttachBlockToMessage( Message * message, uint8_t * block, int bytes )
    {
        yojimbo_assert( message );
        yojimbo_assert( block );
        yojimbo_assert( bytes > 0 );
        yojimbo_assert( message->IsBlockMessage() );
        BlockMessage * blockMessage = (BlockMessage*) message;
        blockMessage->AttachBlock( *m_clientAllocator, block, bytes );
    }

    void BaseClient::FreeBlock( uint8_t * block )
    {
        YOJIMBO_FREE( *m_clientAllocator, block );
    }

    bool BaseClient::CanSendMessage( int channelIndex ) const
    {
        yojimbo_assert( m_connection );
        return m_connection->CanSendMessage( channelIndex );
    }

    bool BaseClient::HasMessagesToSend( int channelIndex ) const
    {
        yojimbo_assert( m_connection );
        return m_connection->HasMessagesToSend( channelIndex );
    }

    void BaseClient::SendMessage( int channelIndex, Message * message )
    {
        yojimbo_assert( m_connection );
        m_connection->SendMessage( channelIndex, message, GetContext() );
    }

    Message * BaseClient::ReceiveMessage( int channelIndex )
    {
        yojimbo_assert( m_connection );
        return m_connection->ReceiveMessage( channelIndex );
    }

    void BaseClient::ReleaseMessage( Message * message )
    {
        yojimbo_assert( m_connection );
        m_connection->ReleaseMessage( message );
    }

    void BaseClient::GetNetworkInfo( NetworkInfo & info ) const
    {
        memset( &info, 0, sizeof( info ) );
        if ( m_connection )
        {
            yojimbo_assert( m_endpoint );
            const uint64_t * counters = reliable_endpoint_counters( m_endpoint );
            info.numPacketsSent = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT];
            info.numPacketsReceived = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
            info.numPacketsAcked = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
            info.RTT = reliable_endpoint_rtt( m_endpoint );
            info.packetLoss = reliable_endpoint_packet_loss( m_endpoint );
            reliable_endpoint_bandwidth( m_endpoint, &info.sentBandwidth, &info.receivedBandwidth, &info.ackedBandwidth );
        }
    }

    // ------------------------------------------------------------------------------------------------------------------

    Client::Client( Allocator & allocator, const Address & address, const ClientServerConfig & config, Adapter & adapter, double time ) 
        : BaseClient( allocator, config, adapter, time ), m_config( config ), m_address( address )
    {
        m_clientId = 0;
        m_client = NULL;
        m_boundAddress = m_address;
    }

    Client::~Client()
    {
        // IMPORTANT: Please disconnect the client before destroying it
        yojimbo_assert( m_client == NULL );
    }

    void Client::InsecureConnect( const uint8_t privateKey[], uint64_t clientId, const Address & address )
    {
        InsecureConnect( privateKey, clientId, &address, 1 );
    }

    void Client::InsecureConnect( const uint8_t privateKey[], uint64_t clientId, const Address serverAddresses[], int numServerAddresses )
    {
        yojimbo_assert( serverAddresses );
        yojimbo_assert( numServerAddresses > 0 );
        yojimbo_assert( numServerAddresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
        Disconnect();
        CreateInternal();
        m_clientId = clientId;
        CreateClient( m_address );
        if ( !m_client )
        {
            Disconnect();
            return;
        }
        uint8_t connectToken[NETCODE_CONNECT_TOKEN_BYTES];
        if ( !GenerateInsecureConnectToken( connectToken, privateKey, clientId, serverAddresses, numServerAddresses ) )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to generate insecure connect token\n" );
            SetClientState( CLIENT_STATE_ERROR );
            return;
        }
        netcode_client_connect( m_client, connectToken );
        SetClientState( CLIENT_STATE_CONNECTING );
    }

    bool Client::GenerateInsecureConnectToken( uint8_t * connectToken, 
                                               const uint8_t privateKey[], 
                                               uint64_t clientId, 
                                               const Address serverAddresses[], 
                                               int numServerAddresses )
    {
        char serverAddressStrings[NETCODE_MAX_SERVERS_PER_CONNECT][MaxAddressLength];
        const char * serverAddressStringPointers[NETCODE_MAX_SERVERS_PER_CONNECT];
        for ( int i = 0; i < numServerAddresses; ++i ) 
        {
            serverAddresses[i].ToString( serverAddressStrings[i], MaxAddressLength );
            serverAddressStringPointers[i] = serverAddressStrings[i];
        }

        uint8_t userData[256];
        memset( &userData, 0, sizeof(userData) );

        return netcode_generate_connect_token( numServerAddresses, 
                                               serverAddressStringPointers, 
                                               serverAddressStringPointers, 
                                               m_config.timeout,
                                               m_config.timeout, 
                                               clientId, 
                                               m_config.protocolId, 
                                               (uint8_t*)privateKey,
                                               &userData[0], 
                                               connectToken ) == NETCODE_OK;
    }

    void Client::Connect( uint64_t clientId, uint8_t * connectToken )
    {
        yojimbo_assert( connectToken );
        Disconnect();
        CreateInternal();
        m_clientId = clientId;
        CreateClient( m_address );
        netcode_client_connect( m_client, connectToken );
        if ( netcode_client_state( m_client ) > NETCODE_CLIENT_STATE_DISCONNECTED )
        {
            SetClientState( CLIENT_STATE_CONNECTING );
        }
        else
        {
            Disconnect();
        }
    }

    void Client::Disconnect()
    {
        BaseClient::Disconnect();
        DestroyClient();
        DestroyInternal();
        m_clientId = 0;
    }

    void Client::SendPackets()
    {
        if ( !IsConnected() )
            return;
        yojimbo_assert( m_client );
        uint8_t * packetData = GetPacketBuffer();
        int packetBytes;
        uint16_t packetSequence = reliable_endpoint_next_packet_sequence( GetEndpoint() );
        if ( GetConnection().GeneratePacket( GetContext(), packetSequence, packetData, m_config.maxPacketSize, packetBytes ) )
        {
            reliable_endpoint_send_packet( GetEndpoint(), packetData, packetBytes );
        }
    }

    void Client::ReceivePackets()
    {
        if ( !IsConnected() )
            return;
        yojimbo_assert( m_client );
        while ( true )
        {
            int packetBytes;
            uint64_t packetSequence;
            uint8_t * packetData = netcode_client_receive_packet( m_client, &packetBytes, &packetSequence );
            if ( !packetData )
                break;
            reliable_endpoint_receive_packet( GetEndpoint(), packetData, packetBytes );
            netcode_client_free_packet( m_client, packetData );
        }
    }

    void Client::AdvanceTime( double time )
    {
        BaseClient::AdvanceTime( time );
        if ( m_client )
        {
            netcode_client_update( m_client, time );
            const int state = netcode_client_state( m_client );
            if ( state < NETCODE_CLIENT_STATE_DISCONNECTED )
            {
                Disconnect();
                SetClientState( CLIENT_STATE_ERROR );
            }
            else if ( state == NETCODE_CLIENT_STATE_DISCONNECTED )
            {
                Disconnect();
                SetClientState( CLIENT_STATE_DISCONNECTED );
            }
            else if ( state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST || state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
            {
                SetClientState( CLIENT_STATE_CONNECTING );
            }
            else
            {
                SetClientState( CLIENT_STATE_CONNECTED );
            }
            NetworkSimulator * networkSimulator = GetNetworkSimulator();
            if ( networkSimulator && networkSimulator->IsActive() )
            {
                uint8_t ** packetData = (uint8_t**) alloca( sizeof( uint8_t*) * m_config.maxSimulatorPackets );
                int * packetBytes = (int*) alloca( sizeof(int) * m_config.maxSimulatorPackets );
                int numPackets = networkSimulator->ReceivePackets( m_config.maxSimulatorPackets, packetData, packetBytes, NULL );
                for ( int i = 0; i < numPackets; ++i )
                {
                    netcode_client_send_packet( m_client, (uint8_t*) packetData[i], packetBytes[i] );
                    YOJIMBO_FREE( networkSimulator->GetAllocator(), packetData[i] );
                }
            }
        }
    }

    int Client::GetClientIndex() const
    {
        return m_client ? netcode_client_index( m_client ) : -1;
    }

    void Client::ConnectLoopback( int clientIndex, uint64_t clientId, int maxClients )
    {
        Disconnect();
        CreateInternal();
        m_clientId = clientId;
        CreateClient( m_address );
        netcode_client_connect_loopback( m_client, clientIndex, maxClients );
        SetClientState( CLIENT_STATE_CONNECTED );
    }

    void Client::DisconnectLoopback()
    {
        netcode_client_disconnect_loopback( m_client );
        BaseClient::Disconnect();
        DestroyClient();
        DestroyInternal();
        m_clientId = 0;
    }

    bool Client::IsLoopback() const
    {
        return netcode_client_loopback( m_client ) != 0;
    }

    void Client::ProcessLoopbackPacket( const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
    {
        netcode_client_process_loopback_packet( m_client, packetData, packetBytes, packetSequence );
    }

    void Client::CreateClient( const Address & address )
    {
        DestroyClient();
        char addressString[MaxAddressLength];
        address.ToString( addressString, MaxAddressLength );

        struct netcode_client_config_t netcodeConfig;
        netcode_default_client_config(&netcodeConfig);
        netcodeConfig.allocator_context             = &GetClientAllocator();
        netcodeConfig.allocate_function             = StaticAllocateFunction;
        netcodeConfig.free_function                 = StaticFreeFunction;
        netcodeConfig.callback_context              = this;
        netcodeConfig.state_change_callback         = StaticStateChangeCallbackFunction;
        netcodeConfig.send_loopback_packet_callback = StaticSendLoopbackPacketCallbackFunction;
        m_client = netcode_client_create(addressString, &netcodeConfig, GetTime());
        
        if ( m_client )
        {
            m_boundAddress.SetPort( netcode_client_get_port( m_client ) );
        }
    }

    void Client::DestroyClient()
    {
        if ( m_client )
        {
            m_boundAddress = m_address;
            netcode_client_destroy( m_client );
            m_client = NULL;
        }
    }

    void Client::StateChangeCallbackFunction( int previous, int current )
    {
        (void) previous;
        (void) current;
    }

    void Client::StaticStateChangeCallbackFunction( void * context, int previous, int current )
    {
        Client * client = (Client*) context;
        client->StateChangeCallbackFunction( previous, current );
    }

    void Client::TransmitPacketFunction( uint16_t packetSequence, uint8_t * packetData, int packetBytes )
    {
        (void) packetSequence;
        NetworkSimulator * networkSimulator = GetNetworkSimulator();
        if ( networkSimulator && networkSimulator->IsActive() )
        {
            networkSimulator->SendPacket( 0, packetData, packetBytes );
        }
        else
        {
            netcode_client_send_packet( m_client, packetData, packetBytes );
        }
    }

    int Client::ProcessPacketFunction( uint16_t packetSequence, uint8_t * packetData, int packetBytes )
    {
        return (int) GetConnection().ProcessPacket( GetContext(), packetSequence, packetData, packetBytes );
    }

    void Client::SendLoopbackPacketCallbackFunction( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
    {
        GetAdapter().ClientSendLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
    }

    void Client::StaticSendLoopbackPacketCallbackFunction( void * context, int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
    {
        Client * client = (Client*) context;
        client->SendLoopbackPacketCallbackFunction( clientIndex, packetData, packetBytes, packetSequence );
    }
}

// ---------------------------------------------------------------------------------

namespace yojimbo
{
    BaseServer::BaseServer( Allocator & allocator, const ClientServerConfig & config, Adapter & adapter, double time ) : m_config( config )
    {
        m_allocator = &allocator;
        m_adapter = &adapter;
        m_context = NULL;
        m_time = time;
        m_running = false;
        m_maxClients = 0;
        m_globalMemory = NULL;
        m_globalAllocator = NULL;
        for ( int i = 0; i < MaxClients; ++i )
        {
            m_clientMemory[i] = NULL;
            m_clientAllocator[i] = NULL;
            m_clientMessageFactory[i] = NULL;
            m_clientConnection[i] = NULL;
            m_clientEndpoint[i] = NULL;
        }
        m_networkSimulator = NULL;
        m_packetBuffer = NULL;
    }

    BaseServer::~BaseServer()
    {
        // IMPORTANT: Please stop the server before destroying it!
        yojimbo_assert( !IsRunning () );
        m_allocator = NULL;
    }

    void BaseServer::SetContext( void * context )
    {
        yojimbo_assert( !IsRunning() );
        m_context = context;
    }

    void BaseServer::Start( int maxClients )
    {
        Stop();
        m_running = true;
        m_maxClients = maxClients;
        yojimbo_assert( !m_globalMemory );
        yojimbo_assert( !m_globalAllocator );
        m_globalMemory = (uint8_t*) YOJIMBO_ALLOCATE( *m_allocator, m_config.serverGlobalMemory );
        m_globalAllocator = m_adapter->CreateAllocator( *m_allocator, m_globalMemory, m_config.serverGlobalMemory );
        yojimbo_assert( m_globalAllocator );
        if ( m_config.networkSimulator )
        {
            m_networkSimulator = YOJIMBO_NEW( *m_globalAllocator, NetworkSimulator, *m_globalAllocator, m_config.maxSimulatorPackets, m_time );
        }
        for ( int i = 0; i < m_maxClients; ++i )
        {
            yojimbo_assert( !m_clientMemory[i] );
            yojimbo_assert( !m_clientAllocator[i] );
            
            m_clientMemory[i] = (uint8_t*) YOJIMBO_ALLOCATE( *m_allocator, m_config.serverPerClientMemory );
            m_clientAllocator[i] = m_adapter->CreateAllocator( *m_allocator, m_clientMemory[i], m_config.serverPerClientMemory );
            yojimbo_assert( m_clientAllocator[i] );
            
            m_clientMessageFactory[i] = m_adapter->CreateMessageFactory( *m_clientAllocator[i] );
            yojimbo_assert( m_clientMessageFactory[i] );
            
            m_clientConnection[i] = YOJIMBO_NEW( *m_clientAllocator[i], Connection, *m_clientAllocator[i], *m_clientMessageFactory[i], m_config, m_time );
            yojimbo_assert( m_clientConnection[i] );

            reliable_config_t reliable_config;
            reliable_default_config( &reliable_config );
            strcpy( reliable_config.name, "server endpoint" );
            reliable_config.context = (void*) this;
            reliable_config.index = i;
            reliable_config.max_packet_size = m_config.maxPacketSize;
            reliable_config.fragment_above = m_config.fragmentPacketsAbove;
            reliable_config.max_fragments = m_config.maxPacketFragments;
            reliable_config.fragment_size = m_config.packetFragmentSize; 
            reliable_config.ack_buffer_size = m_config.ackedPacketsBufferSize;
            reliable_config.received_packets_buffer_size = m_config.receivedPacketsBufferSize;
            reliable_config.fragment_reassembly_buffer_size = m_config.packetReassemblyBufferSize;
            reliable_config.rtt_smoothing_factor = m_config.rttSmoothingFactor;
            reliable_config.transmit_packet_function = BaseServer::StaticTransmitPacketFunction;
            reliable_config.process_packet_function = BaseServer::StaticProcessPacketFunction;
            reliable_config.allocator_context = &GetGlobalAllocator();
            reliable_config.allocate_function = BaseServer::StaticAllocateFunction;
            reliable_config.free_function = BaseServer::StaticFreeFunction;
            m_clientEndpoint[i] = reliable_endpoint_create( &reliable_config, m_time );
            reliable_endpoint_reset( m_clientEndpoint[i] );
        }
        m_packetBuffer = (uint8_t*) YOJIMBO_ALLOCATE( *m_globalAllocator, m_config.maxPacketSize );
    }

    void BaseServer::Stop()
    {
        if ( IsRunning() )
        {
            YOJIMBO_FREE( *m_globalAllocator, m_packetBuffer );
            yojimbo_assert( m_globalMemory );
            yojimbo_assert( m_globalAllocator );
            YOJIMBO_DELETE( *m_globalAllocator, NetworkSimulator, m_networkSimulator );
            for ( int i = 0; i < m_maxClients; ++i )
            {
                yojimbo_assert( m_clientMemory[i] );
                yojimbo_assert( m_clientAllocator[i] );
                yojimbo_assert( m_clientMessageFactory[i] );
                yojimbo_assert( m_clientEndpoint[i] );
                reliable_endpoint_destroy( m_clientEndpoint[i] ); m_clientEndpoint[i] = NULL;
                YOJIMBO_DELETE( *m_clientAllocator[i], Connection, m_clientConnection[i] );
                YOJIMBO_DELETE( *m_clientAllocator[i], MessageFactory, m_clientMessageFactory[i] );
                YOJIMBO_DELETE( *m_allocator, Allocator, m_clientAllocator[i] );
                YOJIMBO_FREE( *m_allocator, m_clientMemory[i] );
            }
            YOJIMBO_DELETE( *m_allocator, Allocator, m_globalAllocator );
            YOJIMBO_FREE( *m_allocator, m_globalMemory );
        }
        m_running = false;
        m_maxClients = 0;
        m_packetBuffer = NULL;
    }

    void BaseServer::AdvanceTime( double time )
    {
        m_time = time;
        if ( IsRunning() )
        {
            for ( int i = 0; i < m_maxClients; ++i )
            {
                m_clientConnection[i]->AdvanceTime( time );
                if ( m_clientConnection[i]->GetErrorLevel() != CONNECTION_ERROR_NONE )
                {
                    yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "client %d connection is in error state. disconnecting client\n", m_clientConnection[i]->GetErrorLevel() );
                    DisconnectClient( i );
                    continue;
                }
                reliable_endpoint_update( m_clientEndpoint[i], m_time );
                int numAcks;
                const uint16_t * acks = reliable_endpoint_get_acks( m_clientEndpoint[i], &numAcks );
                m_clientConnection[i]->ProcessAcks( acks, numAcks );
                reliable_endpoint_clear_acks( m_clientEndpoint[i] );
            }
            NetworkSimulator * networkSimulator = GetNetworkSimulator();
            if ( networkSimulator )
            {
                networkSimulator->AdvanceTime( time );
            }        
        }
    }

    void BaseServer::SetLatency( float milliseconds )
    {
        if ( m_networkSimulator )
        {
            m_networkSimulator->SetLatency( milliseconds );
        }
    }

    void BaseServer::SetJitter( float milliseconds )
    {
        if ( m_networkSimulator )
        {
            m_networkSimulator->SetJitter( milliseconds );
        }
    }

    void BaseServer::SetPacketLoss( float percent )
    {
        if ( m_networkSimulator )
        {
            m_networkSimulator->SetPacketLoss( percent );
        }
    }

    void BaseServer::SetDuplicates( float percent )
    {
        if ( m_networkSimulator )
        {
            m_networkSimulator->SetDuplicates( percent );
        }
    }

    Message * BaseServer::CreateMessage( int clientIndex, int type )
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( m_clientMessageFactory[clientIndex] );
        return m_clientMessageFactory[clientIndex]->CreateMessage( type );
    }

    uint8_t * BaseServer::AllocateBlock( int clientIndex, int bytes )
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( m_clientAllocator[clientIndex] );
        return (uint8_t*) YOJIMBO_ALLOCATE( *m_clientAllocator[clientIndex], bytes );
    }

    void BaseServer::AttachBlockToMessage( int clientIndex, Message * message, uint8_t * block, int bytes )
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( message );
        yojimbo_assert( block );
        yojimbo_assert( bytes > 0 );
        yojimbo_assert( message->IsBlockMessage() );
        BlockMessage * blockMessage = (BlockMessage*) message;
        blockMessage->AttachBlock( *m_clientAllocator[clientIndex], block, bytes );
    }

    void BaseServer::FreeBlock( int clientIndex, uint8_t * block )
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        YOJIMBO_FREE( *m_clientAllocator[clientIndex], block );
    }

    bool BaseServer::CanSendMessage( int clientIndex, int channelIndex ) const
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( m_clientConnection[clientIndex] );
        return m_clientConnection[clientIndex]->CanSendMessage( channelIndex );
    }

    bool BaseServer::HasMessagesToSend( int clientIndex, int channelIndex ) const
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( m_clientConnection[clientIndex] );
        return m_clientConnection[clientIndex]->HasMessagesToSend( channelIndex );
    }

    void BaseServer::SendMessage( int clientIndex, int channelIndex, Message * message )
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( m_clientConnection[clientIndex] );
        return m_clientConnection[clientIndex]->SendMessage( channelIndex, message, GetContext() );
    }

    Message * BaseServer::ReceiveMessage( int clientIndex, int channelIndex )
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( m_clientConnection[clientIndex] );
        return m_clientConnection[clientIndex]->ReceiveMessage( channelIndex );
    }

    void BaseServer::ReleaseMessage( int clientIndex, Message * message )
    {
        yojimbo_assert( clientIndex >= 0 );
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( m_clientConnection[clientIndex] );
        m_clientConnection[clientIndex]->ReleaseMessage( message );
    }

    void BaseServer::GetNetworkInfo( int clientIndex, NetworkInfo & info ) const
    {
        yojimbo_assert( IsRunning() );
        yojimbo_assert( clientIndex >= 0 ); 
        yojimbo_assert( clientIndex < m_maxClients );
        memset( &info, 0, sizeof( info ) );
        if ( IsClientConnected( clientIndex ) )
        {
            yojimbo_assert( m_clientEndpoint[clientIndex] );
            const uint64_t * counters = reliable_endpoint_counters( m_clientEndpoint[clientIndex] );
            info.numPacketsSent = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT];
            info.numPacketsReceived = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
            info.numPacketsAcked = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
            info.RTT = reliable_endpoint_rtt( m_clientEndpoint[clientIndex] );
            info.packetLoss = reliable_endpoint_packet_loss( m_clientEndpoint[clientIndex] );
            reliable_endpoint_bandwidth( m_clientEndpoint[clientIndex], &info.sentBandwidth, &info.receivedBandwidth, &info.ackedBandwidth );
        }
    }

    MessageFactory & BaseServer::GetClientMessageFactory( int clientIndex ) 
    { 
        yojimbo_assert( IsRunning() ); 
        yojimbo_assert( clientIndex >= 0 ); 
        yojimbo_assert( clientIndex < m_maxClients );
        return *m_clientMessageFactory[clientIndex];
    }

    reliable_endpoint_t * BaseServer::GetClientEndpoint( int clientIndex )
    {
        yojimbo_assert( IsRunning() ); 
        yojimbo_assert( clientIndex >= 0 ); 
        yojimbo_assert( clientIndex < m_maxClients );
        return m_clientEndpoint[clientIndex];
    }

    Connection & BaseServer::GetClientConnection( int clientIndex )
    {
        yojimbo_assert( IsRunning() ); 
        yojimbo_assert( clientIndex >= 0 ); 
        yojimbo_assert( clientIndex < m_maxClients );
        yojimbo_assert( m_clientConnection[clientIndex] );
        return *m_clientConnection[clientIndex];
    }

    void BaseServer::StaticTransmitPacketFunction( void * context, int index, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
    {
        BaseServer * server = (BaseServer*) context;
        server->TransmitPacketFunction( index, packetSequence, packetData, packetBytes );
    }
    
    int BaseServer::StaticProcessPacketFunction( void * context, int index, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
    {
        BaseServer * server = (BaseServer*) context;
        return server->ProcessPacketFunction( index, packetSequence, packetData, packetBytes );
    }

    void * BaseServer::StaticAllocateFunction( void * context, uint64_t bytes )
    {
        yojimbo_assert( context );
        Allocator * allocator = (Allocator*) context;
        return YOJIMBO_ALLOCATE( *allocator, bytes );
    }
    
    void BaseServer::StaticFreeFunction( void * context, void * pointer )
    {
        yojimbo_assert( context );
        yojimbo_assert( pointer );
        Allocator * allocator = (Allocator*) context;
        YOJIMBO_FREE( *allocator, pointer );
    }

    // -----------------------------------------------------------------------------------------------------

    Server::Server( Allocator & allocator, const uint8_t privateKey[], const Address & address, const ClientServerConfig & config, Adapter & adapter, double time ) 
        : BaseServer( allocator, config, adapter, time )
    {
        yojimbo_assert( KeyBytes == NETCODE_KEY_BYTES );
        memcpy( m_privateKey, privateKey, NETCODE_KEY_BYTES );
        m_address = address;
        m_boundAddress = address;
        m_config = config;
        m_server = NULL;
    }

    Server::~Server()
    {
        // IMPORTANT: Please stop the server before destroying it!
        yojimbo_assert( !m_server );
    }

    void Server::Start( int maxClients )
    {
        if ( IsRunning() )
            Stop();
        
        BaseServer::Start( maxClients );
        
        char addressString[MaxAddressLength];
        m_address.ToString( addressString, MaxAddressLength );
        
        struct netcode_server_config_t netcodeConfig;
        netcode_default_server_config(&netcodeConfig);
        netcodeConfig.protocol_id = m_config.protocolId;
        memcpy(netcodeConfig.private_key, m_privateKey, NETCODE_KEY_BYTES);
        netcodeConfig.allocator_context = &GetGlobalAllocator();
        netcodeConfig.allocate_function = StaticAllocateFunction;
        netcodeConfig.free_function     = StaticFreeFunction;
        netcodeConfig.callback_context = this;
        netcodeConfig.connect_disconnect_callback = StaticConnectDisconnectCallbackFunction;
        netcodeConfig.send_loopback_packet_callback = StaticSendLoopbackPacketCallbackFunction;
        
        m_server = netcode_server_create(addressString, &netcodeConfig, GetTime());
        
        if ( !m_server )
        {
            Stop();
            return;
        }
        
        netcode_server_start( m_server, maxClients );

        m_boundAddress.SetPort( netcode_server_get_port( m_server ) );
    }

    void Server::Stop()
    {
        if ( m_server )
        {
            m_boundAddress = m_address;
            netcode_server_stop( m_server );
            netcode_server_destroy( m_server );
            m_server = NULL;
        }
        BaseServer::Stop();
    }

    void Server::DisconnectClient( int clientIndex )
    {
        yojimbo_assert( m_server );
        netcode_server_disconnect_client( m_server, clientIndex );
    }

    void Server::DisconnectAllClients()
    {
        yojimbo_assert( m_server );
        netcode_server_disconnect_all_clients( m_server );
    }

    void Server::SendPackets()
    {
        if ( m_server )
        {
            const int maxClients = GetMaxClients();
            for ( int i = 0; i < maxClients; ++i )
            {
                if ( IsClientConnected( i ) )
                {
                    uint8_t * packetData = GetPacketBuffer();
                    int packetBytes;
                    uint16_t packetSequence = reliable_endpoint_next_packet_sequence( GetClientEndpoint(i) );
                    if ( GetClientConnection(i).GeneratePacket( GetContext(), packetSequence, packetData, m_config.maxPacketSize, packetBytes ) )
                    {
                        reliable_endpoint_send_packet( GetClientEndpoint(i), packetData, packetBytes );
                    }
                }
            }
        }
    }

    void Server::ReceivePackets()
    {
        if ( m_server )
        {
            const int maxClients = GetMaxClients();
            for ( int clientIndex = 0; clientIndex < maxClients; ++clientIndex )
            {
                while ( true )
                {
                    int packetBytes;
                    uint64_t packetSequence;
                    uint8_t * packetData = netcode_server_receive_packet( m_server, clientIndex, &packetBytes, &packetSequence );
                    if ( !packetData )
                        break;
                    reliable_endpoint_receive_packet( GetClientEndpoint( clientIndex ), packetData, packetBytes );
                    netcode_server_free_packet( m_server, packetData );
                }
            }
        }
    }

    void Server::AdvanceTime( double time )
    {
        if ( m_server )
        {
            netcode_server_update( m_server, time );
        }
        BaseServer::AdvanceTime( time );
        NetworkSimulator * networkSimulator = GetNetworkSimulator();
        if ( networkSimulator && networkSimulator->IsActive() )
        {
            uint8_t ** packetData = (uint8_t**) alloca( sizeof( uint8_t*) * m_config.maxSimulatorPackets );
            int * packetBytes = (int*) alloca( sizeof(int) * m_config.maxSimulatorPackets );
            int * to = (int*) alloca( sizeof(int) * m_config.maxSimulatorPackets );
            int numPackets = networkSimulator->ReceivePackets( m_config.maxSimulatorPackets, packetData, packetBytes, to );
            for ( int i = 0; i < numPackets; ++i )
            {
                netcode_server_send_packet( m_server, to[i], (uint8_t*) packetData[i], packetBytes[i] );
                YOJIMBO_FREE( networkSimulator->GetAllocator(), packetData[i] );
            }
        }
    }

    bool Server::IsClientConnected( int clientIndex ) const
    {
        return netcode_server_client_connected( m_server, clientIndex ) != 0;
    }

    uint64_t Server::GetClientId( int clientIndex ) const
    {
        return netcode_server_client_id( m_server, clientIndex );
    }

    netcode_address_t * Server::GetClientAddress( int clientIndex ) const
    {
        return netcode_server_client_address( m_server, clientIndex );
    }

    int Server::GetNumConnectedClients() const
    {
        return netcode_server_num_connected_clients( m_server );
    }

    void Server::ConnectLoopbackClient( int clientIndex, uint64_t clientId, const uint8_t * userData )
    {
        netcode_server_connect_loopback_client( m_server, clientIndex, clientId, userData );
    }

    void Server::DisconnectLoopbackClient( int clientIndex )
    {
        netcode_server_disconnect_loopback_client( m_server, clientIndex );
    }

    bool Server::IsLoopbackClient( int clientIndex ) const
    {
        return netcode_server_client_loopback( m_server, clientIndex ) != 0;
    }

    void Server::ProcessLoopbackPacket( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
    {
        netcode_server_process_loopback_packet( m_server, clientIndex, packetData, packetBytes, packetSequence );
    }

    void Server::TransmitPacketFunction( int clientIndex, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
    {
        (void) packetSequence;
        NetworkSimulator * networkSimulator = GetNetworkSimulator();
        if ( networkSimulator && networkSimulator->IsActive() )
        {
            networkSimulator->SendPacket( clientIndex, packetData, packetBytes );
        }
        else
        {
            netcode_server_send_packet( m_server, clientIndex, packetData, packetBytes );
        }
    }

    int Server::ProcessPacketFunction( int clientIndex, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
    {
        return (int) GetClientConnection(clientIndex).ProcessPacket( GetContext(), packetSequence, packetData, packetBytes );
    }

    void Server::ConnectDisconnectCallbackFunction( int clientIndex, int connected )
    {
        if ( connected == 0 )
        {
            GetAdapter().OnServerClientDisconnected( clientIndex );
            reliable_endpoint_reset( GetClientEndpoint( clientIndex ) );
            GetClientConnection( clientIndex ).Reset();
            NetworkSimulator * networkSimulator = GetNetworkSimulator();
            if ( networkSimulator && networkSimulator->IsActive() )
            {
                networkSimulator->DiscardClientPackets( clientIndex );
            }
        }
        else
        {
            GetAdapter().OnServerClientConnected( clientIndex );
        }
    }

    void Server::SendLoopbackPacketCallbackFunction( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
    {
        GetAdapter().ServerSendLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
    }

    void Server::StaticConnectDisconnectCallbackFunction( void * context, int clientIndex, int connected )
    {
        Server * server = (Server*) context;
        server->ConnectDisconnectCallbackFunction( clientIndex, connected );
    }

    void Server::StaticSendLoopbackPacketCallbackFunction( void * context, int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
    {
        Server * server = (Server*) context;
        server->SendLoopbackPacketCallbackFunction( clientIndex, packetData, packetBytes, packetSequence );
    }
}

// ---------------------------------------------------------------------------------

namespace yojimbo
{
    NetworkSimulator::NetworkSimulator( Allocator & allocator, int numPackets, double time )
    {
        yojimbo_assert( numPackets > 0 );
        m_allocator = &allocator;
        m_currentIndex = 0;
        m_time = time;
        m_latency = 0.0f;
        m_jitter = 0.0f;
        m_packetLoss = 0.0f;
        m_duplicates = 0.0f;
        m_active = false;
        m_numPacketEntries = numPackets;
        m_packetEntries = (PacketEntry*) YOJIMBO_ALLOCATE( allocator, sizeof( PacketEntry ) * numPackets );
        yojimbo_assert( m_packetEntries );
        memset( m_packetEntries, 0, sizeof( PacketEntry ) * numPackets );
    }

    NetworkSimulator::~NetworkSimulator()
    {
        yojimbo_assert( m_allocator );
        yojimbo_assert( m_packetEntries );
        yojimbo_assert( m_numPacketEntries > 0 );
        DiscardPackets();
        YOJIMBO_FREE( *m_allocator, m_packetEntries );
        m_numPacketEntries = 0;
        m_allocator = NULL;
    }

    void NetworkSimulator::SetLatency( float milliseconds )
    {
        m_latency = milliseconds;
        UpdateActive();
    }

    void NetworkSimulator::SetJitter( float milliseconds )
    {
        m_jitter = milliseconds;
        UpdateActive();
    }

    void NetworkSimulator::SetPacketLoss( float percent )
    {
        m_packetLoss = percent;
        UpdateActive();
    }

    void NetworkSimulator::SetDuplicates( float percent )
    {
        m_duplicates = percent;
        UpdateActive();
    }

    bool NetworkSimulator::IsActive() const
    {
        return m_active;
    }

    void NetworkSimulator::UpdateActive()
    {
        bool previous = m_active;
        m_active = m_latency != 0.0f || m_jitter != 0.0f || m_packetLoss != 0.0f || m_duplicates != 0.0f;
        if ( previous && !m_active )
        {
            DiscardPackets();
        }
    }

    void NetworkSimulator::SendPacket( int to, uint8_t * packetData, int packetBytes )
    {
        yojimbo_assert( m_allocator );
        yojimbo_assert( packetData );
        yojimbo_assert( packetBytes > 0 );

        if ( yojimbo_random_float( 0.0f, 100.0f ) <= m_packetLoss )
        {
            return;
        }

        PacketEntry & packetEntry = m_packetEntries[m_currentIndex];

        if ( packetEntry.packetData )
        {
            YOJIMBO_FREE( *m_allocator, packetEntry.packetData );
            packetEntry = PacketEntry();
        }

        double delay = m_latency / 1000.0;

        if ( m_jitter > 0 )
            delay += yojimbo_random_float( -m_jitter, +m_jitter ) / 1000.0;

        packetEntry.to = to;
        packetEntry.packetData = (uint8_t*) YOJIMBO_ALLOCATE( *m_allocator, packetBytes );
        memcpy( packetEntry.packetData, packetData, packetBytes );
        packetEntry.packetBytes = packetBytes;
        packetEntry.deliveryTime = m_time + delay;
        m_currentIndex = ( m_currentIndex + 1 ) % m_numPacketEntries;

        if ( yojimbo_random_float( 0.0f, 100.0f ) <= m_duplicates )
        {
            PacketEntry & nextPacketEntry = m_packetEntries[m_currentIndex];
            nextPacketEntry.to = to;
            nextPacketEntry.packetData = (uint8_t*) YOJIMBO_ALLOCATE( *m_allocator, packetBytes );
            memcpy( nextPacketEntry.packetData, packetData, packetBytes );
            nextPacketEntry.packetBytes = packetBytes;
            nextPacketEntry.deliveryTime = m_time + delay + yojimbo_random_float( 0, +1.0 );
            m_currentIndex = ( m_currentIndex + 1 ) % m_numPacketEntries;
        }
    }

    int NetworkSimulator::ReceivePackets( int maxPackets, uint8_t * packetData[], int packetBytes[], int to[] )
    {
        if ( !IsActive() )
            return 0;

        int numPackets = 0;

        for ( int i = 0; i < yojimbo_min( m_numPacketEntries, maxPackets ); ++i )
        {
            if ( !m_packetEntries[i].packetData )
                continue;

            if ( m_packetEntries[i].deliveryTime < m_time )
            {
                packetData[numPackets] = m_packetEntries[i].packetData;
                packetBytes[numPackets] = m_packetEntries[i].packetBytes;
                if ( to )
                {
                    to[numPackets] = m_packetEntries[i].to;
                }
                m_packetEntries[i].packetData = NULL;
                numPackets++;
            }
        }

        return numPackets;
    }

    void NetworkSimulator::DiscardPackets()
    {
        for ( int i = 0; i < m_numPacketEntries; ++i )
        {
            PacketEntry & packetEntry = m_packetEntries[i];
            if ( !packetEntry.packetData )
                continue;
            YOJIMBO_FREE( *m_allocator, packetEntry.packetData );
            packetEntry = PacketEntry();
        }
    }

    void NetworkSimulator::DiscardClientPackets( int clientIndex )
    {
        for ( int i = 0; i < m_numPacketEntries; ++i )
        {
            PacketEntry & packetEntry = m_packetEntries[i];
            if ( !packetEntry.packetData || packetEntry.to != clientIndex )
                continue;
            YOJIMBO_FREE( *m_allocator, packetEntry.packetData );
            packetEntry = PacketEntry();
        }
    }

    void NetworkSimulator::AdvanceTime( double time )
    {
        m_time = time;
    }
}

// ---------------------------------------------------------------------------------
