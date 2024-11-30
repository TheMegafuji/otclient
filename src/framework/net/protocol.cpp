/*
 * Copyright (c) 2010-2022 OTClient <https://github.com/edubart/otclient>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "protocol.h"
#include <random>
#include <framework/core/application.h>
#include "connection.h"

Protocol::Protocol() :m_inputMessage(std::make_shared<InputMessage>()) {
    inflateInit2(&m_zstream, -15);
}

Protocol::~Protocol()
{
#ifndef NDEBUG
    assert(!g_app.isTerminated());
#endif
    disconnect();
    inflateEnd(&m_zstream);
}

void Protocol::connect(const std::string_view host, uint16_t port)
{
    g_logger.info(stdext::format("Protocol::connect - Connecting to %s:%d", host, port));

    m_connection = std::make_shared<Connection>();
    g_logger.info("Created new connection instance");

    m_connection->setErrorCallback([capture0 = asProtocol()](auto&& PH1) { 
        g_logger.info("Connection error callback triggered");
        capture0->onError(std::forward<decltype(PH1)>(PH1));    
    });

    m_connection->connect(host, port, [capture0 = asProtocol()] {
        g_logger.info("Connection success callback triggered"); 
        capture0->onConnect();
    });

    g_logger.info("Connection attempt initiated");
}

void Protocol::disconnect()
{
    if (m_connection) {
        m_connection->close();
        m_connection.reset();
    }
}

void Protocol::send(const OutputMessagePtr& outputMessage)
{
    g_logger.info("Protocol::send - Starting message send");

    // encrypt
    if (m_xteaEncryptionEnabled) {
        g_logger.info("Encrypting message with XTEA");
        xteaEncrypt(outputMessage);
    }

    // write checksum
    if (m_sequencedPackets) {
        g_logger.info(stdext::format("Writing sequence number: %d", m_packetNumber));
        outputMessage->writeSequence(m_packetNumber++);
    } else if (m_checksumEnabled) {
        g_logger.info("Writing message checksum");
        outputMessage->writeChecksum();
    }

    // write message size
    g_logger.info("Writing message size");
    outputMessage->writeMessageSize();

    // send
    if (m_connection) {
        g_logger.info(stdext::format("Sending message of size: %d bytes", outputMessage->getMessageSize()));
        m_connection->write(outputMessage->getHeaderBuffer(), outputMessage->getMessageSize());
    } else {
        g_logger.error("Cannot send message - no active connection");
    }

    // reset message to allow reuse
    g_logger.info("Resetting output message");
    outputMessage->reset();
}

void Protocol::recv()
{
    g_logger.info("Protocol::recv - Starting message receive");
    m_inputMessage->reset();

    // first update message header size
    int headerSize = 2; // 2 bytes for message size
    if (m_checksumEnabled) {
        headerSize += 4; // 4 bytes for checksum
        g_logger.info("Adding 4 bytes to header size for checksum");
    }
    if (m_xteaEncryptionEnabled) {
        headerSize += 2; // 2 bytes for XTEA encrypted message size
        g_logger.info("Adding 2 bytes to header size for XTEA encryption");
    }
    g_logger.info(stdext::format("Setting header size to %d bytes", headerSize));
    m_inputMessage->setHeaderSize(headerSize);

    // read the first 2 bytes which contain the message size
    if (m_connection) {
        g_logger.info("Reading initial 2 bytes for message size");
        m_connection->read(2, [capture0 = asProtocol()](auto&& PH1, auto&& PH2) {
            capture0->internalRecvHeader(std::forward<decltype(PH1)>(PH1),
            std::forward<decltype(PH2)>(PH2));
        });
    } else {
        g_logger.error("No active connection to read from");
    }
}

void Protocol::internalRecvHeader(uint8_t* buffer, uint16_t size)
{
    // read message size
    m_inputMessage->fillBuffer(buffer, size);
    const uint16_t remainingSize = m_inputMessage->readSize();

    // read remaining message data
    if (m_connection)
        m_connection->read(remainingSize, [capture0 = asProtocol()](auto&& PH1, auto&& PH2) {
        capture0->internalRecvData(std::forward<decltype(PH1)>(PH1),
        std::forward<decltype(PH2)>(PH2));
    });
}

void Protocol::internalRecvData(uint8_t* buffer, uint16_t size)
{
    g_logger.info(stdext::format("Protocol::internalRecvData - Received %d bytes", size));

    // process data only if really connected
    if (!isConnected()) {
        g_logger.traceError("received data while disconnected");
        return;
    }

    g_logger.info("Filling input message buffer");
    m_inputMessage->fillBuffer(buffer, size);

    bool decompress = false;
    if (m_sequencedPackets) {
        g_logger.info("Checking sequenced packet compression flag");
        decompress = (m_inputMessage->getU32() & 1 << 31);
        g_logger.info(stdext::format("Message compression: %s", decompress ? "enabled" : "disabled"));
    } else if (m_checksumEnabled && !m_inputMessage->readChecksum()) {
        g_logger.traceError(stdext::format("got a network message with invalid checksum, size: %i", (int)m_inputMessage->getMessageSize()));
        return;
    }

    if (m_xteaEncryptionEnabled) {
        g_logger.info("Attempting XTEA decryption");
        if (!xteaDecrypt(m_inputMessage)) {
            g_logger.traceError("failed to decrypt message");
            return;
        }
        g_logger.info("XTEA decryption successful");
    }

    if (decompress) {
        g_logger.info("Decompressing message");
        static uint8_t zbuffer[InputMessage::BUFFER_MAXSIZE];

        m_zstream.next_in = m_inputMessage->getDataBuffer();
        m_zstream.next_out = zbuffer;
        m_zstream.avail_in = m_inputMessage->getUnreadSize();
        m_zstream.avail_out = InputMessage::BUFFER_MAXSIZE;

        g_logger.info(stdext::format("Compression info - available in: %d, available out: %d", 
            m_zstream.avail_in, m_zstream.avail_out));

        int32_t ret = inflate(&m_zstream, Z_FINISH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            g_logger.traceError(stdext::format("failed to decompress message - %s", m_zstream.msg));
            return;
        }

        const uint32_t totalSize = m_zstream.total_out;
        g_logger.info(stdext::format("Decompression complete - total size: %d", totalSize));
        
        inflateReset(&m_zstream);
        if (totalSize == 0) {
            g_logger.traceError(stdext::format("invalid size of decompressed message - %i", totalSize));
            return;
        }

        m_inputMessage->fillBuffer(zbuffer, totalSize);
        m_inputMessage->setMessageSize(m_inputMessage->getHeaderSize() + totalSize);
        g_logger.info(stdext::format("Final message size after decompression: %d", m_inputMessage->getMessageSize()));
    }

    g_logger.info("Processing received message");
    onRecv(m_inputMessage);
}

void Protocol::generateXteaKey()
{
    std::random_device rd;
    std::uniform_int_distribution<uint32_t > unif;
    std::generate(m_xteaKey.begin(), m_xteaKey.end(), [&unif, &rd] { return unif(rd); });
    
    g_logger.info(stdext::format("Generated XTEA key: [%u, %u, %u, %u]", 
        m_xteaKey[0], m_xteaKey[1], m_xteaKey[2], m_xteaKey[3]));
}

namespace
{
    constexpr uint32_t delta = 0x9E3779B9;

    template<typename Round>
    void apply_rounds(uint8_t* data, size_t length, Round round)
    {
        for (auto j = 0u; j < length; j += 8) {
            uint32_t left = data[j + 0] | data[j + 1] << 8u | data[j + 2] << 16u | data[j + 3] << 24u,
                right = data[j + 4] | data[j + 5] << 8u | data[j + 6] << 16u | data[j + 7] << 24u;

            round(left, right);

            data[j] = static_cast<uint8_t>(left);
            data[j + 1] = static_cast<uint8_t>(left >> 8u);
            data[j + 2] = static_cast<uint8_t>(left >> 16u);
            data[j + 3] = static_cast<uint8_t>(left >> 24u);
            data[j + 4] = static_cast<uint8_t>(right);
            data[j + 5] = static_cast<uint8_t>(right >> 8u);
            data[j + 6] = static_cast<uint8_t>(right >> 16u);
            data[j + 7] = static_cast<uint8_t>(right >> 24u);
        }
    }
}

bool Protocol::xteaDecrypt(const InputMessagePtr& inputMessage) const
{
    const uint16_t encryptedSize = inputMessage->getUnreadSize();
    if (encryptedSize % 8 != 0) {
        g_logger.traceError("invalid encrypted network message");
        return false;
    }

    for (uint32_t i = 0, sum = delta << 5, next_sum = sum - delta; i < 32; ++i, sum = next_sum, next_sum -= delta) {
        apply_rounds(inputMessage->getReadBuffer(), encryptedSize, [&](uint32_t& left, uint32_t& right) {
            right -= ((left << 4 ^ left >> 5) + left) ^ (sum + m_xteaKey[(sum >> 11) & 3]);
            left -= ((right << 4 ^ right >> 5) + right) ^ (next_sum + m_xteaKey[next_sum & 3]);
        });
    }

    const uint16_t decryptedSize = inputMessage->getU16() + 2;
    const int sizeDelta = decryptedSize - encryptedSize;
    if (sizeDelta > 0 || -sizeDelta > encryptedSize) {
        g_logger.traceError("invalid decrypted network message");
        return false;
    }

    inputMessage->setMessageSize(inputMessage->getMessageSize() + sizeDelta);
    return true;
}

void Protocol::xteaEncrypt(const OutputMessagePtr& outputMessage) const
{
    outputMessage->writeMessageSize();
    uint16_t encryptedSize = outputMessage->getMessageSize();

    //add bytes until reach 8 multiple
    if ((encryptedSize % 8) != 0) {
        const uint16_t n = 8 - (encryptedSize % 8);
        outputMessage->addPaddingBytes(n);
        encryptedSize += n;
    }

    for (uint32_t i = 0, sum = 0, next_sum = sum + delta; i < 32; ++i, sum = next_sum, next_sum += delta) {
        apply_rounds(outputMessage->getDataBuffer() - 2, encryptedSize, [&](uint32_t& left, uint32_t& right) {
            left += ((right << 4 ^ right >> 5) + right) ^ (sum + m_xteaKey[sum & 3]);
            right += ((left << 4 ^ left >> 5) + left) ^ (next_sum + m_xteaKey[(next_sum >> 11) & 3]);
        });
    }
}

void Protocol::onConnect() { callLuaField("onConnect"); }

void Protocol::onRecv(const InputMessagePtr& inputMessage)
{
    callLuaField("onRecv", inputMessage);
}

void Protocol::onError(const std::error_code& err)
{
    callLuaField("onError", err.message(), err.value());
    disconnect();
}