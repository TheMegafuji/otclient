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

#include "protocolgame.h"
#include "game.h"
#include "framework/net/inputmessage.h"

void ProtocolGame::login(const std::string_view accountName, const std::string_view accountPassword, const std::string_view host, uint16_t port,
                         const std::string_view characterName, const std::string_view authenticatorToken, const std::string_view sessionKey)
{
    g_logger.info("Logging in with account: " + std::string(accountName) + ", character: " + std::string(characterName) + ", host: " + std::string(host) + ", port: " + std::to_string(port));

    m_accountName = accountName;
    m_accountPassword = accountPassword;
    m_authenticatorToken = authenticatorToken;
    m_sessionKey = sessionKey;
    m_characterName = characterName;

    connect(host, port);
}

void ProtocolGame::onConnect()
{
    g_logger.info("ProtocolGame::onConnect - Connection established");

    m_firstRecv = true;
    Protocol::onConnect();

    m_localPlayer = g_game.getLocalPlayer();
    g_logger.info("Local player initialized");

    if (g_game.getFeature(Otc::GameProtocolChecksum)) {
        g_logger.info("Enabling protocol checksum");
        enableChecksum();
    }

    if (!g_game.getFeature(Otc::GameChallengeOnLogin)) {
        g_logger.info("No challenge required, sending direct login packet");
        sendLoginPacket(0, 0);
    } else {
        g_logger.info("Challenge-based login enabled, waiting for server challenge");
    }

    g_logger.info("Starting to receive data");
    recv();
}

void ProtocolGame::onRecv(const InputMessagePtr& inputMessage)
{
    g_logger.info("ProtocolGame::onRecv - Received message");

    if (m_firstRecv) {
        g_logger.info("Processing first received message");
        m_firstRecv = false;

        if (g_game.getFeature(Otc::GameMessageSizeCheck)) {
            g_logger.info("Performing message size check");
            const int size = inputMessage->getU16();
            g_logger.info(stdext::format("Expected message size: %d, Actual unread size: %d", size, inputMessage->getUnreadSize()));
            
            if (size != inputMessage->getUnreadSize()) {
                g_logger.traceError(stdext::format("Invalid message size - expected %d but got %d", size, inputMessage->getUnreadSize()));
                return;
            }
            g_logger.info("Message size check passed");
        }
    }

    g_logger.info("Parsing message");
    parseMessage(inputMessage);
    g_logger.info("Message parsed, receiving next message");
    recv();
}

void ProtocolGame::onError(const std::error_code& error)
{
    g_game.processConnectionError(error);
    disconnect();
}