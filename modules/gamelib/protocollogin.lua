-- @docclass
ProtocolLogin = extends(Protocol, 'ProtocolLogin')

LoginServerError = 10
LoginServerTokenSuccess = 12
LoginServerTokenError = 13
LoginServerUpdate = 17
LoginServerMotd = 20
LoginServerUpdateNeeded = 30
LoginServerSessionKey = 40
LoginServerCharacterList = 100
LoginServerExtendedCharacterList = 101

-- Since 10.76
LoginServerRetry = 10
LoginServerErrorNew = 11

function ProtocolLogin:login(host, port, accountName, accountPassword, authenticatorToken, stayLogged)
    if string.len(host) == 0 or port == nil or port == 0 then
        signalcall(self.onLoginError, self, tr('You must enter a valid server address and port.'))
        return
    end

    self.accountName = accountName
    self.accountPassword = accountPassword
    self.authenticatorToken = authenticatorToken
    self.stayLogged = stayLogged
    self.connectCallback = self.sendLoginPacket

    self:connect(host, port)
end

function ProtocolLogin:cancelLogin()
    self:disconnect()
end

function ProtocolLogin:sendLoginPacket()
    local msg = OutputMessage.create()
    msg:addU8(ClientOpcodes.ClientEnterAccount)
    msg:addU16(g_game.getOs())
    msg:addU16(g_game.getProtocolVersion())

    -- Build login data object to understand the packet
    local loginData = {
        os = g_game.getOs(),
        protocolVersion = g_game.getProtocolVersion()
    }

    if g_game.getFeature(GameClientVersion) then
        msg:addU32(g_game.getClientVersion())
        loginData.clientVersion = g_game.getClientVersion()
    end

    if g_game.getFeature(GameContentRevision) then
        msg:addU16(g_things.getContentRevision())
        msg:addU16(0)
        loginData.contentRevision = g_things.getContentRevision()
    else
        msg:addU32(g_things.getDatSignature())
        loginData.datSignature = g_things.getDatSignature()
    end

    msg:addU32(g_sprites.getSprSignature())
    msg:addU32(PIC_SIGNATURE)
    loginData.sprSignature = g_sprites.getSprSignature()
    loginData.picSignature = PIC_SIGNATURE

    if g_game.getFeature(GamePreviewState) then
        msg:addU8(0)
        loginData.previewState = 0
    end

    local offset = msg:getMessageSize()
    if g_game.getFeature(GameLoginPacketEncryption) then
        msg:addU8(0)
        self:generateXteaKey()
        local xteaKey = self:getXteaKey()
        msg:addU32(xteaKey[1])
        msg:addU32(xteaKey[2])
        msg:addU32(xteaKey[3])
        msg:addU32(xteaKey[4])
        loginData.xteaKey = xteaKey
    end

    g_logger.info("Preparing login packet with account name: " .. self.accountName)
    if g_game.getFeature(GameAccountNames) then
        msg:addString(self.accountName)
        loginData.accountName = self.accountName
    else
        msg:addU32(tonumber(self.accountName))
        loginData.accountNumber = tonumber(self.accountName)
    end

    msg:addString(self.accountPassword)
    loginData.passwordLength = #self.accountPassword

    if self.getLoginExtendedData then
        local data = self:getLoginExtendedData()
        msg:addString(data)
        loginData.extendedData = data
    end

    local paddingBytes = g_crypt.rsaGetSize() - (msg:getMessageSize() - offset)
    assert(paddingBytes >= 0)
    for i = 1, paddingBytes do
        msg:addU8(math.random(0, 0xff))
    end
    loginData.rsaPaddingBytes = paddingBytes

    if g_game.getFeature(GameLoginPacketEncryption) then
        msg:encryptRsa()
        loginData.rsaEncrypted = true
    end

    if g_game.getFeature(GameOGLInformation) then
        msg:addU8(1)
        msg:addU8(1)

        if g_game.getClientVersion() >= 1072 then
            local renderer = string.format('%s %s', g_graphics.getVendor(), g_graphics.getRenderer())
            msg:addString(renderer)
            loginData.renderer = renderer
        else
            msg:addString(g_graphics.getRenderer())
            loginData.renderer = g_graphics.getRenderer()
        end
        msg:addString(g_graphics.getVersion())
        loginData.glVersion = g_graphics.getVersion()
    end

    if g_game.getFeature(GameAuthenticator) then
        offset = msg:getMessageSize()
        msg:addU8(0)
        msg:addString(self.authenticatorToken)
        loginData.authenticatorToken = #self.authenticatorToken > 0

        if g_game.getFeature(GameSessionKey) then
            msg:addU8(booleantonumber(self.stayLogged))
            loginData.stayLogged = self.stayLogged
        end

        paddingBytes = g_crypt.rsaGetSize() - (msg:getMessageSize() - offset)
        assert(paddingBytes >= 0)
        for i = 1, paddingBytes do
            msg:addU8(math.random(0, 0xff))
        end
        loginData.authPaddingBytes = paddingBytes

        msg:encryptRsa()
    end

    if g_game.getFeature(GameProtocolChecksum) then
        self:enableChecksum()
        loginData.checksumEnabled = true
    end

    -- Log the login data object
    g_logger.info("Login packet data:")
    g_logger.info(json.encode(loginData, {pretty = true}))

    g_logger.info("Sending login packet")
    g_logger.info(string.format("Message size: %d, content: %s", msg:getMessageSize(), msg:getBuffer()))
    -- Log the full message content as hex dump for debugging
    local buffer = msg:getBuffer()
    local hexDump = ""
    for i = 1, #buffer do
        hexDump = hexDump .. string.format("%02X ", buffer:byte(i))
        if i % 16 == 0 then hexDump = hexDump .. "\n" end
    end
    g_logger.info("Message hex dump:")
    g_logger.info(hexDump)
    self:send(msg)

    if g_game.getFeature(GameLoginPacketEncryption) then
        self:enableXteaEncryption()
    end

    if g_game.getFeature(GameSequencedPackets) then
        scheduleEvent(function()
            self:enabledSequencedPackets()
        end, 1000)
    end

    self:recv()
end

function ProtocolLogin:onConnect()
    self.gotConnection = true
    self:connectCallback()
    self.connectCallback = nil
end

function ProtocolLogin:onRecv(msg)
    while not msg:eof() do
        local opcode = msg:getU8()
        g_logger.info("Received message with opcode: " .. opcode)
        if opcode == LoginServerErrorNew then
            self:parseError(msg)
        elseif opcode == LoginServerError then
            self:parseError(msg)
        elseif opcode == LoginServerMotd then
            self:parseMotd(msg)
        elseif opcode == LoginServerUpdateNeeded then
            signalcall(self.onLoginError, self, tr('Client needs update.'))
        elseif opcode == LoginServerTokenSuccess then
            local unknown = msg:getU8()
        elseif opcode == LoginServerTokenError then
            -- TODO: prompt for token here
            local unknown = msg:getU8()
            signalcall(self.onLoginError, self, tr('Invalid authentification token.'))
        elseif opcode == LoginServerCharacterList then
            self:parseCharacterList(msg)
        elseif opcode == LoginServerExtendedCharacterList then
            self:parseExtendedCharacterList(msg)
        elseif opcode == LoginServerUpdate then
            local signature = msg:getString()
            signalcall(self.onUpdateNeeded, self, signature)
        elseif opcode == LoginServerSessionKey then
            self:parseSessionKey(msg)
        else
            self:parseOpcode(opcode, msg)
        end
    end
    self:disconnect()
end

function ProtocolLogin:parseError(msg)
    local errorMessage = msg:getString()
    signalcall(self.onLoginError, self, errorMessage)
end

function ProtocolLogin:parseMotd(msg)
    local motd = msg:getString()
    signalcall(self.onMotd, self, motd)
end

function ProtocolLogin:parseSessionKey(msg)
    local sessionKey = msg:getString()
    signalcall(self.onSessionKey, self, sessionKey)
end

function ProtocolLogin:parseCharacterList(msg)
    local characters = {}

    if g_game.getClientVersion() > 1010 then
        local worlds = {}

        local worldsCount = msg:getU8()
        for i = 1, worldsCount do
            local world = {}
            local worldId = msg:getU8()
            world.worldName = msg:getString()
            world.worldIp = msg:getString()
            world.worldPort = msg:getU16()
            world.previewState = msg:getU8()
            worlds[worldId] = world
        end

        local charactersCount = msg:getU8()
        for i = 1, charactersCount do
            local character = {}
            local worldId = msg:getU8()
            character.name = msg:getString()
            character.worldName = worlds[worldId].worldName
            character.worldIp = worlds[worldId].worldIp
            character.worldPort = worlds[worldId].worldPort
            character.previewState = worlds[worldId].previewState
            characters[i] = character
        end

    else
        local charactersCount = msg:getU8()
        for i = 1, charactersCount do
            local character = {}
            character.name = msg:getString()
            character.worldName = msg:getString()
            character.worldIp = iptostring(msg:getU32())
            character.worldPort = msg:getU16()

            if g_game.getFeature(GamePreviewState) then
                character.previewState = msg:getU8()
            end

            characters[i] = character
        end
    end

    local account = {}
    if g_game.getProtocolVersion() > 1077 then
        account.status = msg:getU8()
        account.subStatus = msg:getU8()

        account.premDays = msg:getU32()
        if account.premDays ~= 0 and account.premDays ~= 65535 then
            account.premDays = math.floor((account.premDays - os.time()) / 86400)
        end
    else
        account.status = AccountStatus.Ok
        account.premDays = msg:getU16()
        account.subStatus = account.premDays > 0 and SubscriptionStatus.Premium or SubscriptionStatus.Free
    end

    signalcall(self.onCharacterList, self, characters, account)
end

function ProtocolLogin:parseExtendedCharacterList(msg)
    local characters = msg:getTable()
    local account = msg:getTable()
    local otui = msg:getString()
    signalcall(self.onCharacterList, self, characters, account, otui)
end

function ProtocolLogin:parseOpcode(opcode, msg)
    signalcall(self.onOpcode, self, opcode, msg)
end

function ProtocolLogin:onError(msg, code)
    local text = translateNetworkError(code, self:isConnecting(), msg)
    g_logger.error("Login error: " .. text)
    signalcall(self.onLoginError, self, text)
end
