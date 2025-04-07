using SMBLibrary.Authentication.NTLM;
using SMBLibrary.Client.Authentication;
using SMBLibrary.NetBios;
using SMBLibrary.Services;
using SMBLibrary.SMB1;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Utilities;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public partial class SMB1AsyncClient : ISMBAsyncClient
    {
        private const string NTLanManagerDialect = "NT LM 0.12";

        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        private static readonly ushort ClientMaxBufferSize = 65535; // Valid range: 512 - 65535
        private static readonly ushort ClientMaxMpxCount = 1;
        private static readonly int DefaultResponseTimeoutInMilliseconds = 5000;

        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket m_clientSocket;
        private ConnectionState m_connectionState;
        private bool m_forceExtendedSecurity;
        private bool m_unicode;
        private bool m_largeFiles;
        private bool m_infoLevelPassthrough;
        private bool m_largeRead;
        private bool m_largeWrite;
        private uint m_serverMaxBufferSize;
        private ushort m_maxMpxCount;
        private int m_responseTimeoutInMilliseconds;

        private ushort m_userID;
        private byte[] m_serverChallenge;
        private byte[] m_securityBlob;
        private byte[] m_sessionKey;

        public SMB1AsyncClient()
        {
        }

        public async Task<bool> Connect(string serverName, SMBTransportType transport, TimeSpan? responseTimeout = null, CancellationToken cancellationToken = default)
        {
            IPAddress[] hostAddresses = Dns.GetHostAddresses(serverName);
            if (hostAddresses.Length == 0)
            {
                throw new Exception(String.Format("Cannot resolve host name {0} to an IP address", serverName));
            }
            IPAddress serverAddress = Client.IPAddressHelper.SelectAddressPreferIPv4(hostAddresses);
            return await Connect(serverAddress, transport, responseTimeout, cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, TimeSpan? responseTimeout = null, CancellationToken cancellationToken = default)
        {
            return await Connect(serverAddress, transport, true, (int)(responseTimeout?.TotalMilliseconds ?? DefaultResponseTimeoutInMilliseconds), cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, bool forceExtendedSecurity, CancellationToken cancellationToken = default)
        {
            return await Connect(serverAddress, transport, forceExtendedSecurity, DefaultResponseTimeoutInMilliseconds, cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, bool forceExtendedSecurity, int responseTimeoutInMilliseconds, CancellationToken cancellationToken = default)
        {
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            return await Connect(serverAddress, transport, port, forceExtendedSecurity, responseTimeoutInMilliseconds, cancellationToken).ConfigureAwait(false);
        }

        protected internal async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, int port, bool forceExtendedSecurity, int responseTimeoutInMilliseconds, CancellationToken cancellationToken = default)
        {
            m_transport = transport;
            if (!m_isConnected)
            {
                m_forceExtendedSecurity = forceExtendedSecurity;
                m_responseTimeoutInMilliseconds = responseTimeoutInMilliseconds;
#if NET5_0_OR_GREATER
                if (! await ConnectSocket(serverAddress, port, cancellationToken).ConfigureAwait(false))
#else
                if (!ConnectSocket(serverAddress, port))
#endif
                {
                    return false;
                }

                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    SessionRequestPacket sessionRequest = new SessionRequestPacket();
                    sessionRequest.CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServerService);
                    sessionRequest.CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);

                    var (isSuccess, sessionResponsePacket, error) = await TrySendPacket(m_clientSocket, sessionRequest, cancellationToken).ConfigureAwait(false);

                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
#if NET6_0_OR_GREATER
                        await m_clientSocket.DisconnectAsync(false, cancellationToken).ConfigureAwait(false);
#else
                        m_clientSocket.Disconnect(false);
#endif

#if NET5_0_OR_GREATER
                        if (!await ConnectSocket(serverAddress, port, cancellationToken).ConfigureAwait(false))
#else
                        if (!ConnectSocket(serverAddress, port))
#endif
                        {
                            return false;
                        }

                        Client.NameServiceClient nameServiceClient = new Client.NameServiceClient(serverAddress);
                        string serverName = nameServiceClient.GetServerName();
                        if (serverName == null)
                        {
                            return false;
                        }

                        sessionRequest.CalledName = serverName;
                        (isSuccess, sessionResponsePacket, error) = await TrySendPacket(m_clientSocket, sessionRequest, cancellationToken).ConfigureAwait(false);

                        if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        {
                            return false;
                        }
                    }
                }

                m_isConnected = true;
                var supportsDialect = await NegotiateDialect(m_forceExtendedSecurity, cancellationToken).ConfigureAwait(false);
                if (!supportsDialect)
                {
                    m_clientSocket.Close();
                    m_isConnected = false;
                }
            }
            return m_isConnected;
        }

        private async Task<bool> NegotiateDialect(bool forceExtendedSecurity, CancellationToken cancellationToken = default)
        {
            NegotiateRequest request = new NegotiateRequest();
            request.Dialects.Add(NTLanManagerDialect);

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_NEGOTIATE, cancellationToken).ConfigureAwait(false);
            if (reply == null)
            {
                return false;
            }

            if (reply.Commands[0] is NegotiateResponse && !forceExtendedSecurity)
            {
                NegotiateResponse response = (NegotiateResponse)reply.Commands[0];
                m_unicode = ((response.Capabilities & Capabilities.Unicode) > 0);
                m_largeFiles = ((response.Capabilities & Capabilities.LargeFiles) > 0);
                bool ntSMB = ((response.Capabilities & Capabilities.NTSMB) > 0);
                bool rpc = ((response.Capabilities & Capabilities.RpcRemoteApi) > 0);
                bool ntStatusCode = ((response.Capabilities & Capabilities.NTStatusCode) > 0);
                m_infoLevelPassthrough = ((response.Capabilities & Capabilities.InfoLevelPassthrough) > 0);
                m_largeRead = ((response.Capabilities & Capabilities.LargeRead) > 0);
                m_largeWrite = ((response.Capabilities & Capabilities.LargeWrite) > 0);
                m_serverMaxBufferSize = response.MaxBufferSize;
                m_maxMpxCount = Math.Min(response.MaxMpxCount, ClientMaxMpxCount);
                m_serverChallenge = response.Challenge;
                return ntSMB && rpc && ntStatusCode;
            }
            else if (reply.Commands[0] is NegotiateResponseExtended)
            {
                NegotiateResponseExtended response = (NegotiateResponseExtended)reply.Commands[0];
                m_unicode = ((response.Capabilities & Capabilities.Unicode) > 0);
                m_largeFiles = ((response.Capabilities & Capabilities.LargeFiles) > 0);
                bool ntSMB = ((response.Capabilities & Capabilities.NTSMB) > 0);
                bool rpc = ((response.Capabilities & Capabilities.RpcRemoteApi) > 0);
                bool ntStatusCode = ((response.Capabilities & Capabilities.NTStatusCode) > 0);
                m_infoLevelPassthrough = ((response.Capabilities & Capabilities.InfoLevelPassthrough) > 0);
                m_largeRead = ((response.Capabilities & Capabilities.LargeRead) > 0);
                m_largeWrite = ((response.Capabilities & Capabilities.LargeWrite) > 0);
                m_serverMaxBufferSize = response.MaxBufferSize;
                m_maxMpxCount = Math.Min(response.MaxMpxCount, ClientMaxMpxCount);
                m_securityBlob = response.SecurityBlob;
                return ntSMB && rpc && ntStatusCode;
            }
            else
            {
                return false;
            }
        }

        public async Task<Result.NTStatus> Login(string domainName, string userName, string password, CancellationToken cancellationToken = default)
        {
            return await Login(domainName, userName, password, AuthenticationMethod.NTLMv2, cancellationToken).ConfigureAwait(false);
        }

        public async Task<Result.NTStatus> Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod, CancellationToken cancellationToken = default)
        {
            if (!m_isConnected)
            {
                return new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            Capabilities clientCapabilities = Capabilities.NTSMB | Capabilities.RpcRemoteApi | Capabilities.NTStatusCode | Capabilities.NTFind;
            if (m_unicode)
            {
                clientCapabilities |= Capabilities.Unicode;
            }
            if (m_largeFiles)
            {
                clientCapabilities |= Capabilities.LargeFiles;
            }
            if (m_largeRead)
            {
                clientCapabilities |= Capabilities.LargeRead;
            }

            if (m_serverChallenge != null)
            {
                SessionSetupAndXRequest request = new SessionSetupAndXRequest();
                request.MaxBufferSize = ClientMaxBufferSize;
                request.MaxMpxCount = m_maxMpxCount;
                request.Capabilities = clientCapabilities;
                request.AccountName = userName;
                request.PrimaryDomain = domainName;
                byte[] clientChallenge = new byte[8];
                new Random().NextBytes(clientChallenge);
                if (authenticationMethod == AuthenticationMethod.NTLMv1)
                {
                    request.OEMPassword = NTLMCryptography.ComputeLMv1Response(m_serverChallenge, password);
                    request.UnicodePassword = NTLMCryptography.ComputeNTLMv1Response(m_serverChallenge, password);
                }
                else if (authenticationMethod == AuthenticationMethod.NTLMv1ExtendedSessionSecurity)
                {
                    // [MS-CIFS] CIFS does not support Extended Session Security because there is no mechanism in CIFS to negotiate Extended Session Security
                    return new ArgumentException("SMB Extended Security must be negotiated in order for NTLMv1 Extended Session Security to be used");
                }
                else // NTLMv2
                {
                    // Note: NTLMv2 over non-extended security session setup is not supported under Windows Vista and later which will return STATUS_INVALID_PARAMETER.
                    // https://msdn.microsoft.com/en-us/library/ee441701.aspx
                    // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                    request.OEMPassword = NTLMCryptography.ComputeLMv2Response(m_serverChallenge, clientChallenge, password, userName, domainName);
                    NTLMv2ClientChallenge clientChallengeStructure = new NTLMv2ClientChallenge(DateTime.UtcNow, clientChallenge, AVPairUtils.GetAVPairSequence(domainName, Environment.MachineName));
                    byte[] temp = clientChallengeStructure.GetBytesPadded();
                    byte[] proofStr = NTLMCryptography.ComputeNTLMv2Proof(m_serverChallenge, temp, password, userName, domainName);
                    request.UnicodePassword = ByteUtils.Concatenate(proofStr, temp);
                }

                var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_SESSION_SETUP_ANDX, cancellationToken).ConfigureAwait(false);
                if (reply != null)
                {
                    m_isLoggedIn = (reply.Header.Status == NTStatus.STATUS_SUCCESS);

                    if (reply.Header.Status == NTStatus.STATUS_SUCCESS) return NTStatus.STATUS_SUCCESS;
                    else return new ErrorResponseException(reply.Header.Status);
                }
                else return error;
            }
            else // m_securityBlob != null
            {
                NTLMAuthenticationClient authenticationClient = new NTLMAuthenticationClient(domainName, userName, password, null, authenticationMethod);
                byte[] negotiateMessage = authenticationClient.InitializeSecurityContext(m_securityBlob);
                if (negotiateMessage == null)
                {
                    return new ErrorResponseException(NTStatus.SEC_E_INVALID_TOKEN);
                }

                SessionSetupAndXRequestExtended request = new SessionSetupAndXRequestExtended();
                request.MaxBufferSize = ClientMaxBufferSize;
                request.MaxMpxCount = m_maxMpxCount;
                request.Capabilities = clientCapabilities;
                request.SecurityBlob = negotiateMessage;

                var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_SESSION_SETUP_ANDX, cancellationToken).ConfigureAwait(false);
                while (reply != null && reply.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED && reply.Commands[0] is SessionSetupAndXResponseExtended)
                {
                    SessionSetupAndXResponseExtended response = (SessionSetupAndXResponseExtended)reply.Commands[0];
                    byte[] authenticateMessage = authenticationClient.InitializeSecurityContext(response.SecurityBlob);
                    if (authenticateMessage == null)
                    {
                        return new ErrorResponseException(NTStatus.SEC_E_INVALID_TOKEN);
                    }

                    m_userID = reply.Header.UID;
                    request = new SessionSetupAndXRequestExtended();
                    request.MaxBufferSize = ClientMaxBufferSize;
                    request.MaxMpxCount = m_maxMpxCount;
                    request.Capabilities = clientCapabilities;
                    request.SecurityBlob = authenticateMessage;

                    (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_SESSION_SETUP_ANDX, cancellationToken).ConfigureAwait(false);
                }

                if (reply != null && reply.Commands[0] is SessionSetupAndXResponseExtended)
                {
                    m_isLoggedIn = (reply.Header.Status == NTStatus.STATUS_SUCCESS);
                    if (m_isLoggedIn)
                    {
                        m_sessionKey = authenticationClient.GetSessionKey();
                        return NTStatus.STATUS_SUCCESS;
                    }
                    else return new ErrorResponseException(reply.Header.Status);
                }
                else
                {
                    if (error != null) return error;
                    else return new ErrorResponseException(NTStatus.STATUS_INVALID_SMB);
                }
            }
        }

        public async Task<Result.NTStatus> Logoff(CancellationToken cancellationToken = default)
        {
            if (!m_isConnected)
            {
                return new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffAndXRequest request = new LogoffAndXRequest();

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_LOGOFF_ANDX, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                m_isLoggedIn = (reply.Header.Status != NTStatus.STATUS_SUCCESS);

                if (reply.Header.Status == NTStatus.STATUS_SUCCESS) return NTStatus.STATUS_SUCCESS;
                else return new ErrorResponseException(reply.Header.Status);
            }
            else return error;
        }

        public async Task<Result<List<string>>> ListShares(CancellationToken cancellationToken = default)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                return new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            var treeConnectReply = await TreeConnect("IPC$", ServiceName.NamedPipe, cancellationToken).ConfigureAwait(false);
            ISMBAsyncFileStore namedPipeShare = treeConnectReply.Value;
            if (namedPipeShare == null)
            {
                return treeConnectReply.Error;
            }

            var listShareResponse = await ServerServiceHelper.ListShares(namedPipeShare, ShareType.DiskDrive, cancellationToken).ConfigureAwait(false);
            await namedPipeShare.Disconnect(cancellationToken).ConfigureAwait(false);
            return listShareResponse;
        }

        public async Task<Result<ISMBAsyncFileStore>> TreeConnect(string shareName, CancellationToken cancellationToken = default)
        {
            return await TreeConnect(shareName, ServiceName.AnyType, cancellationToken).ConfigureAwait(false);
        }

        public async Task<Result<ISMBAsyncFileStore>> TreeConnect(string shareName, ServiceName serviceName, CancellationToken cancellationToken = default)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                return new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            TreeConnectAndXRequest request = new TreeConnectAndXRequest();
            request.Path = shareName;
            request.Service = serviceName;
            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TREE_CONNECT_ANDX, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                var replyStatus = reply.Header.Status;
                if (replyStatus == NTStatus.STATUS_SUCCESS && reply.Commands[0] is TreeConnectAndXResponse)
                {
                    TreeConnectAndXResponse response = (TreeConnectAndXResponse)reply.Commands[0];
                    return new SMB1AsyncFileStore(this, reply.Header.TID);
                }
                else return new ErrorResponseException(replyStatus);
            }
            else
            {
                return error;
            }
        }

        private void Log(string message)
        {
            System.Diagnostics.Debug.Print(message);
        }

        internal async Task<Result<SMB1Message>> TrySendMessage(SMB1Command request, CommandName waitForRespnseCommandName, CancellationToken cancellationToken = default)
        {
            return await TrySendMessage(request, 0, waitForRespnseCommandName, cancellationToken).ConfigureAwait(false);
        }

        internal async Task<Result<SMB1Message>> TrySendMessage(SMB1Command request, ushort treeID, CommandName waitForRespnseCommandName, CancellationToken cancellationToken = default)
        {
            SMB1Message message = new SMB1Message();
            message.Header.UnicodeFlag = m_unicode;
            message.Header.ExtendedSecurityFlag = m_forceExtendedSecurity;
            message.Header.Flags2 |= HeaderFlags2.LongNamesAllowed | HeaderFlags2.LongNameUsed | HeaderFlags2.NTStatusCode;
            message.Header.UID = m_userID;
            message.Header.TID = treeID;
            message.Commands.Add(request);
            return await TrySendMessage(m_clientSocket, message, waitForRespnseCommandName, cancellationToken).ConfigureAwait(false);
        }

        public bool Unicode
        {
            get
            {
                return m_unicode;
            }
        }

        public bool LargeFiles
        {
            get
            {
                return m_largeFiles;
            }
        }

        public bool InfoLevelPassthrough
        {
            get
            {
                return m_infoLevelPassthrough;
            }
        }

        public bool LargeRead
        {
            get
            {
                return m_largeRead;
            }
        }

        public bool LargeWrite
        {
            get
            {
                return m_largeWrite;
            }
        }

        public uint ServerMaxBufferSize
        {
            get
            {
                return m_serverMaxBufferSize;
            }
        }

        public int MaxMpxCount
        {
            get
            {
                return m_maxMpxCount;
            }
        }

        public uint MaxReadSize
        {
            get
            {
                return (uint)ClientMaxBufferSize - (SMB1Header.Length + 3 + ReadAndXResponse.ParametersLength);
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                uint result = ServerMaxBufferSize - (SMB1Header.Length + 3 + WriteAndXRequest.ParametersFixedLength + 4);
                if (m_unicode)
                {
                    result--;
                }
                return result;
            }
        }

        public bool IsConnected
        {
            get
            {
                return m_isConnected;
            }
        }
    }
}