using SMBLibrary.Client.Authentication;
using SMBLibrary.NetBios;
using SMBLibrary.SMB2;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Utilities;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public partial class SMB2AsyncClient : ISMBAsyncClient
    {
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        public static readonly uint ClientMaxTransactSize = 1048576;
        public static readonly uint ClientMaxReadSize = 1048576;
        public static readonly uint ClientMaxWriteSize = 1048576;
        private static readonly ushort DesiredCredits = 16;
        public static readonly int DefaultResponseTimeoutInMilliseconds = 5000;

        private string m_serverName;
        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket m_clientSocket;
        private ConnectionState m_connectionState;
        private int m_responseTimeoutInMilliseconds;

        private SMB2Dialect m_dialect;
        private bool m_signingRequired;
        private byte[] m_signingKey;
        private bool m_encryptSessionData;
        private byte[] m_encryptionKey;
        private byte[] m_decryptionKey;
        private uint m_maxTransactSize;
        private uint m_maxReadSize;
        private uint m_maxWriteSize;
        private ulong m_sessionID;
        private byte[] m_securityBlob;
        private byte[] m_sessionKey;
        private byte[] m_preauthIntegrityHashValue; // SMB 3.1.1
        private ushort m_availableCredits = 1;

        public SMB2AsyncClient()
        {
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public async Task<bool> Connect(string serverName, SMBTransportType transport, CancellationToken cancellationToken = default)
        {
            return await Connect(serverName, transport, responseTimeout: null, cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> Connect(string serverName, SMBTransportType transport, TimeSpan? responseTimeout = null, CancellationToken cancellationToken = default)
        {
            m_serverName = serverName;
            IPAddress[] hostAddresses = Dns.GetHostAddresses(serverName);
            if (hostAddresses.Length == 0)
            {
                throw new Exception(String.Format("Cannot resolve host name {0} to an IP address", serverName));
            }
            IPAddress serverAddress = IPAddressHelper.SelectAddressPreferIPv4(hostAddresses);
            return await Connect(serverAddress, transport, responseTimeout, cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, CancellationToken cancellationToken = default)
        {
            return await Connect(serverAddress, transport, responseTimeout: null, cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, TimeSpan? responseTimeout = null, CancellationToken cancellationToken = default)
        {
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            return await Connect(serverAddress, transport, port, (int)(responseTimeout?.TotalMilliseconds ?? DefaultResponseTimeoutInMilliseconds), cancellationToken).ConfigureAwait(false);
        }

        protected internal async Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, int port, int responseTimeoutInMilliseconds, CancellationToken cancellationToken = default)
        {
            if (m_serverName == null)
            {
                m_serverName = serverAddress.ToString();
            }

            m_transport = transport;
            if (!m_isConnected)
            {
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
                        if (! await ConnectSocket(serverAddress, port, cancellationToken).ConfigureAwait(false))
#else
                        if (!ConnectSocket(serverAddress, port))
#endif
                        {
                            return false;
                        }

                        NameServiceClient nameServiceClient = new NameServiceClient(serverAddress);
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
                var negotiateDialectResponse = await NegotiateDialect(cancellationToken).ConfigureAwait(false);
                if (negotiateDialectResponse.IsSuccess == false)
                {
                    m_clientSocket.Close();
                    m_isConnected = false;
                }
            }
            return m_isConnected;
        }

        private async Task<Result<bool>> NegotiateDialect(CancellationToken cancellationToken = default)
        {
            NegotiateRequest request = new NegotiateRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.Capabilities = Capabilities.Encryption;
            request.ClientGuid = Guid.NewGuid();
            request.ClientStartTime = DateTime.Now;
            request.Dialects.Add(SMB2Dialect.SMB202);
            request.Dialects.Add(SMB2Dialect.SMB210);
            request.Dialects.Add(SMB2Dialect.SMB300);
#if SMB302_CLIENT
            request.Dialects.Add(SMB2Dialect.SMB302);
#endif
#if SMB311_CLIENT
            request.Dialects.Add(SMB2Dialect.SMB311);
            request.NegotiateContextList = GetNegotiateContextList();
            m_preauthIntegrityHashValue = new byte[64];
#endif
            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);

            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS)
                {
                    if (response is NegotiateResponse negotiateResponse)
                    {
                        m_dialect = negotiateResponse.DialectRevision;
                        m_signingRequired = (negotiateResponse.SecurityMode & SecurityMode.SigningRequired) > 0;
                        m_maxTransactSize = Math.Min(negotiateResponse.MaxTransactSize, ClientMaxTransactSize);
                        m_maxReadSize = Math.Min(negotiateResponse.MaxReadSize, ClientMaxReadSize);
                        m_maxWriteSize = Math.Min(negotiateResponse.MaxWriteSize, ClientMaxWriteSize);
                        m_securityBlob = negotiateResponse.SecurityBuffer;
                        return true;
                    }
                    else
                    {
                        var errorMessage = $"Error response type, required {nameof(NegotiateResponse)}, but receive {response.GetType().Name}";
                        Log(errorMessage);
                        return new Exception(errorMessage);
                    }
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public async Task<Result.NTStatus> Login(string domainName, string userName, string password, CancellationToken cancellationToken = default)
        {
            return await Login(domainName, userName, password, AuthenticationMethod.NTLMv2).ConfigureAwait(false);
        }

        public async Task<Result.NTStatus> Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod, CancellationToken cancellationToken = default)
        {
            string spn = string.Format("cifs/{0}", m_serverName);
            NTLMAuthenticationClient authenticationClient = new NTLMAuthenticationClient(domainName, userName, password, spn, authenticationMethod);
            return await Login(authenticationClient, cancellationToken).ConfigureAwait(false);
        }

        public async Task<Result.NTStatus> Login(IAuthenticationClient authenticationClient, CancellationToken cancellationToken = default)
        {
            if (!m_isConnected)
            {
                return new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            byte[] negotiateMessage = authenticationClient.InitializeSecurityContext(m_securityBlob);
            if (negotiateMessage == null)
            {
                return new ErrorResponseException(NTStatus.SEC_E_INVALID_TOKEN);
            }

            SessionSetupRequest request = new SessionSetupRequest();
            request.SecurityMode = SecurityMode.SigningEnabled;
            request.SecurityBuffer = negotiateMessage;
            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            while (response is SessionSetupResponse sessionSetupResponse && response.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
            {
                byte[] authenticateMessage = authenticationClient.InitializeSecurityContext(sessionSetupResponse.SecurityBuffer);
                if (authenticateMessage == null)
                {
                    return new ErrorResponseException(NTStatus.SEC_E_INVALID_TOKEN);
                }

                m_sessionID = response.Header.SessionID;
                request = new SessionSetupRequest();
                request.SecurityMode = SecurityMode.SigningEnabled;
                request.SecurityBuffer = authenticateMessage;
                (isSuccess, response, error)  = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            }

            if (response is SessionSetupResponse finalSessionSetupResponse)
            {
                m_isLoggedIn = (response.Header.Status == NTStatus.STATUS_SUCCESS);
                if (m_isLoggedIn)
                {
                    m_sessionID = response.Header.SessionID;
                    m_sessionKey = authenticationClient.GetSessionKey();
                    SessionFlags sessionFlags = finalSessionSetupResponse.SessionFlags;
                    if ((sessionFlags & SessionFlags.IsGuest) > 0)
                    {
                        // [MS-SMB2] 3.2.5.3.1 If the SMB2_SESSION_FLAG_IS_GUEST bit is set in the SessionFlags field of the SMB2
                        // SESSION_SETUP Response and if RequireMessageSigning is FALSE, Session.SigningRequired MUST be set to FALSE.
                        m_signingRequired = false;
                    }
                    else
                    {
                        m_signingKey = SMB2Cryptography.GenerateSigningKey(m_sessionKey, m_dialect, m_preauthIntegrityHashValue);
                    }

                    if (m_dialect >= SMB2Dialect.SMB300)
                    {
                        m_encryptSessionData = (sessionFlags & SessionFlags.EncryptData) > 0;
                        m_encryptionKey = SMB2Cryptography.GenerateClientEncryptionKey(m_sessionKey, m_dialect, m_preauthIntegrityHashValue);
                        m_decryptionKey = SMB2Cryptography.GenerateClientDecryptionKey(m_sessionKey, m_dialect, m_preauthIntegrityHashValue);
                    }

                    return NTStatus.STATUS_SUCCESS;
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else
            {
                return error;
            }
        }

        public async Task<Result.NTStatus> Logoff(CancellationToken cancellationToken = default)
        {
            if (!m_isConnected)
            {
                return new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffRequest request = new LogoffRequest();
            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                m_isLoggedIn = (response.Header.Status != NTStatus.STATUS_SUCCESS);

                if (response.Header.Status == NTStatus.STATUS_SUCCESS) return NTStatus.STATUS_SUCCESS;
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public async Task<Result<List<string>>> ListShares(CancellationToken cancellationToken = default)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                return new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            var treeConnectResponse = await TreeConnect("IPC$", cancellationToken).ConfigureAwait(false);
            ISMBAsyncFileStore namedPipeShare = treeConnectResponse.Value;
            if (namedPipeShare == null)
            {
                return treeConnectResponse.Error;
            }

            var listShareResponse = await ServerServiceHelper.ListShares(namedPipeShare, m_serverName, SMBLibrary.Services.ShareType.DiskDrive, cancellationToken).ConfigureAwait(false);
            await namedPipeShare.Disconnect(cancellationToken).ConfigureAwait(false);
            return listShareResponse;
        }

        public async Task<Result<ISMBAsyncFileStore>> TreeConnect(string shareName, CancellationToken cancellationToken = default)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                return new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            string sharePath = String.Format(@"\\{0}\{1}", m_serverName, shareName);
            TreeConnectRequest request = new TreeConnectRequest();
            request.Path = sharePath;
            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                var responseStatus = response.Header.Status;
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is TreeConnectResponse)
                {
                    bool encryptShareData = (((TreeConnectResponse)response).ShareFlags & ShareFlags.EncryptData) > 0;
                    return new SMB2AsyncFileStore(this, response.Header.TreeID, m_encryptSessionData || encryptShareData);
                }
                else return new ErrorResponseException(responseStatus);
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

        internal async Task<Result<SMB2Command>> TrySendCommand(SMB2Command request, CancellationToken cancellationToken = default)
        {
            return await TrySendCommand(request, m_encryptSessionData, cancellationToken).ConfigureAwait(false);
        }

        internal async Task<Result<SMB2Command>> TrySendCommand(SMB2Command request, bool encryptData, CancellationToken cancellationToken = default)
        {
            if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
            {
                request.Header.CreditCharge = 0;
                request.Header.Credits = 1;
                m_availableCredits -= 1;
            }
            else
            {
                if (request.Header.CreditCharge == 0)
                {
                    request.Header.CreditCharge = 1;
                }

                if (m_availableCredits < request.Header.CreditCharge)
                {
                    return new Exception("Not enough credits");
                }

                m_availableCredits -= request.Header.CreditCharge;

                if (m_availableCredits < DesiredCredits)
                {
                    request.Header.Credits += (ushort)(DesiredCredits - m_availableCredits);
                }
            }
            
            // [MS-SMB2] If the client encrypts the message [..] then the client MUST set the Signature field of the SMB2 header to zero
            if (m_signingRequired && !encryptData)
            {
                request.Header.IsSigned = (m_sessionID != 0 && ((request.CommandName == SMB2CommandName.TreeConnect || request.Header.TreeID != 0) ||
                                                                (m_dialect >= SMB2Dialect.SMB300 && request.CommandName == SMB2CommandName.Logoff)));
                if (request.Header.IsSigned)
                {
                    request.Header.Signature = new byte[16]; // Request could be reused
                    byte[] buffer = request.GetBytes();
                    byte[] signature = SMB2Cryptography.CalculateSignature(m_signingKey, m_dialect, buffer, 0, buffer.Length);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    request.Header.Signature = ByteReader.ReadBytes(signature, 0, 16);
                }
            }
            return await TrySendCommand(m_clientSocket, request, encryptData ? m_encryptionKey : null, cancellationToken).ConfigureAwait(false);
        }

        /// <remarks>SMB 3.1.1 only</remarks>
        private List<NegotiateContext> GetNegotiateContextList()
        {
            PreAuthIntegrityCapabilities preAuthIntegrityCapabilities = new PreAuthIntegrityCapabilities();
            preAuthIntegrityCapabilities.HashAlgorithms.Add(HashAlgorithm.SHA512);
            preAuthIntegrityCapabilities.Salt = new byte[32];
            new Random().NextBytes(preAuthIntegrityCapabilities.Salt);

            EncryptionCapabilities encryptionCapabilities = new EncryptionCapabilities();
            encryptionCapabilities.Ciphers.Add(CipherAlgorithm.Aes128Ccm);

            return new List<NegotiateContext>()
            {
                preAuthIntegrityCapabilities,
                encryptionCapabilities
            };
        }

        public uint MaxTransactSize
        {
            get
            {
                return m_maxTransactSize;
            }
        }

        public uint MaxReadSize
        {
            get
            {
                return m_maxReadSize;
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                return m_maxWriteSize;
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
