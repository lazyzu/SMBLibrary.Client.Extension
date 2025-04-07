using SMBLibrary.NetBios;
using SMBLibrary.SMB2;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Utilities;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public partial class SMB2AsyncClient
    {
        private uint m_messageID = 0;

        private SmbCommandTaskCompletionSource m_sessionResponseCommand;
        private readonly SemaphoreSlim m_sendMessageSemaphoreSlim = new SemaphoreSlim(1);

        private TaskCompletionSource<Result<SessionPacket>> m_sessionResponsePacket;
        private readonly SemaphoreSlim m_sendPackageSemaphoreSlim = new SemaphoreSlim(1);

#if NET5_0_OR_GREATER
        private async Task<bool> ConnectSocket(IPAddress serverAddress, int port, CancellationToken cancellationToken = default)
#else
        private bool ConnectSocket(IPAddress serverAddress, int port)
#endif
        {
            m_clientSocket = new Socket(serverAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            try
            {
#if NET5_0_OR_GREATER
                await m_clientSocket.ConnectAsync(serverAddress, port, cancellationToken).ConfigureAwait(false);
#else
                m_clientSocket.Connect(serverAddress, port);
#endif
            }
            catch (SocketException)
            {
                return false;
            }

            m_connectionState = new ConnectionState(m_clientSocket);
            NBTConnectionReceiveBuffer buffer = m_connectionState.ReceiveBuffer;
            var asyncResult = m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), m_connectionState);
            return true;
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            ConnectionState state = (ConnectionState)ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            lock (state.ReceiveBuffer)
            {
                int numberOfBytesReceived = 0;
                try
                {
                    numberOfBytesReceived = clientSocket.EndReceive(ar);
                }
                catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
                {
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                    return;
                }
                catch (ObjectDisposedException)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                    state.ReceiveBuffer.Dispose();
                    return;
                }
                catch (SocketException ex)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                    state.ReceiveBuffer.Dispose();
                    return;
                }

                if (numberOfBytesReceived == 0)
                {
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                }
                else
                {
                    NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
                    buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                    ProcessConnectionBuffer(state);

                    if (clientSocket.Connected)
                    {
                        try
                        {
                            clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
                        }
                        catch (ObjectDisposedException)
                        {
                            m_isConnected = false;
                            Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                            buffer.Dispose();
                        }
                        catch (SocketException ex)
                        {
                            m_isConnected = false;
                            Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                            buffer.Dispose();
                        }
                    }
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    Log("[ProcessConnectionBuffer] Invalid packet");
                    state.ClientSocket.Close();
                    state.ReceiveBuffer.Dispose();
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, state);
                }
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                byte[] messageBytes;
                if (m_dialect >= SMB2Dialect.SMB300 && SMB2TransformHeader.IsTransformHeader(packet.Trailer, 0))
                {
                    SMB2TransformHeader transformHeader = new SMB2TransformHeader(packet.Trailer, 0);
                    byte[] encryptedMessage = ByteReader.ReadBytes(packet.Trailer, SMB2TransformHeader.Length, (int)transformHeader.OriginalMessageSize);
                    messageBytes = SMB2Cryptography.DecryptMessage(m_decryptionKey, transformHeader, encryptedMessage);
                }
                else
                {
                    messageBytes = packet.Trailer;
                }

                SMB2Command command;
                try
                {
                    command = SMB2Command.ReadResponse(messageBytes, 0);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB2 response: " + ex.Message);
                    state.ClientSocket.Close();
                    m_isConnected = false;
                    state.ReceiveBuffer.Dispose();
                    return;
                }

                if (m_preauthIntegrityHashValue != null && (command is NegotiateResponse || (command is SessionSetupResponse sessionSetupResponse && sessionSetupResponse.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)))
                {
                    m_preauthIntegrityHashValue = SMB2Cryptography.ComputeHash(HashAlgorithm.SHA512, ByteUtils.Concatenate(m_preauthIntegrityHashValue, messageBytes));
                }

                m_availableCredits += command.Header.Credits;

                if (m_transport == SMBTransportType.DirectTCPTransport && command is NegotiateResponse)
                {
                    NegotiateResponse negotiateResponse = (NegotiateResponse)command;
                    if ((negotiateResponse.Capabilities & Capabilities.LargeMTU) > 0)
                    {
                        // [MS-SMB2] 3.2.5.1 Receiving Any Message - If the message size received exceeds Connection.MaxTransactSize, the client SHOULD disconnect the connection.
                        // Note: Windows clients do not enforce the MaxTransactSize value.
                        // We use a value that we have observed to work well with both Microsoft and non-Microsoft servers.
                        // see https://github.com/TalAloni/SMBLibrary/issues/239
                        int serverMaxTransactSize = (int)Math.Max(negotiateResponse.MaxTransactSize, negotiateResponse.MaxReadSize);
                        int maxPacketSize = SessionPacket.HeaderLength + (int)Math.Min(serverMaxTransactSize, ClientMaxTransactSize) + 256;
                        if (maxPacketSize > state.ReceiveBuffer.Buffer.Length)
                        {
                            state.ReceiveBuffer.IncreaseBufferSize(maxPacketSize);
                        }
                    }
                }

                // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request,
                // and the client MUST NOT attempt to locate the request, but instead process it as follows:
                // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19.
                // Otherwise, the response MUST be discarded as invalid.
                if (command.Header.MessageID != 0xFFFFFFFFFFFFFFFF || command.Header.Command == SMB2CommandName.OplockBreak)
                {
                    var waitForResponseMessageId = m_sessionResponseCommand?.SendedCommand?.Header?.MessageID;
                    if (waitForResponseMessageId.HasValue && waitForResponseMessageId == command.MessageID)
                    {
                        m_sessionResponseCommand?.TrySetResult(command);
                    }
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_sessionResponsePacket?.TrySetResult(packet);
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
                state.ReceiveBuffer.Dispose();
            }
        }

#if NET6_0_OR_GREATER
        public async Task Disconnect(CancellationToken cancellationToken = default)
#else
        public void Disconnect()
#endif
        {
            if (m_isConnected)
            {
#if NET6_0_OR_GREATER
                await m_clientSocket.DisconnectAsync(false, cancellationToken).ConfigureAwait(false);
#else
                m_clientSocket.Disconnect(false);
#endif
                m_clientSocket.Close();
                lock (m_connectionState.ReceiveBuffer)
                {
                    m_connectionState.ReceiveBuffer.Dispose();
                }

                m_sendMessageSemaphoreSlim.Dispose();
                m_sendPackageSemaphoreSlim.Dispose();

                m_isConnected = false;
                m_messageID = 0;
                m_sessionID = 0;
                m_availableCredits = 1;
            }
        }

        private async Task<Result<SMB2Command>> TrySendCommand(Socket socket, SMB2Command request, byte[] encryptionKey, CancellationToken cancellationToken = default)
        {
            if (m_isConnected == false) return new AccessViolationException("Disconnected");

            SmbCommandTaskCompletionSource sendingSmbMessage = new SmbCommandTaskCompletionSource(request);

            try
            {
                await m_sendPackageSemaphoreSlim.WaitAsync(cancellationToken).ConfigureAwait(false);

                try
                {
                    m_sessionResponseCommand = sendingSmbMessage;

                    if (cancellationToken.IsCancellationRequested) return new OperationCanceledException();
                    else cancellationToken.Register(() =>
                    {
                        sendingSmbMessage.TrySetResult(new OperationCanceledException());
                    });

                    var responseTimeoutSource = new CancellationTokenSource(m_responseTimeoutInMilliseconds);
                    responseTimeoutSource.Token.Register(() =>
                    {
                        sendingSmbMessage.TrySetResult(new TimeoutException($"no response in {m_responseTimeoutInMilliseconds}ms"));
                    });

                    request.Header.MessageID = m_messageID;
                    request.Header.SessionID = m_sessionID;

                    SessionMessagePacket packet = new SessionMessagePacket();
                    if (encryptionKey != null)
                    {
                        byte[] requestBytes = request.GetBytes();
                        packet.Trailer = SMB2Cryptography.TransformMessage(encryptionKey, requestBytes, request.Header.SessionID);
                    }
                    else
                    {
                        packet.Trailer = request.GetBytes();
                        if (m_preauthIntegrityHashValue != null && (request is NegotiateRequest || request is SessionSetupRequest))
                        {
                            m_preauthIntegrityHashValue = SMB2Cryptography.ComputeHash(HashAlgorithm.SHA512, ByteUtils.Concatenate(m_preauthIntegrityHashValue, packet.Trailer));
                        }
                    }
                    
                    byte[] packetBytes = packet.GetBytes();
                    socket.BeginSend(packetBytes, 0, packetBytes.Length, SocketFlags.None, asyncResult =>
                    {
                        try
                        {
                            socket.EndSend(asyncResult);
                        }
                        catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
                        {
                            m_isConnected = false;
                            sendingSmbMessage.TrySetResult(new AccessViolationException("Disconnected", ex));
                        }
                    }, packetBytes);
                    return await sendingSmbMessage.Task.ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
                {
                    m_isConnected = false;
                    return new AccessViolationException("Disconnected", ex);
                }
            }
            catch (ObjectDisposedException ex)
            {
                return new AccessViolationException("Disconnected", ex);
            }
            catch (OperationCanceledException ex)
            {
                return ex;
            }
            finally
            {
                if (m_dialect == SMB2Dialect.SMB202 || m_transport == SMBTransportType.NetBiosOverTCP)
                {
                    m_messageID++;
                }
                else
                {
                    m_messageID += request.Header.CreditCharge;
                }

                m_sessionResponseCommand = null;
                m_sendPackageSemaphoreSlim.Release();
            }
        }

        private async Task<Result<SessionPacket>> TrySendPacket(Socket socket, SessionPacket packet, CancellationToken cancellationToken = default)
        {
            if (m_isConnected == false) return new AccessViolationException("Disconnected");

            try
            {
                await m_sendPackageSemaphoreSlim.WaitAsync(cancellationToken).ConfigureAwait(false);

                try
                {
                    var currentSessionResponsePacket = m_sessionResponsePacket = new TaskCompletionSource<Result<SessionPacket>>(TaskCreationOptions.RunContinuationsAsynchronously);

                    if (cancellationToken.IsCancellationRequested) return new OperationCanceledException();
                    else cancellationToken.Register(() => currentSessionResponsePacket.TrySetResult(new OperationCanceledException()));

                    var responseTimeoutSource = new CancellationTokenSource(m_responseTimeoutInMilliseconds);
                    responseTimeoutSource.Token.Register(() =>
                    {
                        currentSessionResponsePacket.TrySetResult(new TimeoutException($"no response in {m_responseTimeoutInMilliseconds}ms"));
                    });

                    byte[] packetBytes = packet.GetBytes();
                    socket.BeginSend(packetBytes, 0, packetBytes.Length, SocketFlags.None, asyncResult =>
                    {
                        try
                        {
                            socket.EndSend(asyncResult);
                        }
                        catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
                        {
                            m_isConnected = false;
                            currentSessionResponsePacket.TrySetResult(new AccessViolationException("Disconnected", ex));
                        }
                    }, packetBytes);
                    return await currentSessionResponsePacket.Task.ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
                {
                    m_isConnected = false;
                    return new AccessViolationException("Disconnected", ex);
                }
            }
            catch (ObjectDisposedException ex)
            {
                return new AccessViolationException("Disconnected", ex);
            }
            catch (OperationCanceledException ex)
            {
                return ex;
            }
            finally
            {
                m_sessionResponsePacket = null;
                m_sendPackageSemaphoreSlim.Release();
            }
        }

        private class SmbCommandTaskCompletionSource : TaskCompletionSource<Result<SMB2Command>>
        {
            public readonly SMB2Command SendedCommand;

            public SmbCommandTaskCompletionSource(SMB2Command sendedCommand) : base(TaskCreationOptions.RunContinuationsAsynchronously)
            {
                this.SendedCommand = sendedCommand;
            }
        }
    }
}
