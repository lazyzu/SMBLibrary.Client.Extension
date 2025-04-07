using SMBLibrary.NetBios;
using SMBLibrary.SMB1;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public partial class SMB1AsyncClient
    {
        private SmbMessageTaskCompletionSource m_sessionResponseCommand;
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

            m_connectionState = new Client.ConnectionState(m_clientSocket);
            NBTConnectionReceiveBuffer buffer = m_connectionState.ReceiveBuffer;
            m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), m_connectionState);
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
                            buffer.Dispose();
                            Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                        }
                        catch (SocketException ex)
                        {
                            m_isConnected = false;
                            buffer.Dispose();
                            Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                        }
                    }
                }
            }
        }

        private void ProcessConnectionBuffer(Client.ConnectionState state)
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

        private void ProcessPacket(SessionPacket packet, Client.ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                SMB1Message message;
                try
                {
                    message = SMB1Message.GetSMB1Message(packet.Trailer);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB1 message: " + ex.Message);
                    state.ClientSocket.Close();
                    state.ReceiveBuffer.Dispose();
                    m_isConnected = false;
                    return;
                }

                // [MS-CIFS] 3.2.5.1 - If the MID value is the reserved value 0xFFFF, the message can be an OpLock break
                // sent by the server. Otherwise, if the PID and MID values of the received message are not found in the
                // Client.Connection.PIDMIDList, the message MUST be discarded.
                if ((message.Header.MID == 0xFFFF && message.Header.Command == CommandName.SMB_COM_LOCKING_ANDX) ||
                    (message.Header.PID == 0 && message.Header.MID == 0))
                {
                    var waitForRespsonseCommandName = m_sessionResponseCommand?.WaitForRespsonseCommandName;
                    if (waitForRespsonseCommandName.HasValue && waitForRespsonseCommandName == message.Commands[0].CommandName)
                    {
                        m_sessionResponseCommand?.TrySetResult(message);
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
                m_userID = 0;
            }
        }

        private async Task<Result<SMB1Message>> TrySendMessage(Socket socket, SMB1Message message, CommandName waitForRespnseCommandName, CancellationToken cancellationToken = default)
        {
            if (m_isConnected == false) return new AccessViolationException("Disconnected");

            SmbMessageTaskCompletionSource sendingSmbMessage = new SmbMessageTaskCompletionSource(message, waitForRespnseCommandName);

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

                    SessionMessagePacket packet = new SessionMessagePacket();
                    packet.Trailer = message.GetBytes();
                    
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
                            sendingSmbMessage.TrySetException(new AccessViolationException("Disconnected", ex));
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

        private class SmbMessageTaskCompletionSource : TaskCompletionSource<Result<SMB1Message>>
        {
            public readonly SMB1Message SendedCommand;
            public readonly CommandName WaitForRespsonseCommandName;

            public SmbMessageTaskCompletionSource(SMB1Message sendedCommand, CommandName waitForRespsonseCommandName) : base(TaskCreationOptions.RunContinuationsAsynchronously)
            {
                this.SendedCommand = sendedCommand;
                this.WaitForRespsonseCommandName = waitForRespsonseCommandName;
            }
        }
    }
}
