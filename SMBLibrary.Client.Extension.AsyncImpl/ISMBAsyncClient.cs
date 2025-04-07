using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public interface ISMBAsyncClient
    {
        Task<bool> Connect(string serverName, SMBTransportType transport, TimeSpan? responseTimeout = null, CancellationToken cancellationToken = default);

        Task<bool> Connect(IPAddress serverAddress, SMBTransportType transport, TimeSpan? responseTimeout = null, CancellationToken cancellationToken = default);

#if NET6_0_OR_GREATER
        Task Disconnect(CancellationToken cancellationToken = default);
#else
        void Disconnect();
#endif

        Task<Result.NTStatus> Login(string domainName, string userName, string password, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> Login(string domainName, string userName, string password, Client.AuthenticationMethod authenticationMethod, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> Logoff(CancellationToken cancellationToken = default);

        Task<Result<List<string>>> ListShares(CancellationToken cancellationToken = default);

        Task<Result<ISMBAsyncFileStore>> TreeConnect(string shareName, CancellationToken cancellationToken = default);

        uint MaxReadSize
        {
            get;
        }

        uint MaxWriteSize
        {
            get;
        }

        bool IsConnected
        {
            get;
        }
    }
}
