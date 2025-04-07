using SMBLibrary.Client.Extension.AsyncImpl.FluentConnect.Handle;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect
{
    public abstract class SMBTransaction : IAsyncDisposable
    {
        public ISMBAsyncClient Client { get; internal set; }

        private bool hasLogin;
        private bool disposedValue;

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(IPAddress serverAddress
            , Action<TSMBTransaction> afterConnectInitial
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            var transaction = new TSMBTransaction();
            await transaction.ConnectOnlyInitial(serverAddress, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            afterConnectInitial(transaction);
            return transaction;
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(IPAddress serverAddress
            , Action<TSMBTransaction> afterConnectInitial
            , string username, string password, string domainName = null
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            var transaction = new TSMBTransaction();
            await transaction.ConnectAndLoginInitial(serverAddress, username, password, domainName, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            afterConnectInitial(transaction);
            return transaction;
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(IPAddress serverAddress
            , Action<TSMBTransaction> afterConnectInitial
            , ISMBCredientail credientail
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            var transaction = new TSMBTransaction();
            if (credientail == null) await transaction.ConnectOnlyInitial(serverAddress, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            else await transaction.ConnectAndLoginInitial(serverAddress, credientail.UserName, credientail.Password, credientail.DomainName, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            afterConnectInitial(transaction);
            return transaction;
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(string serverName
            , Action<TSMBTransaction> afterConnectInitial
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            var (isSuccess, serverAddress, error) = SMBClientFactory.LoadServerAddress(serverName);
            if (isSuccess) return await SMBTransaction.NewTransaction<TSMBTransaction>(serverAddress, afterConnectInitial, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            else throw error;
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(string serverName
            , Action<TSMBTransaction> afterConnectInitial
            , string username, string password, string domainName = null
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            var (isSuccess, serverAddress, error) = SMBClientFactory.LoadServerAddress(serverName);
            if (isSuccess) return await SMBTransaction.NewTransaction<TSMBTransaction>(serverAddress, afterConnectInitial, username, password, domainName, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            else throw error;
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(string serverName
            , Action<TSMBTransaction> afterConnectInitial
            , ISMBCredientail credientail
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            var (isSuccess, serverAddress, error) = SMBClientFactory.LoadServerAddress(serverName);
            if (isSuccess) return await SMBTransaction.NewTransaction<TSMBTransaction>(serverAddress, afterConnectInitial, credientail, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            else throw error;
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(SMBPath path
            , Action<TSMBTransaction> afterConnectInitial
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (IPAddress.TryParse(path.HostName, out var hostAddress))
            {
                return await SMBTransaction.NewTransaction<TSMBTransaction>(hostAddress, afterConnectInitial, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            }
            else return await SMBTransaction.NewTransaction<TSMBTransaction>(path.HostName, afterConnectInitial, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(SMBPath path
            , Action<TSMBTransaction> afterConnectInitial
            , string username, string password, string domainName = null
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (IPAddress.TryParse(path.HostName, out var hostAddress))
            {
                return await SMBTransaction.NewTransaction<TSMBTransaction>(hostAddress, afterConnectInitial, username, password, domainName, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            }
            else return await SMBTransaction.NewTransaction<TSMBTransaction>(path.HostName, afterConnectInitial, username, password, domainName, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(SMBPath path
            , Action<TSMBTransaction> afterConnectInitial
            , ISMBCredientail credientail
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (IPAddress.TryParse(path.HostName, out var hostAddress))
            {
                return await SMBTransaction.NewTransaction<TSMBTransaction>(hostAddress, afterConnectInitial, credientail, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            }
            else return await SMBTransaction.NewTransaction<TSMBTransaction>(path.HostName, afterConnectInitial, credientail, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
        }

        protected virtual async Task ConnectOnlyInitial(IPAddress serverAddress
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
        {
            if (serverAddress == null) throw new ArgumentNullException(nameof(serverAddress));

            var connectResponse = await SMBClientFactory.TryConnectWithAddress(serverAddress, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            if (connectResponse.IsSuccess)
            {
                this.Client = connectResponse.Value.SMBClient;
                this.hasLogin = false;
            }
            else throw connectResponse.Error;
        }

        protected virtual async Task ConnectAndLoginInitial(IPAddress serverAddress
            , string username, string password, string domainName
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
        {
            if (serverAddress == null) throw new ArgumentNullException(nameof(serverAddress));

            var connectResponse = await SMBClientFactory.TryConnectWithAddress(serverAddress, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            if (connectResponse.IsSuccess)
            {
                var loginResponse = await connectResponse.Value.SMBClient.Login(domainName ?? String.Empty, username, password, cancellationToken);
                if (loginResponse.IsSuccess == false)
                {
                    throw loginResponse.Error;
                }

                this.Client = connectResponse.Value.SMBClient;
                this.hasLogin = true;
            }
            else throw connectResponse.Error;
        }

        public async ValueTask DisposeAsync()
        {
            await DisposeAsyncCore(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual async ValueTask DisposeAsyncCore(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: 處置受控狀態 (受控物件)
                    if (hasLogin) await this.Client?.Logoff();
#if NET6_0_OR_GREATER
                    if (this.Client?.IsConnected ?? false) await this.Client?.Disconnect();
#else
                    if (this.Client?.IsConnected ?? false) this.Client?.Disconnect();
#endif
                }

                this.Client = null;

                disposedValue = true;
            }
        }
    }

    public class SMBSimpleTransaction : SMBTransaction
    {
        public SMBFile FileHandle { get; private set; }
        public SMBDirectory FolderHandle { get; private set; }

        public void InitialHandles()
        {
            this.FileHandle = new SMBFile(this.Client, this);
            this.FolderHandle = new SMBDirectory(this.Client, this);
        }
    }
}
