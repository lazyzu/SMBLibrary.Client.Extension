using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace SMBLibrary.Client.Extension.FluentConnect
{
    public abstract class SMBTransaction : IDisposable
    {
        public ISMBClient Client { get; private set; }

        private bool hasLogin;
        private bool disposedValue;

        public static TSMBTransaction NewTransaction<TSMBTransaction>(IPAddress serverAddress, Action<TSMBTransaction> afterConnectInitial, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            var transaction = new TSMBTransaction();
            transaction.ConnectOnlyInitial(serverAddress, testClientTypes);
            afterConnectInitial(transaction);
            return transaction;
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(IPAddress serverAddress, Action<TSMBTransaction> afterConnectInitial, string username, string password, string domainName = null, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            var transaction = new TSMBTransaction();
            transaction.ConnectAndLoginInitial(serverAddress, username, password, domainName, testClientTypes);
            afterConnectInitial(transaction);
            return transaction;
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(IPAddress serverAddress, Action<TSMBTransaction> afterConnectInitial, ISMBCredientail credientail, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            var transaction = new TSMBTransaction();
            if (credientail == null) transaction.ConnectOnlyInitial(serverAddress, testClientTypes);
            else transaction.ConnectAndLoginInitial(serverAddress, credientail.UserName, credientail.Password, credientail.DomainName, testClientTypes);
            afterConnectInitial(transaction);
            return transaction;
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(string serverName, Action<TSMBTransaction> afterConnectInitial, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            var (isSuccess, serverAddress, error) = SMBClientFactory.LoadServerAddress(serverName);
            if (isSuccess) return SMBTransaction.NewTransaction<TSMBTransaction>(serverAddress, afterConnectInitial, testClientTypes);
            else throw error;
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(string serverName, Action<TSMBTransaction> afterConnectInitial, string username, string password, string domainName = null, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            var (isSuccess, serverAddress, error) = SMBClientFactory.LoadServerAddress(serverName);
            if (isSuccess) return SMBTransaction.NewTransaction<TSMBTransaction>(serverAddress, afterConnectInitial, username, password, domainName, testClientTypes);
            else throw error;
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(string serverName, Action<TSMBTransaction> afterConnectInitial, ISMBCredientail credientail, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            var (isSuccess, serverAddress, error) = SMBClientFactory.LoadServerAddress(serverName);
            if (isSuccess) return SMBTransaction.NewTransaction<TSMBTransaction>(serverAddress, afterConnectInitial, credientail, testClientTypes);
            else throw error;
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(SMBPath path, Action<TSMBTransaction> afterConnectInitial, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (IPAddress.TryParse(path.HostName, out var hostAddress))
            {
                return SMBTransaction.NewTransaction<TSMBTransaction>(hostAddress, afterConnectInitial, testClientTypes);
            }
            else return SMBTransaction.NewTransaction<TSMBTransaction>(path.HostName, afterConnectInitial, testClientTypes);
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(SMBPath path, Action<TSMBTransaction> afterConnectInitial, string username, string password, string domainName = null, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (IPAddress.TryParse(path.HostName, out var hostAddress))
            {
                return SMBTransaction.NewTransaction<TSMBTransaction>(hostAddress, afterConnectInitial, username, password, domainName, testClientTypes);
            }
            else return SMBTransaction.NewTransaction<TSMBTransaction>(path.HostName, afterConnectInitial, username, password, domainName, testClientTypes);
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(SMBPath path, Action<TSMBTransaction> afterConnectInitial, ISMBCredientail credientail, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (IPAddress.TryParse(path.HostName, out var hostAddress))
            {
                return SMBTransaction.NewTransaction<TSMBTransaction>(hostAddress, afterConnectInitial, credientail, testClientTypes);
            }
            else return SMBTransaction.NewTransaction<TSMBTransaction>(path.HostName, afterConnectInitial, credientail, testClientTypes);
        }

        protected virtual void ConnectOnlyInitial(IPAddress serverAddress, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
        {
            if (serverAddress == null) throw new ArgumentNullException(nameof(serverAddress));

            var (isConnectionSuccess, connectionInfo, error) = SMBClientFactory.TryConnectWithAddress(serverAddress, testClientTypes);
            if (isConnectionSuccess)
            {
                this.Client = connectionInfo.SMBClient;
                this.hasLogin = false;
            }
            else throw error;
        }

        protected virtual void ConnectAndLoginInitial(IPAddress serverAddress, string username, string password, string domainName, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
        {
            if (serverAddress == null) throw new ArgumentNullException(nameof(serverAddress));

            var (isConnectionSuccess, connectionInfo, error) = SMBClientFactory.TryConnectWithAddress(serverAddress, testClientTypes);
            if (isConnectionSuccess)
            {
                var loginStatus = connectionInfo.SMBClient.Login(domainName ?? String.Empty, username, password);
                if (loginStatus != NTStatus.STATUS_SUCCESS)
                {
                    throw new InvalidOperationException($"Login to {serverAddress} operation is failed with {loginStatus}");
                }

                this.Client = connectionInfo.SMBClient;
                this.hasLogin = true;
            }
            else throw error;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: 處置受控狀態 (受控物件)
                    if (hasLogin) this.Client.Logoff();
                    if (this.Client.IsConnected) this.Client.Disconnect();
                }

                // TODO: 釋出非受控資源 (非受控物件) 並覆寫完成項
                // TODO: 將大型欄位設為 Null
                disposedValue = true;
            }
        }

        // // TODO: 僅有當 'Dispose(bool disposing)' 具有會釋出非受控資源的程式碼時，才覆寫完成項
        // ~SmbWork()
        // {
        //     // 請勿變更此程式碼。請將清除程式碼放入 'Dispose(bool disposing)' 方法
        //     Dispose(disposing: false);
        // }

        public virtual void Dispose()
        {
            // 請勿變更此程式碼。請將清除程式碼放入 'Dispose(bool disposing)' 方法
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    public class SMBSimpleTransaction : SMBTransaction
    {
        public SMBFile FileHandle { get; private set; }
        public SMBDirectory FolderHandle { get; private set; }

        public void InitialHandles()
        {
            this.FileHandle = new SMBFile(this.Client);
            this.FolderHandle = new SMBDirectory(this.Client);
        }
    }
}
