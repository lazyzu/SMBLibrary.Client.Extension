using System;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect
{
    public interface ISMBCredientail
    {
        string DomainName { get; }
        string UserName { get; }
        string Password { get; }
    }

    public class SMBCredientail : ISMBCredientail
    {
        private readonly string domainName;
        public string DomainName => domainName;

        private readonly string userName;
        public string UserName => userName;

        private readonly string password;
        public string Password => password;

        private SMBCredientail(string userName, string password, string domainName = null)
        {
            this.userName = userName?.Trim();
            this.password = password?.Trim();
            this.domainName = domainName?.Trim();

            if (string.IsNullOrEmpty(this.userName)) throw new ArgumentNullException(nameof(userName));
            if (string.IsNullOrEmpty(this.password)) throw new ArgumentNullException(nameof(password));
        }

        public static SMBCredientail From(string userName, string password, string domainNmae = null)
            => new SMBCredientail(userName, password, domainNmae);

        public static SMBCredientail NoCredientail = null;
    }

    public interface ISmbCredientailGetter
    {
        ISMBCredientail GetFrom(SMBPath path);
    }

    public static class SMBCredientailGetterExtension
    {
        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(this ISmbCredientailGetter credientailGetter
            , string path
            , Action<TSMBTransaction> afterConnectInitial
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            var pathParseResponse = SMBPath.ParseFrom(path);
            if (pathParseResponse.IsSuccess) return await NewTransaction<TSMBTransaction>(credientailGetter, pathParseResponse.Value, afterConnectInitial, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            else throw pathParseResponse.Error;
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(this ISmbCredientailGetter credientailGetter
            , SMBPath path
            , Action<TSMBTransaction> afterConnectInitial
            , SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All
            , SMBClientFactory.SMBTransportTypeSelection transportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (path == null) throw new ArgumentNullException(nameof(path));

            var credientail = credientailGetter.GetFrom(path);
            return await SMBTransaction.NewTransaction<TSMBTransaction>(path, afterConnectInitial, credientail, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
        }
    }
}
