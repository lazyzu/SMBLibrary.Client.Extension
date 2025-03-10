using System;

namespace SMBLibrary.Client.Extension.FluentConnect
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

        private SMBCredientail(string userName, string password, string domainNmae = null)
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
        public static TSMBTransaction NewTransaction<TSMBTransaction>(this ISmbCredientailGetter credientailGetter, string path, Action<TSMBTransaction> afterConnectInitial, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            var (isParsed, parsedPath, parseError) = SMBPath.ParseFrom(path);
            if (isParsed) return NewTransaction<TSMBTransaction>(credientailGetter, parsedPath, afterConnectInitial, testClientTypes);
            else throw parseError;
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(this ISmbCredientailGetter credientailGetter, SMBPath path, Action<TSMBTransaction> afterConnectInitial, SMBClientFactory.TestClientSelection testClientTypes = SMBClientFactory.TestClientSelection.All)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (path == null) throw new ArgumentNullException(nameof(path));

            var credientail = credientailGetter.GetFrom(path);
            return SMBTransaction.NewTransaction<TSMBTransaction>(path, afterConnectInitial, credientail, testClientTypes);
        }
    }
}
