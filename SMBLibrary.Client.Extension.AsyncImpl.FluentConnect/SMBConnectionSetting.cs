using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect
{
    public interface ISMBConnectionSetting
    {
        SMBClientFactory.TestClientSelection Client { get; }
        SMBClientFactory.SMBTransportTypeSelection TransportType { get; }
        TimeSpan? ResponseTimeout { get; }
        ISMBCredientail Credientail { get; }
    }

    public class SMBConnectionSetting : ISMBConnectionSetting
    {
        private SMBClientFactory.TestClientSelection client;
        public SMBClientFactory.TestClientSelection Client => client;

        private SMBClientFactory.SMBTransportTypeSelection transportType;
        public SMBClientFactory.SMBTransportTypeSelection TransportType => transportType;

        private ISMBCredientail credientail;
        public ISMBCredientail Credientail => credientail;

        private TimeSpan? responseTimeout;
        public TimeSpan? ResponseTimeout => responseTimeout;

        private SMBConnectionSetting(SMBClientFactory.TestClientSelection client
            , SMBClientFactory.SMBTransportTypeSelection transportType
            , TimeSpan? responseTimeout
            , ISMBCredientail credientail)
        {
            this.client = client;
            this.transportType = transportType;
            this.responseTimeout = responseTimeout;
            this.credientail = credientail ?? SMBCredientail.NoCredientail;
        }

        public static SMBConnectionSetting From(SMBClientFactory.TestClientSelection client
            , SMBClientFactory.SMBTransportTypeSelection transportType
            , TimeSpan? responseTimeout
            , ISMBCredientail credientail)
            => new SMBConnectionSetting(client, transportType, responseTimeout, credientail);
    }

    public interface ISMBConnectionSettingGetter
    {
        ISMBConnectionSetting GetFrom(SMBPath path);
    }

    public static class SMBConnectionSettingGetterExtension
    {
        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(this ISMBConnectionSettingGetter connectionSettingGetter
            , string path
            , Action<TSMBTransaction> afterConnectInitial
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            var pathParseResponse = SMBPath.ParseFrom(path);
            if (pathParseResponse.IsSuccess) return await NewTransaction<TSMBTransaction>(connectionSettingGetter, pathParseResponse.Value, afterConnectInitial, cancellationToken);
            else throw pathParseResponse.Error;
        }

        public static async Task<TSMBTransaction> NewTransaction<TSMBTransaction>(this ISMBConnectionSettingGetter connectionSettingGetter
            , SMBPath path
            , Action<TSMBTransaction> afterConnectInitial
            , CancellationToken cancellationToken = default)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (path == null) throw new ArgumentNullException(nameof(path));

            var connectionSetting = connectionSettingGetter.GetFrom(path);
            return await SMBTransaction.NewTransaction<TSMBTransaction>(path, afterConnectInitial, connectionSetting.Credientail, connectionSetting.Client, connectionSetting.TransportType, connectionSetting.ResponseTimeout, cancellationToken);
        }
    }
}
