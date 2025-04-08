using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace SMBLibrary.Client.Extension.FluentConnect
{
    public interface ISMBConnectionSetting
    {
        SMBClientFactory.TestClientSelection Client { get; }
        SMBClientFactory.SMBTransportTypeSelection TransportType { get; }
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

        private SMBConnectionSetting(SMBClientFactory.TestClientSelection client
            , SMBClientFactory.SMBTransportTypeSelection transportType
            , ISMBCredientail credientail)
        {
            this.client = client;
            this.transportType = transportType;
            this.credientail = credientail ?? SMBCredientail.NoCredientail;
        }

        public static SMBConnectionSetting From(SMBClientFactory.TestClientSelection client
            , SMBClientFactory.SMBTransportTypeSelection transportType
            , ISMBCredientail credientail)
            => new SMBConnectionSetting(client, transportType, credientail);
    }

    public interface ISMBConnectionSettingGetter
    {
        ISMBConnectionSetting GetFrom(SMBPath path);
    }

    public static class SMBConnectionSettingGetterExtension
    {
        public static TSMBTransaction NewTransaction<TSMBTransaction>(this ISMBConnectionSettingGetter connectionSettingGetter
            , string path
            , Action<TSMBTransaction> afterConnectInitial)
            where TSMBTransaction : SMBTransaction, new()
        {
            var pathParseResponse = SMBPath.ParseFrom(path);
            if (pathParseResponse.IsSuccess) return NewTransaction<TSMBTransaction>(connectionSettingGetter, pathParseResponse.Value, afterConnectInitial);
            else throw pathParseResponse.Error;
        }

        public static TSMBTransaction NewTransaction<TSMBTransaction>(this ISMBConnectionSettingGetter connectionSettingGetter
            , SMBPath path
            , Action<TSMBTransaction> afterConnectInitial)
            where TSMBTransaction : SMBTransaction, new()
        {
            if (path == null) throw new ArgumentNullException(nameof(path));

            var connectionSetting = connectionSettingGetter.GetFrom(path);
            return SMBTransaction.NewTransaction<TSMBTransaction>(path, afterConnectInitial, connectionSetting.Credientail, connectionSetting.Client, connectionSetting.TransportType);
        }
    }
}
