using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect
{
    public class SMBClientFactory
    {
        [Flags]
        public enum TestClientSelection
        {
            None,
            SMB1Client,
            SMB2Client,
            All = SMB1Client | SMB2Client
        }

        [Flags]
        public enum SMBTransportTypeSelection
        {
            None,
            NetBiosOverTCP,
            DirectTCPTransport,
            All = NetBiosOverTCP | DirectTCPTransport
        }

        public class ConnectionInfo
        {
            public readonly ISMBAsyncClient SMBClient;
            public readonly string TransportType;

            public string Dialect
            {
                get
                {
                    if (SMBClient is SMB1AsyncClient) return DialectSelection.CIFS;
                    else if (SMBClient is SMB2AsyncClient SMB2Client)
                    {
                        try
                        {
                            var dialectFieldInfo = typeof(SMB2AsyncClient).GetField("m_dialect", System.Reflection.BindingFlags.NonPublic
                                                                                          | System.Reflection.BindingFlags.Instance);

                            if (dialectFieldInfo.GetValue(SMBClient) is SMB2.SMB2Dialect dialect)
                            {
                                switch (dialect)
                                {
                                    case SMB2.SMB2Dialect.SMB202:
                                        return DialectSelection.SMB202;
                                    case SMB2.SMB2Dialect.SMB210:
                                        return DialectSelection.SMB210;
                                    case SMB2.SMB2Dialect.SMB300:
                                        return DialectSelection.SMB300;
                                    case SMB2.SMB2Dialect.SMB302:
                                        return DialectSelection.SMB302;
                                    case SMB2.SMB2Dialect.SMB311:
                                        return DialectSelection.SMB311;
                                    case SMB2.SMB2Dialect.SMB2xx:
                                        return DialectSelection.SMB2xx;
                                    default:
                                        return dialect.ToString();
                                }
                            }
                            else return string.Empty;
                        }
                        catch (Exception)
                        {
                            return string.Empty;
                        }
                    }
                    else throw new NotSupportedException("Only support SMB1Client / SMB2Client currently");
                }
            }

            internal ConnectionInfo(ISMBAsyncClient client, string transportType)
            {
                this.SMBClient = client;
                this.TransportType = transportType;
            }

            internal static string GetTransportTypeStr(SMBTransportType transportType)
            {
                switch (transportType)
                {
                    case SMBTransportType.NetBiosOverTCP:
                        return TransportTypeSelection.NetBiosOverTCP;
                    case SMBTransportType.DirectTCPTransport:
                        return TransportTypeSelection.DirectTCPTransport;
                    default:
                        return string.Empty;
                }
            }

            public static class DialectSelection
            {
                public const string CIFS = "NT LM 0.12";
                public const string SMB202 = "SMB 2.0.2";
                public const string SMB210 = "SMB 2.1";
                public const string SMB300 = "SMB 3.0";
                public const string SMB302 = "SMB 3.0.2";
                public const string SMB311 = "SMB 3.1.1";
                public const string SMB2xx = "SMB 2.xx";
            }

            public static class TransportTypeSelection
            {
                public const string NetBiosOverTCP = "NetBiosOverTCP";  // Port 139
                public const string DirectTCPTransport = "DirectTCPTransport";  // Port 445
            }
        }

        public static async Task<Result<ConnectionInfo>> TryConnectWithServerName(string serverName
            , TestClientSelection testClientTypes = TestClientSelection.All
            , SMBTransportTypeSelection transportTypeSelection = SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
        {
            var loadServerAddressResponse = LoadServerAddress(serverName);
            if (loadServerAddressResponse.IsSuccess) return await TryConnectWithAddress(loadServerAddressResponse.Value, testClientTypes, transportTypeSelection, responseTimeout, cancellationToken);
            else return loadServerAddressResponse.Error;
        }

        public static Result<IPAddress> LoadServerAddress(string serverName)
        {
            IPAddress[] hostAddresses = Dns.GetHostAddresses(serverName);
            if (hostAddresses.Length == 0)
            {
                return new Exception($"Cannot parse host name {serverName} to an IP address");
            }

            IPAddress serverAddress = IPAddressHelper.SelectAddressPreferIPv4(hostAddresses);
            return serverAddress;
        }

        public static async Task<Result<ConnectionInfo>> TryConnectWithAddress(IPAddress serverAddress
            , TestClientSelection testClientTypes = TestClientSelection.All
            , SMBTransportTypeSelection transportTypeSelection = SMBTransportTypeSelection.All
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
        {
            var _testConnectClients = getTestClients(testClientTypes);
            var _testTransportTypes = getTransportType(transportTypeSelection).ToArray();
            var connectErrors = new Dictionary<string, Exception>();

            foreach (var client in _testConnectClients)
            {
                var connectResponse = await tryConnectByServerAddress(client, serverAddress, _testTransportTypes, responseTimeout, cancellationToken);

                if (connectResponse.IsSuccess)
                {
                    return new ConnectionInfo(client, transportType: connectResponse.Value);
                }
                else
                {
                    connectErrors.Add(client.GetType().Name, connectResponse.Error);
                }
            }

            var errorResponse = new Exception($"Try connect operation is failed with client selection: {testClientTypes}");
            foreach (var connectError in connectErrors) errorResponse.Data.Add(connectError.Key, connectError.Value);
            return errorResponse;

        }

        private static async Task<Result<string>> tryConnectByServerAddress(ISMBAsyncClient client
            , IPAddress serverAddress
            , SMBTransportType[] testedTransportTypes
            , TimeSpan? responseTimeout = null
            , CancellationToken cancellationToken = default)
        {
            var exceptions = new List<Exception>();

            foreach (var testedTransportType in testedTransportTypes)
            {
                try
                {
                    var isConnected = await client.Connect(serverAddress, testedTransportType, responseTimeout, cancellationToken);
                    if (isConnected)
                    {
                        return ConnectionInfo.GetTransportTypeStr(testedTransportType);
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
            return new AggregateException(exceptions);
        }

        private static IEnumerable<ISMBAsyncClient> getTestClients(TestClientSelection testClientTypes)
        {
            if (testClientTypes.HasFlag(TestClientSelection.SMB2Client)) yield return new SMB2AsyncClient();
            if (testClientTypes.HasFlag(TestClientSelection.SMB1Client)) yield return new SMB1AsyncClient();
        }

        private static IEnumerable<SMBTransportType> getTransportType(SMBTransportTypeSelection transportTypeSelection)
        {
            if (transportTypeSelection.HasFlag(SMBTransportTypeSelection.DirectTCPTransport)) yield return SMBTransportType.DirectTCPTransport;
            if (transportTypeSelection.HasFlag(SMBTransportTypeSelection.NetBiosOverTCP)) yield return SMBTransportType.NetBiosOverTCP;
        }
    }
}
