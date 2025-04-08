using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace SMBLibrary.Client.Extension.FluentConnect
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
            public readonly ISMBClient SMBClient;
            public readonly string TransportType;

            public string Dialect
            {
                get
                {
                    if (SMBClient is SMB1Client) return DialectSelection.CIFS;
                    else if (SMBClient is SMB2Client SMB2Client)
                    {
                        try
                        {
                            var dialectFieldInfo = typeof(SMB2Client).GetField("m_dialect", System.Reflection.BindingFlags.NonPublic 
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

            internal ConnectionInfo(ISMBClient client, string transportType)
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

        public static Result<ConnectionInfo, Exception> TryConnectWithServerName(string serverName
            , TestClientSelection testClientTypes = TestClientSelection.All
            , SMBTransportTypeSelection transportTypeSelection = SMBTransportTypeSelection.All)
        {
            var (isSuccess, serverAddress, error) = LoadServerAddress(serverName);
            if (isSuccess) return TryConnectWithAddress(serverAddress, testClientTypes, transportTypeSelection);
            else return error;
        }

        public static Result<IPAddress, Exception> LoadServerAddress(string serverName)
        {
            IPAddress[] hostAddresses = Dns.GetHostAddresses(serverName);
            if (hostAddresses.Length == 0)
            {
                return new Exception($"Cannot parse host name {serverName} to an IP address");
            }

            IPAddress serverAddress = IPAddressHelper.SelectAddressPreferIPv4(hostAddresses);
            return serverAddress;
        }

        public static Result<ConnectionInfo, Exception> TryConnectWithAddress(IPAddress serverAddress
            , TestClientSelection testClientTypes = TestClientSelection.All
            , SMBTransportTypeSelection transportTypeSelection = SMBTransportTypeSelection.All)
        {
            var _testConnectClients = getTestClients(testClientTypes);
            var _testTransportTypes = getTransportType(transportTypeSelection).ToArray();

            foreach (var client in _testConnectClients)
            {
                var isConnected = tryConnectByServerAddress(client, serverAddress, _testTransportTypes, out var transportType);

                if (isConnected)
                {
                    return new ConnectionInfo(client, transportType);
                }
            }

            return new Exception($"Try connect operation is failed with client selection: {testClientTypes} ");
        }

        private static bool tryConnectByServerAddress(ISMBClient client
            , IPAddress serverAddress
            , SMBTransportType[] testedTransportTypes
            , out string transportType)
        {
            foreach (var testedTransportType in testedTransportTypes)
            {
                var isConnected = client.Connect(serverAddress, testedTransportType);
                if (isConnected)
                {
                    transportType = ConnectionInfo.GetTransportTypeStr(testedTransportType);
                    return true;
                } 
            }

            transportType = string.Empty;
            return false;
        }

        private static IEnumerable<ISMBClient> getTestClients(TestClientSelection testClientTypes)
        {
            if (testClientTypes.HasFlag(TestClientSelection.SMB2Client)) yield return new SMB2Client();
            if (testClientTypes.HasFlag(TestClientSelection.SMB1Client)) yield return new SMB1Client();
        }

        private static IEnumerable<SMBTransportType> getTransportType(SMBTransportTypeSelection transportTypeSelection)
        {
            if (transportTypeSelection.HasFlag(SMBTransportTypeSelection.DirectTCPTransport)) yield return SMBTransportType.DirectTCPTransport;
            if (transportTypeSelection.HasFlag(SMBTransportTypeSelection.NetBiosOverTCP)) yield return SMBTransportType.NetBiosOverTCP;
        }
    }
}