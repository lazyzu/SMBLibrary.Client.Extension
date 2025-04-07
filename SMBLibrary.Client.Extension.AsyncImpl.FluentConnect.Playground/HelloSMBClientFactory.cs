using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect.Playground
{
    public class HelloSMBClientFactory
    {
        [Test]
        public async Task SMBClientFactory_TryConnect()
        {
            var connectResponse = await SMBClientFactory.TryConnectWithServerName("localhost", SMBClientFactory.TestClientSelection.SMB2Client);
            //var connectResponse = SMBClientFactory.TryConnectWithAddress(IPAddress.Parse("127.0.0.1"));

            if (connectResponse.IsSuccess)
            {
                var connectionInfo = connectResponse.Value;
                var client = connectionInfo.SMBClient;
                var dialect = connectionInfo.Dialect;
                var transportType = connectionInfo.TransportType;
            }
            else throw connectResponse.Error;
        }
    }
}
