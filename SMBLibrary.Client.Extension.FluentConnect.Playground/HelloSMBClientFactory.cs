using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.FluentConnect.Playground
{
    public class HelloSMBClientFactory
    {
        [Test]
        public void SMBClientFactory_TryConnect()
        {
            var (isSuccess, connectionInfo, error) = SMBClientFactory.TryConnectWithServerName("localhost");
            //var (isSuccess, connectionInfo, error) = SMBClientFactory.TryConnectWithAddress(IPAddress.Parse("127.0.0.1"));

            if (isSuccess)
            {
                var client = connectionInfo.SMBClient;
                var dialect = connectionInfo.Dialect;
                var transportType = connectionInfo.TransportType;
            }
            else Assert.Fail(error.Message);
        }
    }
}
