using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.FluentConnect.Playground
{
    public class HelloSMBTransaction
    {
        [Test]
        public void SMBTransaction_StartTransaction()
        {
            var (isPathParsed, sampleFolderPath, _) = SMBPath.ParseFrom(@"\\localhost\d$");

            if (isPathParsed)
            {
                /* We can start transaction without login credientail
                 * using (var transaction = SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleSmbPath, afterConnectInitial: _tran => _tran.InitialHandles()))
                 * using (var transaction = SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleSmbPath, afterConnectInitial: _tran => _tran.InitialHandles(), SMBCredientail.NoCredientail))
                 * 
                 * Or with login credientail
                 * using (var transaction = SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleSmbPath, afterConnectInitial: _tran => _tran.InitialHandles(), username: , password: ))
                 * using (var transaction = SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleSmbPath, afterConnectInitial: _tran => _tran.InitialHandles(), SMBCredientail.From(userName: , password: ) ))
                 * 
                 * Or with credientail managed by ISmbCredientailGetter implement
                */

                var credientailGetter = new SMBCredientailGetter();

                using (var transaction = credientailGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles()))
                {
                    var fileInfosInFolder = transaction.FolderHandle.GetFiles(sampleFolderPath, searchOption: SearchOption.TopDirectoryOnly).ToArray();

                    (isPathParsed, var samplePath, _) = sampleFolderPath.GetRelative("text.txt");
                    if (isPathParsed) transaction.FileHandle.CreateFile(samplePath, "test");
                }
            }
        }


        public class SMBCredientailGetter : ISmbCredientailGetter
        {
            public ISMBCredientail GetFrom(SMBPath path)
            {
                if (path is not null)
                {
                    switch (path.HostName)
                    {
                        case "localhost":
                            return SMBCredientail.From(userName: "tu_tu", password: "1qaz2wsx!@#$"); // TODO: Remove the credientail SMBCredientail.From(userName: "", password: "");
                        default:
                            return SMBCredientail.NoCredientail;
                    }
                }
                else return SMBCredientail.NoCredientail;
            }
        }
    }
}
