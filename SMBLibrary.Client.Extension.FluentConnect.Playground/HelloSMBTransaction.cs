
namespace SMBLibrary.Client.Extension.FluentConnect.Playground
{
    public class HelloSMBTransaction
    {
        private const string TestHostName = "xxx.xxx.xxx.xxx";
        private const string TestSharePath = @$"\\{TestHostName}\...";
        private const SMBClientFactory.TestClientSelection TestClientSelection = SMBClientFactory.TestClientSelection.SMB2Client;
        private const SMBClientFactory.SMBTransportTypeSelection TestTransportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.DirectTCPTransport;
        private static readonly SMBCredientail TestCredientail = SMBCredientail.From(userName: "...", password: "...");

        [Test]
        public void SMBTransaction_StartTransaction()
        {
            var (isPathParsed, sampleFolderPath, _) = SMBPath.ParseFrom(TestSharePath);

            if (isPathParsed)
            {
                /* We can start transaction without login credientail
                 * using (var transaction = SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles()))
                 * using (var transaction = SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), SMBCredientail.NoCredientail))
                 * 
                 * Or with login credientail
                 * using (var transaction = SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), username: , password: ))
                 * using (var transaction = SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), SMBCredientail.From(userName: , password: ) ))
                 * 
                 * Or with credientail managed by ISmbCredientailGetter implement
                */

                var connectionSettingGetter = new SMBConnectionSettingGetter();

                using (var transaction = connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles()))
                {
                    var fileInfosInFolder = transaction.FolderHandle.GetFiles(sampleFolderPath, searchOption: SearchOption.TopDirectoryOnly).ToArray();

                    (isPathParsed, var samplePath, _) = sampleFolderPath.GetRelative("text.txt");
                    if (isPathParsed) transaction.FileHandle.CreateFile(samplePath, "test");
                }
            }
        }

        [Test]
        public async Task SMBFileStream_Usecase()
        {
            var (isPathParsed, sampleFolderPath, _) = SMBPath.ParseFrom(TestSharePath);

            if (isPathParsed)
            {
                var connectionSettingGetter = new SMBConnectionSettingGetter();

                using (var transaction = connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles()))
                {
                    var workbookDestination = sampleFolderPath.GetRelative("SMBStream.xlsx").Value;

                    using (var fileStream = SMBFileStream.CreateFrom(workbookDestination
                        , transaction.Client
                        , SMBLibrary.CreateDisposition.FILE_OVERWRITE_IF
                        , SMBLibrary.AccessMask.GENERIC_READ | AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE
                        , ShareAccess.None))
                    using (var streamWriter = new StreamWriter(fileStream))
                    {
                        streamWriter.WriteLine("Hello World");
                        streamWriter.WriteLine("Hello Stream");
                    }

                    using (var fileStream = SMBFileStream.CreateFrom(workbookDestination
                        , transaction.Client
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE
                        , ShareAccess.None))
                    using (var streamReader = new StreamReader(fileStream))
                    {
                        await Assert.That(streamReader.ReadLine()).IsEqualTo("Hello World");
                        await Assert.That(streamReader.ReadLine()).IsEqualTo("Hello Stream");
                    }
                }
            }
        }

        [Test]
        public async Task SMBTransaction_UsageCases()
        {
            var sampleSharePath = SMBPath.ParseFrom(TestSharePath).Value;
            var sampleFolderPath = sampleSharePath.GetRelative(@"smbtest").Value;

            var connectionSettingGetter = new SMBConnectionSettingGetter();

            using (var transaction = connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles()))
            {
                // Create Folder
                if (transaction.FolderHandle.Exists(sampleFolderPath) == false)
                {
                    transaction.FolderHandle.CreateDirectory(sampleFolderPath);
                }

                // Create Files
                var createdFileCount = 100;
                for (int i = 0; i < createdFileCount; i++)
                {
                    var _sampleFilePath = sampleFolderPath.GetRelative($"text{i}.txt").Value;
                    transaction.FileHandle.CreateFile(_sampleFilePath, $"test{i}");
                }

                //  Load Files in folder
                var fileInfosInFolder = transaction.FolderHandle.GetFiles(sampleFolderPath, searchOption: SearchOption.TopDirectoryOnly).ToArray();
                await Assert.That(fileInfosInFolder.Length).IsEqualTo(createdFileCount);

                // Rename File 
                var sampleFilePath = sampleFolderPath.GetRelative("text1.txt").Value;
                var movedSampleFilePath = sampleFolderPath.GetRelative(@"\moved\text1.txt").Value;
                transaction.FileHandle.Move(sampleFilePath, movedSampleFilePath);

                // Readout file content 
                var readFileResponse = transaction.FileHandle.ReadAllText(movedSampleFilePath);
                await Assert.That(readFileResponse).IsEqualTo("test1");

                // Set File Last Write Time of File
                var targetTime = DateTime.UtcNow.AddDays(-1);
                transaction.FileHandle.SetInfo(movedSampleFilePath, info =>
                {
                    info.LastWriteTimeUtc = targetTime;
                });
                var fileInformation = transaction.FileHandle.GetInfo(movedSampleFilePath);
                await Assert.That(fileInformation.LastWriteTimeUtc).IsEqualTo(targetTime);

                // Load Folder Info
                var sampleFolderInfo = transaction.FolderHandle.GetInfo(sampleFolderPath);
                await Assert.That(sampleFolderInfo).IsNotNull();

                // Move Folder
                var movedSampleFolderPath = sampleSharePath.GetRelative(@"other_smbtest").Value;
                transaction.FolderHandle.Move(sampleFolderPath, movedSampleFolderPath);
                await Assert.That(transaction.FolderHandle.Exists(movedSampleFolderPath)).IsTrue();

                // Delete folder and files in folder
                transaction.FolderHandle.DeleteDirectory(movedSampleFolderPath, deleteSubItems: true);
            }
        }

        public class SMBConnectionSettingGetter : ISMBConnectionSettingGetter
        {
            public ISMBConnectionSetting GetFrom(SMBPath path)
            {
                if (path is not null)
                {
                    switch (path.HostName)
                    {
                        case TestHostName:
                            return SMBConnectionSetting.From(TestClientSelection
                                , TestTransportTypeSelection
                                , TestCredientail);
                        default:
                            return SMBConnectionSetting.From(SMBClientFactory.TestClientSelection.All
                                , SMBClientFactory.SMBTransportTypeSelection.All
                                , SMBCredientail.NoCredientail);
                    }
                }
                else throw new NotSupportedException();
            }
        }
    }
}
