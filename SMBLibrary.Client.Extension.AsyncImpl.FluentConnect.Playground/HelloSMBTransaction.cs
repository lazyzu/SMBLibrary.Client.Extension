using ClosedXML.Excel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect.Playground
{
    public class HelloSMBTransaction
    {
        private const string TestHostName = "xxx.xxx.xxx.xxx";
        private const string TestSharePath = @$"\\{TestHostName}\...";
        private const SMBClientFactory.TestClientSelection TestClientSelection = SMBClientFactory.TestClientSelection.SMB2Client;
        private const SMBClientFactory.SMBTransportTypeSelection TestTransportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.DirectTCPTransport;
        private static readonly SMBCredientail TestCredientail = SMBCredientail.From(userName: "...", password: "...");

        [Test]
        public async Task SMBFileStream_Usecase(CancellationToken cancellationToken)
        {
            var (isPathParsed, sampleFolderPath, _) = SMBPath.ParseFrom(TestSharePath);

            if (isPathParsed)
            {
                var connectionSettingGetter = new SMBConnectionSettingGetter();

                await using (var transaction = await connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), cancellationToken))
                {
                    var workbookDestination = sampleFolderPath.GetRelative("SMBStreamAsync.xlsx").Value;

                    await using (var fileStream = (await transaction.FileHandle.Open(workbookDestination
                        , SMBLibrary.CreateDisposition.FILE_OVERWRITE_IF
                        , SMBLibrary.AccessMask.GENERIC_READ | SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.ShareAccess.None)).Value)
                    using (var workbook = new XLWorkbook())
                    {
                        var sheet = workbook.AddWorksheet("Test");
                        sheet.Cell(1, 1).Value = 123;
                        workbook.SaveAs(fileStream);
                    }

                    await using (var fileStream = (await transaction.FileHandle.Open(workbookDestination
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.AccessMask.GENERIC_READ | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.ShareAccess.None)).Value)
                    using (var workbook = new XLWorkbook(fileStream))
                    {
                        var sheet = workbook.Worksheet("Test");
                        await Assert.That(sheet.Cell(1, 1).Value).IsEqualTo(123);
                    }
                }
            }
        }

        [Test]
        public async Task SMBTransaction_UseCases(CancellationToken cancellationToken)
        {
            var sampleSharePath = SMBPath.ParseFrom(TestSharePath).Value;
            var sampleFolderPath = sampleSharePath.GetRelative(@"smbtest").Value;

            /* We can start transaction without login credientail
             * await using (var transaction = await SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles()))
             * await using (var transaction = await SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), SMBCredientail.NoCredientail))
             * 
             * Or with login credientail
             * await using (var transaction = await SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), username: , password: ))
             * await using (var transaction = await SMBTransaction.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), SMBCredientail.From(userName: , password: ) ))
             * 
             * Or with credientail managed by ISmbCredientailGetter implement
            */

            var connectionSettingGetter = new SMBConnectionSettingGetter();

            await using (var transaction = await connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), cancellationToken: cancellationToken))
            {
                // Create Folder
                if (await transaction.FolderHandle.Exists(sampleFolderPath, cancellationToken) == false)
                {
                    var createFolderResponse = await transaction.FolderHandle.CreateDirectory(sampleFolderPath, cancellationToken);
                    if (createFolderResponse.IsSuccess == false) throw createFolderResponse.Error;
                }

                // Create Files
                var createdFileCount = 100;
                for (int i = 0; i < createdFileCount; i++)
                {
                    var _sampleFilePath = sampleFolderPath.GetRelative($"text{i}.txt").Value;

                    var createFileResponse = await transaction.FileHandle.CreateFile(_sampleFilePath, $"test{i}", cancellationToken);
                    if (createFileResponse.IsSuccess == false) throw createFileResponse.Error;
                }

                //  Load Files in folder
                var fileInfosInFolder = await transaction.FolderHandle.GetFiles(sampleFolderPath, searchOption: SearchOption.TopDirectoryOnly, cancellationToken: cancellationToken).ToArrayAsync();
                await Assert.That(fileInfosInFolder.Length).IsEqualTo(createdFileCount);

                // Rename File 
                var sampleFilePath = sampleFolderPath.GetRelative("text1.txt").Value;
                var movedSampleFilePath = sampleFolderPath.GetRelative(@"\moved\text1.txt").Value;
                var moveFileResponse = await transaction.FileHandle.Move(sampleFilePath, movedSampleFilePath, cancellationToken);
                if (moveFileResponse.IsSuccess == false) throw moveFileResponse.Error;

                // Readout file content 
                var readFileResponse = await transaction.FileHandle.ReadAllText(movedSampleFilePath, cancellationToken: cancellationToken);
                if (readFileResponse.IsSuccess == false) throw readFileResponse.Error;
                else await Assert.That(readFileResponse.Value).IsEqualTo("test1");

                // Set File Last Write Time of File
                var targetTime = DateTime.UtcNow.AddDays(-1);
                var setWriteTimeResponse = await transaction.FileHandle.SetInfo(movedSampleFilePath, info =>
                {
                    info.LastWriteTimeUtc = targetTime;
                }, cancellationToken);
                if (setWriteTimeResponse.IsSuccess == false) throw setWriteTimeResponse.Error;
                else
                {
                    var readFileInformationResponse = await transaction.FileHandle.GetInfo(movedSampleFilePath, cancellationToken);
                    if (readFileInformationResponse.IsSuccess == false) throw readFileInformationResponse.Error;
                    else await Assert.That(readFileInformationResponse.Value.LastWriteTimeUtc).IsEqualTo(targetTime);
                }

                // Load Folder Info
                var readSampleFolderInfoResponse = await transaction.FolderHandle.GetInfo(sampleFolderPath, cancellationToken);
                if (readSampleFolderInfoResponse.IsSuccess == false) throw readSampleFolderInfoResponse.Error;
                else await Assert.That(readSampleFolderInfoResponse.Value).IsNotNull();

                // Move Folder
                var movedSampleFolderPath = sampleSharePath.GetRelative(@"other_smbtest").Value;
                var moveFolderResponse = await transaction.FolderHandle.Move(sampleFolderPath, movedSampleFolderPath, cancellationToken);
                if (moveFolderResponse.IsSuccess == false) throw moveFolderResponse.Error;
                else await Assert.That(await transaction.FolderHandle.Exists(movedSampleFolderPath)).IsTrue();
                
                // Delete folder and files in folder
                var deleteFolderResponse = await transaction.FolderHandle.DeleteDirectory(movedSampleFolderPath, deleteSubItems: true, cancellationToken);
                if (deleteFolderResponse.IsSuccess == false) throw deleteFolderResponse.Error;

                if (await transaction.FolderHandle.Exists(movedSampleFolderPath, cancellationToken)) Assert.Fail($"Folder {movedSampleFolderPath} is still exist");
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
                                , responseTimeout: null
                                , TestCredientail);
                        default:
                            return SMBConnectionSetting.From(SMBClientFactory.TestClientSelection.All
                                , SMBClientFactory.SMBTransportTypeSelection.All
                                , responseTimeout: null
                                , SMBCredientail.NoCredientail);
                    }
                }
                else throw new NotSupportedException();
            }
        }
    }
}
