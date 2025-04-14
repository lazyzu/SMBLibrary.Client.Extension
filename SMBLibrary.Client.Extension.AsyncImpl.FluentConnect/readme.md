About SMBLibrary.Client.Extension.AsyncImpl.FluentConnect:
=================
`SMBLibrary.Client.Extension.AsyncImpl.FluentConnect` is a library that encapsulates the Client functionality of SMBLibrary.Client.Extension.AsyncImpl.
It provides an SMB access interface similar to `System.IO.File`, `Directory`, and `FileStream`.
It also offers extensions for connection management and path recognition.

Using SMBLibrary.Client.Extension.AsyncImpl.FluentConnect:
=================
### Access SMB resources using an interface similar to System.IO
`SMBFile` and `SMBDirectory` are implemented to mimic `System.IO`. 
We can access these two objects through `SMBSimpleTransaction.FileHandle/FolderHandle`.
```
public async Task Access_Like_System_IO(CancellationToken cancellationToken)
{
    var sampleSharePath = SMBPath.ParseFrom(TestSharePath).Value;
    var sampleFolderPath = sampleSharePath.GetRelative(@"smbtest").Value;

    var connectionSettingGetter = new SMBConnectionSettingGetter();

    await using (var transaction = await connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath
    , afterConnectInitial: _tran => _tran.InitialHandles(), cancellationToken: cancellationToken))
    {
        // Create Folder
        if (await transaction.FolderHandle.Exists(sampleFolderPath, cancellationToken) == false)
        {
            var createFolderResponse = await transaction.FolderHandle.CreateDirectory(sampleFolderPath, cancellationToken);
        }
    
        // Create Files
        var createdFileCount = 100;
        for (int i = 0; i < createdFileCount; i++)
        {
            var _sampleFilePath = sampleFolderPath.GetRelative($"text{i}.txt").Value;
    
            var createFileResponse = await transaction.FileHandle.CreateFile(_sampleFilePath, $"test{i}", cancellationToken);
        }
    
        //  Load Files in folder
        var fileInfosInFolder = await transaction.FolderHandle.GetFiles(sampleFolderPath, searchOption: SearchOption.TopDirectoryOnly, cancellationToken: cancellationToken).ToArrayAsync();
    
        // Rename File 
        var sampleFilePath = sampleFolderPath.GetRelative("text1.txt").Value;
        var movedSampleFilePath = sampleFolderPath.GetRelative(@"\moved\text1.txt").Value;
        var moveFileResponse = await transaction.FileHandle.Move(sampleFilePath, movedSampleFilePath, cancellationToken);
    
        // Readout file content 
        var readFileResponse = await transaction.FileHandle.ReadAllText(movedSampleFilePath, cancellationToken: cancellationToken);
    
        // Set File Last Write Time of File
        var targetTime = DateTime.UtcNow.AddDays(-1);
        var setWriteTimeResponse = await transaction.FileHandle.SetInfo(movedSampleFilePath, info =>
        {
            info.LastWriteTimeUtc = targetTime;
        }, cancellationToken);
        var readFileInformationResponse = await transaction.FileHandle.GetInfo(movedSampleFilePath, cancellationToken);
    
        // Load Folder Info
        var readSampleFolderInfoResponse = await transaction.FolderHandle.GetInfo(sampleFolderPath, cancellationToken);
    
        // Move Folder
        var movedSampleFolderPath = sampleSharePath.GetRelative(@"other_smbtest").Value;
        var moveFolderResponse = await transaction.FolderHandle.Move(sampleFolderPath, movedSampleFolderPath, cancellationToken);
        
        // Delete folder and files in folder
        var deleteFolderResponse = await transaction.FolderHandle.DeleteDirectory(movedSampleFolderPath, deleteSubItems: true, cancellationToken);
    }
}

private const string TestHostName = "SMB_HOST_NAME";
private const string TestSharePath = $@"\\{TestHostName}\SMB_SHARE_NAME";
private const SMBClientFactory.TestClientSelection TestClientSelection = SMBClientFactory.TestClientSelection.SMB2Client;
private const SMBClientFactory.SMBTransportTypeSelection TestTransportTypeSelection = SMBClientFactory.SMBTransportTypeSelection.DirectTCPTransport;
private static readonly SMBCredientail TestCredientail = SMBCredientail.From(userName: "...", password: "...");

class SMBConnectionSettingGetter : ISMBConnectionSettingGetter
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
```

### Access SMB files using a `Stream`
We can access the file stream using `SMBFile.Open` or `SMBFileStream.CreateFrom`.
```
public async Task SMBFileStream_Usecase(CancellationToken cancellationToken)
{
    var (isPathParsed, sampleFolderPath, _) = SMBPath.ParseFrom(TestSharePath);

    if (isPathParsed)
    {
        var connectionSettingGetter = new SMBConnectionSettingGetter();

        await using (var transaction = await connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles(), cancellationToken))
        {
            var sampleFilePath = sampleFolderPath.GetRelative("SMBStream.txt").Value;

            await using (var fileStream = (await transaction.FileHandle.Open(sampleFilePath
                , SMBLibrary.CreateDisposition.FILE_OVERWRITE_IF
                , SMBLibrary.AccessMask.GENERIC_READ | SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.SYNCHRONIZE
                , SMBLibrary.ShareAccess.None)).Value)
            using (var streamWriter = new StreamWriter(fileStream))
            {
                streamWriter.WriteLine("Hello World");
                streamWriter.WriteLine("Hello Stream");
            }

            await using (var fileStream = (await transaction.FileHandle.Open(sampleFilePath
                , SMBLibrary.CreateDisposition.FILE_OPEN
                , SMBLibrary.AccessMask.GENERIC_READ | SMBLibrary.AccessMask.SYNCHRONIZE
                , SMBLibrary.ShareAccess.None)).Value)
            using (var streamReader = new StreamReader(fileStream))
            {
                await Assert.That(streamReader.ReadLine()).IsEqualTo("Hello World");
                await Assert.That(streamReader.ReadLine()).IsEqualTo("Hello Stream");
            }
        }
    }
}
```

`SMBFileStream` does not close the underlying connection by default when disposed.
If you need to close the connection when disposing, you can set `leaveConnectionOpenWhenDispose` to `false`.
 ```
 public async Task<Stream> LoadSMBFileStream(CancellationToken cancellationToken)
 {
    var sampleFolderPath = SMBPath.ParseFrom(TestSharePath).Value;
    var sampleFileDestination = sampleFolderPath.GetRelative("SMBStream.xlsx").Value;

    var connectionSettingGetter = new SMBConnectionSettingGetter();
    var transaction = await connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath, afterConnectInitial: _tran => _tran.InitialHandles());
    var createStreamResponse = await SMBFileStream.CreateFrom(sampleFileDestination
            , transaction.Client
            , SMBLibrary.CreateDisposition.FILE_OVERWRITE_IF
            , SMBLibrary.AccessMask.GENERIC_READ | AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE
            , ShareAccess.None
            , leaveConnectionOpenWhenDispose: false);

    if (createStreamResponse.IsSuccess) return createStreamResponse.Value;
    else throw createStreamResponse.Error;
 }
 ```

 ### Connection Setting
We can manage the credentials and client settings used for accessing different paths by implementing `ISMBConnectionSettingGetter`.
```
class SMBConnectionSettingGetter : ISMBConnectionSettingGetter
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
```

 We can manage the client state using `SMBTransaction`. 
 When dispose occurs, it will automatically execute disconnect and logout (if login credential was provided when creating the Transaction).
```
public async Task Transaction_Usecase()
{
    var sampleSharePath = SMBPath.ParseFrom(TestSharePath).Value;
    var sampleFolderPath = sampleSharePath.GetRelative(@"smbtest").Value;

    var connectionSettingGetter = new SMBConnectionSettingGetter();

    await using (var transaction = await connectionSettingGetter.NewTransaction<SMBSimpleTransaction>(sampleFolderPath
          , afterConnectInitial: _tran => _tran.InitialHandles()))
    {
        // Operations
    }   // Disconnect & logout when dispose
}
```

`SMBTransaction` can be implemented to include different processing components.
For example, `SMBSimpleTransaction` is defined as follows, including implementations of `SMBDirectory` and `SMBFile`.
Additionally, the `afterConnectInitial` argument of `SMBTransaction.NewTransaction` provides an opportunity to pass parameters and perform flexible initialization settings.
```
public class SMBSimpleTransaction : SMBTransaction
{
    public SMBFile FileHandle { get; private set; }
    public SMBDirectory FolderHandle { get; private set; }

    public void InitialHandles()
    {
        this.FileHandle = new SMBFile(this.Client, this);
        this.FolderHandle = new SMBDirectory(this.Client, this);
    }
}
```

### More
The `SMBPath` object containing Host, Share, and Path properties. You can parse the path string using `SMBPath.ParseFrom` to obtain an `SMBPath` object.
```
var (isParsed, samplePath, parsedError) = SMBPath.ParseFrom(@"\\127.0.0.1\share\hello\sample.txt");
```

`SMBClientFactory` is responsible for attempting to connect to unknown SMB resources (You can specify the list of clients implemented by SMBLibrary.) and return the connection information containing Client, Dialect, and TransportType.
```
public async Task SMBClientFactory_TryConnect()
{
    var connectResponse = await SMBClientFactory.TryConnectWithServerName("ServerName");
    //var connectResponse = await SMBClientFactory.TryConnectWithAddress(IPAddress.Parse("..."));

    if (connectResponse.IsSuccess)
    {
        var connectionInfo = connectResponse.Value;
        var client = connectionInfo.SMBClient;
        var dialect = connectionInfo.Dialect;
        var transportType = connectionInfo.TransportType;
    }
    else throw connectResponse.Error;
}
```

Licensing:
=================
`SMBLibrary.Client.Extension.AsyncImpl.FluentConnect` can be used in any scenario without any cost. However, please note the [commercial usage restrictions of the underlying SMBLibrary](https://github.com/TalAloni/SMBLibrary?tab=readme-ov-file#licensing).