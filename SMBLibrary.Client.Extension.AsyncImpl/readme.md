About SMBLibrary.Client.Extension.FluentConnect:
=================
`SMBLibrary.Client.Extension.FluentConnect` is a .NET library for access SMB resource easier with the underlying [SMBLibrary](https://github.com/TalAloni/SMBLibrary)

Using SMBLibrary.Client.Extension.FluentConnect:
=================
* `SMBPath` object containing Host, Share, and Path properties. You can parse the path string using `SMBPath.ParseFrom` to obtain an `SMBPath` object.
```
public async Task SMBPath_ParseFrom()
{
    var (isParsed, samplePath, parsedError) = SMBPath.ParseFrom(@"\\127.0.0.1\share\hello\sample.txt");
    if (isParsed)
    {
        await Assert.That(samplePath.HostName).IsEqualTo("127.0.0.1");
        await Assert.That(samplePath.ShareName).IsEqualTo("share");
        await Assert.That(samplePath.Path).IsEqualTo(@"hello\sample.txt");
        await Assert.That(samplePath.ToString()).IsEqualTo(@"\\127.0.0.1\share\hello\sample.txt");
    }
    else Assert.Fail(parsedError.Message);
}
```

* `SMBClientFactory` is responsible for attempting to connect to unknown SMB resources (You can specify the list of clients implemented by SMBLibrary.) and return the connection information containing Client, Dialect, and TransportType.
```
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
```

* You can manage different SMB path login credentials by implementing `ISMBCredentialGetter`
```
public class SMBCredientailGetter : ISmbCredientailGetter
{
    public ISMBCredientail GetFrom(SMBPath path)
    {
        if (path is not null)
        {
            switch (path.HostName)
            {
                case "localhost":
                    return SMBCredientail.From(userName: "userName", password: "...");
                default:
                    return SMBCredientail.NoCredientail;
            }
        }
        else return SMBCredientail.NoCredientail;
    }
}
```

* You can manage the client state using `SMBTransaction`. When dispose occurs, it will automatically execute disconnect and logout (if login credential was provided when creating the Transaction).
```
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
```

* `SMBTransaction` can be implemented to include different processing components. For example, `SMBSimpleTransaction` is defined as follows, including implementations of `SMBDirectory` and `SMBFile` (each containing some basic functionalities).
* Additionally, the `afterConnectInitial` argument of `SMBTransaction.NewTransaction` provides an opportunity to pass parameters and perform flexible initialization settings.
```
public class SMBSimpleTransaction : SMBTransaction
{
    public SMBFile FileHandle { get; private set; }
    public SMBDirectory FolderHandle { get; private set; }

    public void InitialHandles()
    {
        this.FileHandle = new SMBFile(this.Client);
        this.FolderHandle = new SMBDirectory(this.Client);
    }
}
```

<!--
NuGet Packages:
===============
[SMBLibrary.Client.Extension.FluentConnect](https://www.nuget.org/packages/SMBLibrary/) - Wrapper of SMBLibrary client functions, It aims to provide an intuitive and user-friendly interface.
[SMBLibrary.Client.Extension.AsyncImpl](https://www.nuget.org/packages/SMBLibrary.Win32/) - Async SMBLibrary client functions.
[SMBLibrary.Client.Extension.AsyncImpl.FluentConnect](https://www.nuget.org/packages/SMBLibrary.Adapters/) - Wrapper of Async SMBLibrary client functions, It aims to provide an intuitive and user-friendly interface.
-->