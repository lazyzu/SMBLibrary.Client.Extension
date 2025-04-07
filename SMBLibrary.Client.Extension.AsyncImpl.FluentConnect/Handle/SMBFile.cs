using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect.Handle
{
    public class SMBFile
    {
        private protected readonly ISMBAsyncClient client;
        private protected readonly SMBTransaction transaction;

        public SMBFile(ISMBAsyncClient client, SMBTransaction transaction)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));
            if (transaction == null) throw new ArgumentException(nameof(transaction));

            this.client = client;
            this.transaction = transaction;
        }

        public virtual async Task<Result.None> CreateFile(SMBPath path, Stream stream, CancellationToken cancellationToken = default)
        {
            if (path == null) return new ArgumentNullException(nameof(path));
            if (stream == null) return new ArgumentNullException(nameof(stream));
            
            var getParentDirectoryResponse = path.GetRelative("..");
            if (getParentDirectoryResponse.IsSuccess)
            {
                var directoryHandle = new SMBDirectory(client, transaction);
                var parentDirectory = getParentDirectoryResponse.Value;
                if (parentDirectory != null && (await directoryHandle.Exists(parentDirectory, cancellationToken).ConfigureAwait(false) == false))
                {
                    var createDirectoryResponse = await directoryHandle.CreateDirectory(parentDirectory, cancellationToken).ConfigureAwait(false);
                    if (createDirectoryResponse.IsSuccess == false) return createDirectoryResponse.Error;
                }

                var shareConnectResponse = await client.TreeConnect(path.ShareName, cancellationToken).ConfigureAwait(false);
                if (shareConnectResponse.IsSuccess == false)
                {
                    return new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}", shareConnectResponse.Error);
                }

                var fileStore = shareConnectResponse.Value;
                var fileConnectResponse = await fileStore.CreateFile(path.Path
                    , AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE, FileAttributes.Normal
                    , ShareAccess.Read
                    , CreateDisposition.FILE_SUPERSEDE
                    , CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                    , null
                    , cancellationToken).ConfigureAwait(false);

                if (fileConnectResponse.IsSuccess)
                {
                    var fileHandle = fileConnectResponse.Value.Handle;
                    int writeOffset = 0;
                    while (stream.Position < stream.Length)
                    {
                        byte[] buffer = new byte[(int)client.MaxWriteSize];
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                        if (bytesRead < (int)client.MaxWriteSize)
                        {
                            Array.Resize<byte>(ref buffer, bytesRead);
                        }

                        var writeFileResponse = await fileStore.WriteFile(fileHandle, writeOffset, buffer, cancellationToken).ConfigureAwait(false);
                        if (writeFileResponse.IsSuccess == false)
                        {
                            await fileStore.CloseFile(fileHandle, cancellationToken).ConfigureAwait(false);
                            await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                            return new AccessViolationException($"Failed to write file: {path}", writeFileResponse.Error);
                        }
                        writeOffset += bytesRead;
                    }

                    await fileStore.CloseFile(fileHandle, cancellationToken).ConfigureAwait(false);
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return new Result.None();
                }
                else
                {
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return new AccessViolationException($"Not able to connect file {path}", fileConnectResponse.Error);
                }
            }
            else return getParentDirectoryResponse.Error;
        }

        public virtual async Task<Result.None> CreateFile(SMBPath path, string content, CancellationToken cancellationToken = default)
        {
            using (var stream = new MemoryStream())
            using (var writer = new StreamWriter(stream))
            {
                await writer.WriteAsync(content).ConfigureAwait(false);
                await writer.FlushAsync().ConfigureAwait(false);
                stream.Seek(0, SeekOrigin.Begin);

                return await CreateFile(path, stream, cancellationToken).ConfigureAwait(false);
            }
        }

        public virtual async Task<Result.None> CreateFile(SMBPath path, byte[] content, CancellationToken cancellationToken = default)
        {
            using (var stream = new MemoryStream(content))
            {
                stream.Seek(0, SeekOrigin.Begin);
                return await CreateFile(path, stream, cancellationToken).ConfigureAwait(false);
            }
        }

        public virtual Task<Result<SMBFileStream>> Open(SMBPath path
            , SMBLibrary.CreateDisposition mode, SMBLibrary.AccessMask access, SMBLibrary.ShareAccess share
            , bool leaveConnectionOpenWhenDispose = true
            , CancellationToken cancellationToken = default)
            => SMBFileStream.CreateFrom(path, transaction, mode, access, share, leaveConnectionOpenWhenDispose, cancellationToken);

        public virtual async Task<Result.None> DeleteFile(SMBPath path, CancellationToken cancellationToken = default)
        {
            if (path == null) return new ArgumentNullException(nameof(path));
            else
            {
                if (await Exists(path, cancellationToken).ConfigureAwait(false))
                {
                    var shareConnectResponse = await client.TreeConnect(path.ShareName, cancellationToken).ConfigureAwait(false);
                    if (shareConnectResponse.IsSuccess == false)
                    {
                        return new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}", shareConnectResponse.Error);
                    }

                    var targetFilePath = path.Path;

                    if (client is SMB1Client)
                    {
                        targetFilePath = $"{targetFilePath}\\";
                    }

                    var fileStore = shareConnectResponse.Value;

                    var fileConnectResponse = await fileStore.CreateFile(targetFilePath
                        , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.DELETE | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.None
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null
                        , cancellationToken).ConfigureAwait(false);

                    if (fileConnectResponse.IsSuccess == false)
                    {
                        await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                        return new AccessViolationException($"Not able to connect file {path}", fileConnectResponse.Error);
                    }
                    else
                    {
                        var fileHandle = fileConnectResponse.Value.Handle;
                        var dispositionInformation = new FileDispositionInformation();
                        dispositionInformation.DeletePending = true;
                        var setInformationResponse = await fileStore.SetFileInformation(fileHandle, dispositionInformation, cancellationToken).ConfigureAwait(false);

                        await fileStore.CloseFile(fileHandle, cancellationToken).ConfigureAwait(false);
                        await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);

                        if (setInformationResponse.IsSuccess == false)
                        {
                            return new AccessViolationException($"Not able to delete file {path}", setInformationResponse.Error);
                        }
                        else
                        {
                            if (setInformationResponse.Value == NTStatus.STATUS_SUCCESS) return new Result.None();
                            else return new AccessViolationException($"Not able to delete file {path}", new ErrorResponseException(setInformationResponse.Value));
                        }
                    }
                }
                else return new Result.None();  // Not exist, No need to delete
            }
        }

        public virtual async Task<Result.None> Move(SMBPath from, SMBPath to, CancellationToken cancellationToken = default)
        {
            if (from == null) return new ArgumentNullException(nameof(from));
            if (to == null) return new ArgumentNullException(nameof(to));

            if (await Exists(to, cancellationToken).ConfigureAwait(false))
            {
                return new ArgumentException($"{nameof(to)} file {to} is already exist");
            }
            else
            {
                if (await Exists(from, cancellationToken).ConfigureAwait(false))
                {
                    var shareConnectResponse = await client.TreeConnect(from.ShareName, cancellationToken).ConfigureAwait(false);
                    if (shareConnectResponse.IsSuccess == false)
                    {
                        return new AccessViolationException($"Not able to connect share {from.ShareName} of {from.HostName}", shareConnectResponse.Error);
                    }

                    var fromParentFolder = from.Path;

                    if (client is SMB1Client)
                    {
                        fromParentFolder = $"{fromParentFolder}\\";
                    }

                    var fileStore = shareConnectResponse.Value;
                    var fromParentFolderConnectResponse = await fileStore.CreateFile(fromParentFolder
                        , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.DELETE | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.None
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null
                        , cancellationToken).ConfigureAwait(false);

                    if (fromParentFolderConnectResponse.IsSuccess == false)
                    {
                        await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                        return new AccessViolationException($"Not able to connect file {from}", fromParentFolderConnectResponse.Error);
                    }
                    else
                    {
                        var directoryHnadle = new SMBDirectory(this.client, this.transaction);
                        var toParentPathResponse = to.GetRelative("..");
                        if (toParentPathResponse.IsSuccess)
                        {
                            var createParentDirectoryResponse = await directoryHnadle.CreateDirectory(toParentPathResponse.Value, cancellationToken).ConfigureAwait(false);
                            if (createParentDirectoryResponse.IsSuccess)
                            {
                                var fileHandle = fromParentFolderConnectResponse.Value.Handle;
                                Result.NTStatus setInformationResponse;
                                if (client is SMB1Client)
                                {
                                    FileRenameInformationType1 fileRenameInformation = new FileRenameInformationType1();
                                    fileRenameInformation.FileName = to.Path;
                                    fileRenameInformation.ReplaceIfExists = false;
                                    setInformationResponse = await fileStore.SetFileInformation(fileHandle, fileRenameInformation, cancellationToken).ConfigureAwait(false);
                                }
                                else
                                {
                                    FileRenameInformationType2 fileRenameInformation = new FileRenameInformationType2();
                                    fileRenameInformation.FileName = to.Path;
                                    fileRenameInformation.ReplaceIfExists = false;
                                    setInformationResponse = await fileStore.SetFileInformation(fileHandle, fileRenameInformation, cancellationToken).ConfigureAwait(false);
                                }

                                await fileStore.CloseFile(fileHandle, cancellationToken).ConfigureAwait(false);
                                await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);

                                if (setInformationResponse.IsSuccess)
                                {
                                    if (setInformationResponse.Value == NTStatus.STATUS_SUCCESS) return new Result.None();
                                    else return new AccessViolationException($"Move operation from {from} to {to} is failed", new ErrorResponseException(setInformationResponse.Value));
                                } 
                                else
                                {
                                    return new AccessViolationException($"Move operation from {from} to {to} is failed", setInformationResponse.Error);
                                }
                            }
                            else return createParentDirectoryResponse.Error;
                        }
                        else return toParentPathResponse.Error;
                    }
                }
                else return new ArgumentException($"{nameof(from)} file {from} is not exist");
            }
        }

        public virtual async Task<bool> Exists(SMBPath path, CancellationToken cancellationToken = default)
        {
            var fileConnectResponse = await DoSomethingAfterFileConnect(path, client, action: null, cancellationToken).ConfigureAwait(false);
            return fileConnectResponse.IsSuccess;
        }

        public virtual async Task<Result<FileInformation>> GetInfo(SMBPath path, CancellationToken cancellationToken = default)
        {
            var (isFileConnectSuccess, getInformationResponse, fileConnectError) = await DoSomethingAfterFileConnect<Result<FileInformation>>(path, client, func: async (fileStore, fileHandle) =>
            {
                var basicInfoResponse = await GetInfo<FileBasicInformation>(path, fileStore, fileHandle, SMBLibrary.FileInformationClass.FileBasicInformation, cancellationToken).ConfigureAwait(false);
                if (basicInfoResponse.IsSuccess == false) return basicInfoResponse.Error;

                var stdInfoResponse = await GetInfo<FileStandardInformation>(path, fileStore, fileHandle, SMBLibrary.FileInformationClass.FileStandardInformation, cancellationToken).ConfigureAwait(false);
                if (stdInfoResponse.IsSuccess == false) return stdInfoResponse.Error;

                return FileInformation.ParseFrom(basicInfoResponse.Value, stdInfoResponse.Value);
            }, cancellationToken).ConfigureAwait(false);

            if (isFileConnectSuccess && getInformationResponse.IsSuccess) return getInformationResponse.Value;
            else if (isFileConnectSuccess == false) return fileConnectError;
            else return getInformationResponse.Value;
        }

        public virtual async Task<Result.None> SetInfo(SMBPath path, Action<SetInfoModel> infoSetter, CancellationToken cancellationToken = default)
        {
            if (path == null) return new ArgumentNullException(nameof(path));
            if (infoSetter == null) return new ArgumentNullException(nameof(infoSetter));

            var shareConnectResponse = await client.TreeConnect(path.ShareName, cancellationToken).ConfigureAwait(false);
            if (shareConnectResponse.IsSuccess == false)
            {
                return new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}", shareConnectResponse.Error);
            }

            var fileStore = shareConnectResponse.Value;

            var fileConnectResponse = await fileStore.CreateFile(path.Path
                , AccessMask.GENERIC_READ | AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE
                , FileAttributes.Normal
                , ShareAccess.Read
                , CreateDisposition.FILE_OPEN
                , CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                , null
                , cancellationToken).ConfigureAwait(false);

            if (fileConnectResponse.IsSuccess)
            {
                var fileHandle = fileConnectResponse.Value.Handle;
                var basicInfoResponse = await GetInfo<FileBasicInformation>(path, fileStore, fileHandle, SMBLibrary.FileInformationClass.FileBasicInformation, cancellationToken).ConfigureAwait(false);
                if (basicInfoResponse.IsSuccess)
                {
                    var setInfoModel = SetInfoModel.ParseFrom(basicInfoResponse.Value);
                    infoSetter(setInfoModel);
                    var renderedBasicInfo = setInfoModel.RenderBack(basicInfoResponse.Value);
                    var setFileResponse = await fileStore.SetFileInformation(fileHandle, renderedBasicInfo, cancellationToken).ConfigureAwait(false);

                    await fileStore.CloseFile(fileHandle, cancellationToken).ConfigureAwait(false);
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);

                    if (setFileResponse.IsSuccess) return new Result.None();
                    else return setFileResponse.Error;
                }
                else
                {
                    await fileStore.CloseFile(fileHandle, cancellationToken).ConfigureAwait(false);
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return new AccessViolationException($"Not able to read file information {path}", basicInfoResponse.Error);
                }
            }
            else
            {
                await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                return new AccessViolationException($"Not able to connect file {path}", fileConnectResponse.Error);
            }
        }

        internal static async Task<Result<T>> GetInfo<T>(SMBPath path, ISMBAsyncFileStore fileStore, object fileHandle, SMBLibrary.FileInformationClass queryInfoClass, CancellationToken cancellationToken = default) where T : SMBLibrary.FileInformation
        {
            var fileInformationResponse = await fileStore.GetFileInformation(fileHandle, queryInfoClass, cancellationToken).ConfigureAwait(false);
            if (fileInformationResponse.IsSuccess == false) return new AccessViolationException($"Not able to get {queryInfoClass} of file {path}", fileInformationResponse.Error);
            if (fileInformationResponse.Value == null) return new AccessViolationException($"Not able to get {queryInfoClass} of file {path}, error:NULL_RESULT");
            if (fileInformationResponse.Value is T info)
            {
                return info;
            }
            else return new NotSupportedException($"Not able to get {queryInfoClass} of file {path}, error:NOT_SUPPORT_RESULT_TYPE({fileInformationResponse.Value.GetType().FullName})");
        }

        internal async Task<Result<MemoryStream>> OpenRead(SMBPath path, long offset = 0, long? length = null, CancellationToken cancellationToken = default)
        {
            var resultStream = new MemoryStream();
            var openReadResponse = await OpenRead(resultStream, path, offset, length, cancellationToken).ConfigureAwait(false);
            if (openReadResponse.IsSuccess == false) return openReadResponse.Error;
            else
            {
                resultStream.Seek(0, SeekOrigin.Begin);
                return resultStream;
            }
        }

        public virtual async Task<Result.None> OpenRead(Stream stream, SMBPath path, long offset = 0, long? length = null, CancellationToken cancellationToken = default)
        {
            if (path == null) return new ArgumentNullException(nameof(path));
            else
            {
                if (await Exists(path, cancellationToken).ConfigureAwait(false))
                {
                    var shareConnectResponse  = await client.TreeConnect(path.ShareName, cancellationToken).ConfigureAwait(false);
                    if (shareConnectResponse.IsSuccess == false)
                    {
                        return new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}", shareConnectResponse.Error);
                    }

                    var targetFilePath = path.Path;

                    if (client is SMB1Client)
                    {
                        targetFilePath = $"{targetFilePath}\\";
                    }

                    var fileStore = shareConnectResponse.Value;

                    var fileConnectResponse = await fileStore.CreateFile(targetFilePath
                        , SMBLibrary.AccessMask.GENERIC_READ | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.Read | ShareAccess.Write
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null
                        , cancellationToken).ConfigureAwait(false);

                    if (fileConnectResponse.IsSuccess == false)
                    {
                        await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                        return new AccessViolationException($"Not able to connect file {path}", fileConnectResponse.Error);
                    }
                    else
                    {
                        var fileHandle = fileConnectResponse.Value.Handle;
                        long bytesRead = offset;
                        while (true)
                        {
                            var readLength = (int)client.MaxReadSize;
                            if (length.HasValue)
                            {
                                var remainLength = length.Value - (bytesRead - offset);
                                if (remainLength < readLength) readLength = (int)remainLength;
                            }

                            var readFileResponse = await fileStore.ReadFile(fileHandle, bytesRead, readLength, cancellationToken).ConfigureAwait(false);
                            if (readFileResponse.IsSuccess == false)
                            {
                                return new AccessViolationException($"Failed to read from file {path}", readFileResponse.Error);
                            }

                            var responseData = readFileResponse.Value.Data;
                            var responseDataStatus = readFileResponse.Value.ReplyHeaderStatus;
                            if (responseDataStatus == NTStatus.STATUS_END_OF_FILE || responseData.Length == 0)
                            {
                                break;
                            }
                            bytesRead += responseData.Length;
                            await stream.WriteAsync(responseData, 0, responseData.Length, cancellationToken).ConfigureAwait(false);

                            if (length.HasValue && bytesRead >= length.Value)
                            {
                                break;
                            }
                        }

                        await fileStore.CloseFile(fileHandle, cancellationToken).ConfigureAwait(false);
                        await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                        return new Result.None();
                    }
                }
                else return new FileNotFoundException($"{path}");
            }
        }

        public virtual async Task<Result<byte[]>> ReadAllBytes(SMBPath path, int offset = 0, long? length = null, CancellationToken cancellationToken = default)
        {
            var openReadResponse = await OpenRead(path, offset, length, cancellationToken).ConfigureAwait(false);
            if (openReadResponse.IsSuccess == false) return openReadResponse.Error;
            else
            {
                var outputStream = openReadResponse.Value;
                if (outputStream == null) return new byte[0];
                else
                {
                    using (outputStream)
                    {
                        return outputStream.ToArray();
                    }
                }
            }
        }

        public virtual async Task<Result<string>> ReadAllText(SMBPath path, int offset = 0, long? length = null, CancellationToken cancellationToken = default)
        {
            var openReadResponse = await OpenRead(path, offset, length, cancellationToken).ConfigureAwait(false);
            if (openReadResponse.IsSuccess == false) return openReadResponse.Error;
            else
            {
                var outputStream = openReadResponse.Value;
                if (outputStream == null) return string.Empty;
                else
                {
                    using (outputStream)
                    using (var streamReader = new StreamReader(outputStream))
                    {
                        return await streamReader.ReadToEndAsync().ConfigureAwait(false);
                    }
                }
            }
        }

        public virtual async IAsyncEnumerable<string> ReadAllLines(SMBPath path, int offset = 0, long? length = null, Action<Exception> errorHandle = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var openReadResponse = await OpenRead(path, offset, length, cancellationToken).ConfigureAwait(false);
            if (openReadResponse.IsSuccess == false)
            {
                errorHandle?.Invoke(openReadResponse.Error);
            }
            else
            {
                var outputStream = openReadResponse.Value;
                if (outputStream == null) yield break;
                else
                {
                    using (outputStream)
                    using (var streamReader = new StreamReader(outputStream))
                    {
                        while (streamReader.Peek() >= 0)
                        {
                            yield return await streamReader.ReadLineAsync().ConfigureAwait(false);
                        }
                    }
                }
            }
        }

        internal static async Task<Result.None> DoSomethingAfterFileConnect(SMBPath path, ISMBAsyncClient client, Action<ISMBAsyncFileStore, object> action, CancellationToken cancellationToken = default)
        {
            var (isSuccess, noneResult, error) = await DoSomethingAfterFileConnect(path, client, func: (fileStore, fileHandle) =>
            {
                try
                {
                    action?.Invoke(fileStore, fileHandle);
                    return Task.FromResult(new Result.None());
                }
                catch (Exception ex)
                {
                    return Task.FromResult(new Result.None(ex));
                }
            }, cancellationToken).ConfigureAwait(false);

            if (isSuccess) return noneResult;
            else return error;
        }

        internal static async Task<Result<T>> DoSomethingAfterFileConnect<T>(SMBPath path, ISMBAsyncClient client, Func<ISMBAsyncFileStore, object, Task<T>> func, CancellationToken cancellationToken = default)
        {
            if (path == null)
            {
                return new ArgumentNullException(nameof(path));
            }
            else
            {
                var shareConnectResponse = await client.TreeConnect(path.ShareName, cancellationToken).ConfigureAwait(false);
                if (shareConnectResponse.IsSuccess == false) return new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}", shareConnectResponse.Error);

                var targetFilePath = path.Path;

                if (client is SMB1Client)
                {
                    targetFilePath = $"{targetFilePath}\\";
                }

                var fileStore = shareConnectResponse.Value;

                var fileConnectResponse = await fileStore.CreateFile(targetFilePath
                    , SMBLibrary.AccessMask.GENERIC_READ
                    , SMBLibrary.FileAttributes.Directory
                    , SMBLibrary.ShareAccess.Read | SMBLibrary.ShareAccess.Write
                    , SMBLibrary.CreateDisposition.FILE_OPEN
                    , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE
                    , null
                    , cancellationToken).ConfigureAwait(false);

                if (fileConnectResponse.IsSuccess == false)
                {
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return new AccessViolationException($"Not able to connect file {path}", fileConnectResponse.Error);
                }
                else
                {
                    T result = default;
                    if (func != null) result = await func(fileStore, fileConnectResponse.Value.Handle).ConfigureAwait(false);

                    await fileStore.CloseFile(fileConnectResponse.Value.Handle, cancellationToken).ConfigureAwait(false);
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return result;
                }
            }
        }

        // TODO: Curently not support to modify file yet

        public class FileInformation
        {
            public DateTime? CreationTimeUtc { get; private set; }

            public DateTime? CreationTime
            {
                get
                {
                    if (CreationTimeUtc.HasValue) return TimeZoneInfo.ConvertTimeFromUtc(CreationTimeUtc.Value, TimeZoneInfo.Local);
                    else return null;
                }
            }

            public DateTime? LastAccessTimeUtc { get; private set; }

            public DateTime? LastAccessTime
            {
                get
                {
                    if (LastAccessTimeUtc.HasValue) return TimeZoneInfo.ConvertTimeFromUtc(LastAccessTimeUtc.Value, TimeZoneInfo.Local);
                    else return null;
                }
            }

            public DateTime? LastWriteTimeUtc { get; private set; }

            public DateTime? LastWriteTime
            {
                get
                {
                    if (LastWriteTimeUtc.HasValue) return TimeZoneInfo.ConvertTimeFromUtc(LastWriteTimeUtc.Value, TimeZoneInfo.Local);
                    else return null;
                }
            }

            public DateTime? ChangeTimeUtc { get; private set; }

            public DateTime? ChangeTime
            {
                get
                {
                    if (ChangeTimeUtc.HasValue) return TimeZoneInfo.ConvertTimeFromUtc(ChangeTimeUtc.Value, TimeZoneInfo.Local);
                    else return null;
                }
            }

            public SMBLibrary.FileAttributes FileAttributes { get; private set; }

            public uint Reserved { get; private set; }

            public long EndOfFile { get; private set; }

            public long AllocationSize { get; private set; }

            public static FileInformation ParseFrom(SMBLibrary.FileBasicInformation basicInfo, SMBLibrary.FileStandardInformation stdInfo)
            {
                if (basicInfo == null) return null;
                if (stdInfo == null) return null;
                else
                {
                    return new FileInformation
                    {
                        CreationTimeUtc = basicInfo.CreationTime.Time,
                        LastAccessTimeUtc = basicInfo.LastAccessTime.Time,
                        LastWriteTimeUtc = basicInfo.LastWriteTime.Time,
                        ChangeTimeUtc = basicInfo.ChangeTime.Time,
                        FileAttributes = basicInfo.FileAttributes,
                        Reserved = basicInfo.Reserved,
                        AllocationSize = stdInfo.AllocationSize,
                        EndOfFile = stdInfo.EndOfFile
                    };
                }
            }
        }

        public class SetInfoModel
        {
            public DateTime? CreationTimeUtc { get; set; }
            public DateTime? LastAccessTimeUtc { get; set; }
            public DateTime? LastWriteTimeUtc { get; set; }
            public DateTime? ChangeTimeUtc { get; set; }
            public SMBLibrary.FileAttributes FileAttributes { get; set; }

            internal static SetInfoModel ParseFrom(SMBLibrary.FileBasicInformation basicInfo)
            {
                if (basicInfo == null) return null;
                else
                {
                    return new SetInfoModel
                    {
                        CreationTimeUtc = basicInfo.CreationTime.Time,
                        LastAccessTimeUtc = basicInfo.LastAccessTime.Time,
                        LastWriteTimeUtc = basicInfo.LastWriteTime.Time,
                        ChangeTimeUtc = basicInfo.ChangeTime.Time,
                        FileAttributes = basicInfo.FileAttributes,
                    };
                }
            }

            internal SMBLibrary.FileBasicInformation RenderBack(SMBLibrary.FileBasicInformation basicInfo)
            {
                return new SMBLibrary.FileBasicInformation
                {
                    CreationTime = new SetFileTime
                    {
                        Time = this.CreationTimeUtc
                    },
                    LastAccessTime = new SetFileTime
                    {
                        Time = this.LastAccessTimeUtc
                    },
                    LastWriteTime = new SetFileTime
                    {
                        Time = this.LastWriteTimeUtc
                    },
                    ChangeTime = new SetFileTime
                    {
                        Time = this.ChangeTimeUtc
                    },
                    FileAttributes = this.FileAttributes,
                    Reserved = basicInfo.Reserved
                };
            }
        }
    }
}
