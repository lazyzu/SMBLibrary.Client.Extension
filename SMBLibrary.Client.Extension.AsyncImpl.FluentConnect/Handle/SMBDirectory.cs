using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect.Handle
{
    public class SMBDirectory
    {
        private protected readonly ISMBAsyncClient client;
        private protected readonly SMBTransaction transaction;

        public SMBDirectory(ISMBAsyncClient client, SMBTransaction transaction)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));
            if (transaction == null) throw new ArgumentException(nameof(transaction));

            this.client = client;
            this.transaction = transaction;
        }

        public virtual async Task<Result.None> CreateDirectory(SMBPath path, CancellationToken cancellationToken = default)
        {
            if (path == null) return new ArgumentNullException(nameof(path));

            if (await Exists(path, cancellationToken).ConfigureAwait(false)) return new Result.None(); // Already exist, No need to create
            else
            {
                if (string.IsNullOrEmpty(path.Path) == false)
                {
                    var parentFolderPathResponse = path.GetRelative("..");
                    if (parentFolderPathResponse.IsSuccess)
                    {
                        if (await Exists(parentFolderPathResponse.Value, cancellationToken).ConfigureAwait(false) == false)
                        {
                            var parentDirectoryCreateResponse = await CreateDirectory(parentFolderPathResponse.Value, cancellationToken).ConfigureAwait(false);
                            if (parentDirectoryCreateResponse.IsSuccess == false) return parentDirectoryCreateResponse.Error;
                        }
                    }
                    else return parentFolderPathResponse.Error;
                }

                var shareConnectResponse = await client.TreeConnect(path.ShareName, cancellationToken).ConfigureAwait(false);
                if (shareConnectResponse.IsSuccess == false)
                {
                    return new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}", shareConnectResponse.Error);
                }

                var targetFolder = path.Path;

                if (client is SMB1Client)
                {
                    targetFolder = $"{targetFolder}\\";
                }

                var fileStore = shareConnectResponse.Value;
                var createFileResponse = await fileStore.CreateFile(targetFolder
                    , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.SYNCHRONIZE
                    , SMBLibrary.FileAttributes.Normal
                    , SMBLibrary.ShareAccess.Read
                    , SMBLibrary.CreateDisposition.FILE_CREATE
                    , SMBLibrary.CreateOptions.FILE_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                    , null
                    , cancellationToken).ConfigureAwait(false);

                if (createFileResponse.IsSuccess == false)
                {
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return new AccessViolationException($"Not able to create directory {path}", createFileResponse.Error);
                }
                else
                {
                    var directoryHandle = createFileResponse.Value.Handle;
                    await fileStore.CloseFile(directoryHandle, cancellationToken).ConfigureAwait(false);
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return new Result.None();
                }
            }
        }

        public virtual async Task<Result.None> DeleteDirectory(SMBPath path, bool deleteSubItems = false, CancellationToken cancellationToken = default)
        {
            if (path == null) return new ArgumentNullException(nameof(path));
            else
            {
                if (await Exists(path, cancellationToken).ConfigureAwait(false))
                {
                    if (deleteSubItems)
                    {
                        Exception getSubItemException = null;
                        var yieldReturnProcessHandle = new YieldReturnProcessHandle(endProcessOnError: true, errorHandle: (ex) =>
                        {
                            getSubItemException = ex;
                        });

                        await foreach (var subDirectory in GetDirectories(path, yieldReturnProcessHandle: yieldReturnProcessHandle, cancellationToken: cancellationToken).ConfigureAwait(false))
                        {
                            var deleteDirectoryResponse = await DeleteDirectory(subDirectory.SMBPath, deleteSubItems: true, cancellationToken).ConfigureAwait(false);
                            if (deleteDirectoryResponse.IsSuccess == false) return new AccessViolationException($"Error occured when deleting {subDirectory}", deleteDirectoryResponse.Error);
                        }
                        if (getSubItemException != null) return new AccessViolationException($"Error occured when access sub items of {path}", getSubItemException);

                        var fileHandle = new SMBFile(this.client, this.transaction);
                        await foreach (var subFile in GetFiles(path, yieldReturnProcessHandle: yieldReturnProcessHandle, cancellationToken: cancellationToken).ConfigureAwait(false))
                        {
                            var deleteFileResponse = await fileHandle.DeleteFile(subFile.SMBPath, cancellationToken).ConfigureAwait(false);
                            if (deleteFileResponse.IsSuccess == false) return new AccessViolationException($"Error occured when deleting {subFile}", deleteFileResponse.Error);
                        }
                        if (getSubItemException != null) return new AccessViolationException($"Error occured when access sub items of {path}", getSubItemException);
                    }

                    var shareConnectResponse = await client.TreeConnect(path.ShareName, cancellationToken).ConfigureAwait(false);
                    if (shareConnectResponse.IsSuccess == false)
                    {
                        return new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}", shareConnectResponse.Error);
                    }

                    var targetFolder = path.Path;

                    if (client is SMB1Client)
                    {
                        targetFolder = $"{targetFolder}\\";
                    }

                    var fileStore = shareConnectResponse.Value;

                    var directoryConnectResponse = await fileStore.CreateFile(targetFolder
                        , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.DELETE | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.Read
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null
                        , cancellationToken).ConfigureAwait(false);

                    if (directoryConnectResponse.IsSuccess == false)
                    {
                        await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                        return new AccessViolationException($"Not able to connect directory {path}", directoryConnectResponse.Error);
                    }
                    else
                    {
                        FileDispositionInformation fileDispositionInformation = new FileDispositionInformation();
                        fileDispositionInformation.DeletePending = true;
                        var directoryHandle = directoryConnectResponse.Value.Handle;
                        var setFileInformationResponse = await fileStore.SetFileInformation(directoryHandle, fileDispositionInformation, cancellationToken).ConfigureAwait(false);

                        await fileStore.CloseFile(directoryHandle, cancellationToken).ConfigureAwait(false);
                        await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);

                        bool deleteSucceeded = setFileInformationResponse.IsSuccess;
                        if (deleteSucceeded == false) return new AccessViolationException($"Not able to delete directory {path}", setFileInformationResponse.Error);
                        else
                        {
                            if (setFileInformationResponse.Value == NTStatus.STATUS_SUCCESS) return new Result.None();
                            else return new AccessViolationException($"Not able to delete directory {path}", new ErrorResponseException(setFileInformationResponse.Value));
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
                return new ArgumentException($"{nameof(to)} directory {to} is already exist");
            }
            else
            {
                if (await Exists(from, cancellationToken).ConfigureAwait(false))
                {
                    var shareConnectResponse = await client.TreeConnect(from.ShareName, cancellationToken).ConfigureAwait(false);
                    if (shareConnectResponse.IsSuccess)
                    {
                        var fromFolderPath = from.Path;

                        if (client is SMB1Client)
                        {
                            fromFolderPath = $"{fromFolderPath}\\";
                        }

                        var fileStore = shareConnectResponse.Value;

                        var fromDirectoryConnectResponse = await fileStore.CreateFile(fromFolderPath
                            , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.DELETE | SMBLibrary.AccessMask.SYNCHRONIZE
                            , SMBLibrary.FileAttributes.Normal
                            , SMBLibrary.ShareAccess.None
                            , SMBLibrary.CreateDisposition.FILE_OPEN
                            , SMBLibrary.CreateOptions.FILE_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                            , null
                            , cancellationToken).ConfigureAwait(false);

                        if (fromDirectoryConnectResponse.IsSuccess == false)
                        {
                            await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                            return new AccessViolationException($"Not able to connect directory {from}", fromDirectoryConnectResponse.Error);
                        }
                        else
                        {
                            var toParentFolderPathResponse = to.GetRelative("..");
                            if (toParentFolderPathResponse.IsSuccess)
                            {
                                var createDirectoryResponse = await CreateDirectory(toParentFolderPathResponse.Value, cancellationToken).ConfigureAwait(false);
                                if (createDirectoryResponse.IsSuccess == false)
                                {
                                    await fileStore.CloseFile(fromDirectoryConnectResponse.Value.Handle, cancellationToken).ConfigureAwait(false);
                                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);

                                    return createDirectoryResponse.Error;
                                }

                                Result.NTStatus setFileInformationResponse;
                                if (client is SMB1Client)
                                {
                                    FileRenameInformationType1 fileRenameInformation = new FileRenameInformationType1();
                                    fileRenameInformation.FileName = to.Path;
                                    fileRenameInformation.ReplaceIfExists = false;
                                    setFileInformationResponse = await fileStore.SetFileInformation(fromDirectoryConnectResponse.Value.Handle, fileRenameInformation, cancellationToken).ConfigureAwait(false);
                                }
                                else
                                {
                                    FileRenameInformationType2 fileRenameInformation = new FileRenameInformationType2();
                                    fileRenameInformation.FileName = to.Path;
                                    fileRenameInformation.ReplaceIfExists = false;
                                    setFileInformationResponse = await fileStore.SetFileInformation(fromDirectoryConnectResponse.Value.Handle, fileRenameInformation, cancellationToken).ConfigureAwait(false);
                                }

                                await fileStore.CloseFile(fromDirectoryConnectResponse.Value.Handle, cancellationToken).ConfigureAwait(false);
                                await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);

                                if (setFileInformationResponse.IsSuccess)
                                {
                                    if (setFileInformationResponse.Value == NTStatus.STATUS_SUCCESS) return new Result.None();
                                    else return new AccessViolationException($"Move operation from {from} to {to} is failed", new ErrorResponseException(setFileInformationResponse.Value));
                                }
                                else return new AccessViolationException($"Move operation from {from} to {to} is failed", setFileInformationResponse.Error);
                            }
                            else
                            {
                                await fileStore.CloseFile(fromDirectoryConnectResponse.Value.Handle, cancellationToken).ConfigureAwait(false);
                                await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                                return toParentFolderPathResponse.Error;
                            }
                        }
                    }
                    else return new AccessViolationException($"Not able to connect share {from.ShareName} of {from.HostName}", shareConnectResponse.Error);
                }
                else return new ArgumentException($"{nameof(from)} directory {from} is not exist");
            }
        }

        public virtual async Task<bool> Exists(SMBPath path, CancellationToken cancellationToken = default)
        {
            var directoryConnectResponse = await DoSomethingAfterDirectoryConnect(path, action: null, cancellationToken).ConfigureAwait(false);
            return directoryConnectResponse.IsSuccess;
        }

        public virtual async Task<Result<DirectoryInformation>> GetInfo(SMBPath path, CancellationToken cancellationToken = default)
        {
            var (isDirectoryConnectSuccess, getFileInformationResponse, directoryConnectError) = await DoSomethingAfterDirectoryConnect<Result<DirectoryInformation>>(path, func: async (fileStore, directoryHandle) =>
            {
                var (isGetFileInfoSuccess, information, error) = await fileStore.GetFileInformation(directoryHandle, SMBLibrary.FileInformationClass.FileBasicInformation, cancellationToken).ConfigureAwait(false);
                if (isGetFileInfoSuccess)
                {
                    if (information is SMBLibrary.FileBasicInformation fileBsicInformation) return DirectoryInformation.ParseFrom(fileBsicInformation);
                    else return new NotSupportedException($"Not able to get info of directory {path}, error:NOT_SUPPORT_RESULT_TYPE({information.GetType().FullName})");
                }
                else return error;
            }, cancellationToken).ConfigureAwait(false);

            if (isDirectoryConnectSuccess && getFileInformationResponse.IsSuccess) return getFileInformationResponse.Value;
            else if (isDirectoryConnectSuccess == false) return directoryConnectError;
            else return getFileInformationResponse.Error;
        }

        public virtual async IAsyncEnumerable<FileDirectoryInformation> GetFiles(SMBPath path, string searchPattern = "*", SearchOption searchOption = SearchOption.TopDirectoryOnly, YieldReturnProcessHandle yieldReturnProcessHandle = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var _yieldReturnProcessHandle = yieldReturnProcessHandle ?? YieldReturnProcessHandle.GetDefault();

            if (await Exists(path).ConfigureAwait(false))
            {
                switch (searchOption)
                {
                    case SearchOption.TopDirectoryOnly:
                        var (isSuccess, entries, error) = await GetFileEntries(path, searchPattern, cancellationToken).ConfigureAwait(false);
                        if (isSuccess)
                        {
                            foreach (var entry in entries) yield return entry;
                        }
                        else _yieldReturnProcessHandle.ErrorHandle(error);
                        break;
                    case SearchOption.AllDirectories:
                        await foreach (var entry in GetFileEntries_AllDirectory(path, _yieldReturnProcessHandle, searchPattern, cancellationToken).ConfigureAwait(false)) yield return entry;
                        break;
                    default:
                        _yieldReturnProcessHandle.ErrorHandle(new NotSupportedException());
                        break;
                }
            }
            else
            {
                //_yieldReturnProcessHandle.ErrorHandle(new AccessViolationException($"{path} is not exist"));
            }
        }

        public virtual async IAsyncEnumerable<FileDirectoryInformation> GetDirectories(SMBPath path, string searchPattern = "*", SearchOption searchOption = SearchOption.TopDirectoryOnly, YieldReturnProcessHandle yieldReturnProcessHandle = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var _yieldReturnProcessHandle = yieldReturnProcessHandle ?? YieldReturnProcessHandle.GetDefault();

            if (await Exists(path).ConfigureAwait(false))
            {
                switch (searchOption)
                {
                    case SearchOption.TopDirectoryOnly:
                        var (isSuccess, entries, error) = await GetDirectoryEntries(path, searchPattern, cancellationToken).ConfigureAwait(false);
                        if (isSuccess)
                        {
                            foreach (var entry in entries) yield return entry;
                        }
                        else _yieldReturnProcessHandle.ErrorHandle(error);
                        break;
                    case SearchOption.AllDirectories:
                        await foreach (var entry in GetDirectoryEntries_AllDirectory(path, _yieldReturnProcessHandle, searchPattern, cancellationToken).ConfigureAwait(false)) yield return entry;
                        break;
                    default:
                        _yieldReturnProcessHandle.ErrorHandle(new NotSupportedException());
                        break;
                }
            }
            else
            {
                //_yieldReturnProcessHandle.ErrorHandle(new AccessViolationException($"{path} is not exist"));
            }
        }

        private async Task<Result<FileDirectoryInformation[]>> GetDirectoryEntries(SMBPath path, string searchPattern = "*", CancellationToken cancellationToken = default)
        {
            var getEntriesResponse = await GetEntries(path, searchPattern, cancellationToken).ConfigureAwait(false);
            if (getEntriesResponse.IsSuccess) return GetDirectoryEntries(getEntriesResponse.Value).ToArray();
            else return getEntriesResponse.Error;
        }

        private IEnumerable<FileDirectoryInformation> GetDirectoryEntries(IEnumerable<FileDirectoryInformation> entries)
        {
            if (entries == null) yield break;
            else
            {
                foreach (var entry in entries)
                {
                    var isDirectory = ((entry.FileAttributes & SMBLibrary.FileAttributes.Directory) > 0);
                    var isCurrentOrParentDirectory = entry.FileName.StartsWith(".");
                    if (isDirectory && (isCurrentOrParentDirectory == false)) yield return entry;
                }
            }
        }

        private async Task<Result<FileDirectoryInformation[]>> GetFileEntries(SMBPath path, string searchPattern = "*", CancellationToken cancellationToken = default)
        {
            var getEntriesResponse = await GetEntries(path, searchPattern, cancellationToken).ConfigureAwait(false);
            if (getEntriesResponse.IsSuccess) return GetFileEntries(getEntriesResponse.Value).ToArray();
            else return getEntriesResponse.Error;
        }

        private IEnumerable<FileDirectoryInformation> GetFileEntries(IEnumerable<FileDirectoryInformation> entries)
        {
            if (entries == null) yield break;
            else
            {
                foreach (var entry in entries)
                {
                    if ((entry.FileAttributes & SMBLibrary.FileAttributes.Directory) == 0) yield return entry;
                }
            }
        }

        private async IAsyncEnumerable<FileDirectoryInformation> GetFileEntries_AllDirectory(SMBPath path, YieldReturnProcessHandle yieldReturnProcessHandle, string searchPattern = "*", [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            if (yieldReturnProcessHandle.EndProcessRequested) yield break;
            else
            {
                var getTopEntriesResponse = await GetEntries(path, searchPattern, cancellationToken).ConfigureAwait(false);
                if (getTopEntriesResponse.IsSuccess)
                {
                    var patternMatchedFileEntries = GetFileEntries(getTopEntriesResponse.Value);
                    foreach (var patternMatchedFileEntry in patternMatchedFileEntries) yield return patternMatchedFileEntry;

                    var getTopDirectoryEntriesResponse = await GetEntries(path, "*", cancellationToken).ConfigureAwait(false);

                    if (getTopDirectoryEntriesResponse.IsSuccess)
                    {
                        var topDirectoryEntries = GetDirectoryEntries(getTopDirectoryEntriesResponse.Value);
                        foreach (var topDirectoryEntry in topDirectoryEntries)
                        {
                            if (topDirectoryEntry.FileName.StartsWith(".") == false)   // Not parent folder or current folder
                            {
                                await foreach (var patternMatchedFileEntry in GetFileEntries_AllDirectory(topDirectoryEntry.SMBPath, yieldReturnProcessHandle, searchPattern, cancellationToken).ConfigureAwait(false))
                                {
                                    yield return patternMatchedFileEntry;
                                }
                            }
                        }
                    }
                    else yieldReturnProcessHandle.ErrorHandle(getTopDirectoryEntriesResponse.Error);
                }
                else yieldReturnProcessHandle.ErrorHandle(getTopEntriesResponse.Error);
            }
        }

        private async IAsyncEnumerable<FileDirectoryInformation> GetDirectoryEntries_AllDirectory(SMBPath path, YieldReturnProcessHandle yieldReturnProcessHandle, string searchPattern = "*", [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            if (yieldReturnProcessHandle.EndProcessRequested) yield break;
            else
            {
                var getTopEntriesResponse = await GetEntries(path, searchPattern, cancellationToken).ConfigureAwait(false);
                if (getTopEntriesResponse.IsSuccess)
                {
                    IEnumerable<FileDirectoryInformation> result = new FileDirectoryInformation[0];

                    var patternMatchedDirectoryEntries = GetDirectoryEntries(getTopEntriesResponse.Value);
                    foreach (var patternMatchedDirectoryEntry in patternMatchedDirectoryEntries) yield return patternMatchedDirectoryEntry;

                    var getTopDirectoryEntriesResponse = await GetEntries(path, "*", cancellationToken).ConfigureAwait(false);
                    if (getTopDirectoryEntriesResponse.IsSuccess)
                    {
                        var topDirectoryEntries = GetDirectoryEntries(getTopDirectoryEntriesResponse.Value);
                        foreach (var topDirectoryEntry in topDirectoryEntries)
                        {
                            if (topDirectoryEntry.FileName.StartsWith(".") == false)   // Not parent folder or current folder
                            {
                                await foreach (var patternMatchedDirectoryEntry in GetDirectoryEntries_AllDirectory(topDirectoryEntry.SMBPath, yieldReturnProcessHandle, searchPattern, cancellationToken).ConfigureAwait(false))
                                {
                                    yield return patternMatchedDirectoryEntry;
                                }
                            }
                        }
                    }
                    else yieldReturnProcessHandle.ErrorHandle(getTopDirectoryEntriesResponse.Error);
                }
                else yieldReturnProcessHandle.ErrorHandle(getTopEntriesResponse.Error);
            }
        }

        private async Task<Result<FileDirectoryInformation[]>> GetEntries(SMBPath path, string searchPattern = "*", CancellationToken cancellationToken = default)
        {
            var (isDirectoryConnectSuccess, getEntriesResponse, directoryConnectError) =  await DoSomethingAfterDirectoryConnect(path, func: async (fileStore, directoryHandle) =>
            {
                return await GetEntries(path, fileStore, directoryHandle, searchPattern, cancellationToken).ConfigureAwait(false);
            }, cancellationToken).ConfigureAwait(false);

            if (isDirectoryConnectSuccess && getEntriesResponse.IsSuccess) return getEntriesResponse.Value;
            else if (isDirectoryConnectSuccess == false) return directoryConnectError;
            else return getEntriesResponse.Error;
        }

        private async Task<Result<FileDirectoryInformation[]>> GetEntries(SMBPath path, ISMBAsyncFileStore fileStore, object directoryHandle, string searchPattern = "*", CancellationToken cancellationToken = default)
        {
            var targetSearch = searchPattern?.Trim() ?? "*";

            if (client is SMB1Client)
            {
                targetSearch = $"\\{targetSearch}";
            }

            var queryDirectoryResponse = await fileStore.QueryDirectory(directoryHandle, targetSearch, FileInformationClass.FileDirectoryInformation, cancellationToken).ConfigureAwait(false);
            if (queryDirectoryResponse.IsSuccess == false)
            {
                return queryDirectoryResponse.Error;
            }
            else return FileDirectoryInformation.ParseFrom(queryDirectoryResponse.Value, path).ToArray();
        }

        private async Task<Result.None> DoSomethingAfterDirectoryConnect(SMBPath path, Action<ISMBAsyncFileStore, object> action, CancellationToken cancellationToken = default)
        {
            var (isSuccess, noneResult, error) = await DoSomethingAfterDirectoryConnect(path, func: (fileStore, directoryHandle) =>
            {
                try
                {
                    action?.Invoke(fileStore, directoryHandle);
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

        private async Task<Result<T>> DoSomethingAfterDirectoryConnect<T>(SMBPath path, Func<ISMBAsyncFileStore, object, Task<T>> func, CancellationToken cancellationToken = default)
        {
            if (path == null)
            {
                return new ArgumentNullException(nameof(path));
            }
            else
            {
                var shareConnectResponse = await client.TreeConnect(path.ShareName, cancellationToken).ConfigureAwait(false);
                if (shareConnectResponse.IsSuccess == false) return new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}", shareConnectResponse.Error);

                var targetFolder = path.Path;

                if (client is SMB1Client)
                {
                    targetFolder = $"{targetFolder}\\";
                }

                var fileStore = shareConnectResponse.Value;

                var directoryConnectResponse = await fileStore.CreateFile(targetFolder
                    , SMBLibrary.AccessMask.GENERIC_READ
                    , SMBLibrary.FileAttributes.Directory
                    , SMBLibrary.ShareAccess.Read | SMBLibrary.ShareAccess.Write
                    , SMBLibrary.CreateDisposition.FILE_OPEN
                    , SMBLibrary.CreateOptions.FILE_DIRECTORY_FILE
                    , null
                    , cancellationToken).ConfigureAwait(false);

                if (directoryConnectResponse.IsSuccess == false)
                {
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return new AccessViolationException($"Not able to connect directory {path}", directoryConnectResponse.Error);
                }
                else
                {
                    T result = default;
                    if (func != null) result = await func(fileStore, directoryConnectResponse.Value.Handle).ConfigureAwait(false);

                    await fileStore.CloseFile(directoryConnectResponse.Value.Handle, cancellationToken).ConfigureAwait(false);
                    await fileStore.Disconnect(cancellationToken).ConfigureAwait(false);
                    return result;
                }
            }
        }

        public class FileDirectoryInformation
        {
            public string FileName { get; private set; } = string.Empty;

            public DateTime CreationTime { get; private set; }

            public DateTime LastAccessTime { get; private set; }

            public DateTime LastWriteTime { get; private set; }

            public DateTime ChangeTime { get; private set; }

            public long EndOfFile { get; private set; }

            public long AllocationSize { get; private set; }

            public SMBLibrary.FileAttributes FileAttributes { get; private set; }

            public SMBPath SMBPath { get; private set; }

            public static FileDirectoryInformation ParseFrom(SMBLibrary.FileDirectoryInformation source, SMBPath parent)
            {
                if (source == null) return null;
                else
                {
                    var (smbPathParsed, smbPath, _) = parent.GetRelative(source.FileName);
                    return new FileDirectoryInformation
                    {
                        FileName = source.FileName,
                        CreationTime = source.CreationTime,
                        LastAccessTime = source.LastAccessTime,
                        LastWriteTime = source.LastWriteTime,
                        ChangeTime = source.ChangeTime,
                        EndOfFile = source.EndOfFile,
                        AllocationSize = source.AllocationSize,
                        FileAttributes = source.FileAttributes,
                        SMBPath = smbPath
                    };
                }
            }

            public static IEnumerable<FileDirectoryInformation> ParseFrom(IEnumerable<QueryDirectoryFileInformation> queryDirectoryFileInformations, SMBPath path)
            {
                if (queryDirectoryFileInformations != null)
                {
                    foreach (var entry in queryDirectoryFileInformations)
                    {
                        if (entry is SMBLibrary.FileDirectoryInformation entryResult)
                        {
                            yield return FileDirectoryInformation.ParseFrom(entryResult, path);
                        }
                    }
                }
            }
        }

        public class DirectoryInformation
        {
            public DateTime? CreationTimeUtc { get; private set; }

            public DateTime? CreationTime
            {
                get
                {
                    if(CreationTimeUtc.HasValue) return TimeZoneInfo.ConvertTimeFromUtc(CreationTimeUtc.Value, TimeZoneInfo.Local);
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

            public static DirectoryInformation ParseFrom(SMBLibrary.FileBasicInformation info)
            {
                if (info == null) return null;
                else
                {
                    return new DirectoryInformation
                    {
                        CreationTimeUtc = info.CreationTime.Time,
                        LastAccessTimeUtc = info.LastAccessTime.Time,
                        LastWriteTimeUtc = info.LastWriteTime.Time,
                        ChangeTimeUtc = info.ChangeTime.Time,
                        FileAttributes = info.FileAttributes,
                        Reserved = info.Reserved
                    };
                }
            }
        }
    }
}
