using SMBLibrary.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SMBLibrary.Client.Extension.FluentConnect
{
    public class SMBDirectory
    {
        private ISMBClient client;

        public SMBDirectory(ISMBClient client)
        {
            if(client == null) throw new ArgumentNullException("client");

            this.client = client;
        }

        public void CreateDirectory(SMBPath path)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));

            if (Exists(path)) { /*Already exist, No need to create*/ }
            else
            {
                if (string.IsNullOrEmpty(path.Path) == false)
                {
                    var (parentPathParsed, parentPath, _) = path.GetRelative("..");
                    if (Exists(parentPath) == false) CreateDirectory(parentPath);
                }

                var fileStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
                if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
                {
                    throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
                }

                var targetFolder = path.Path;

                if (client is SMB1Client)
                {
                    targetFolder = $"{targetFolder}\\";
                }

                var directoryConnectStatus = fileStore.CreateFile(out var directoryHandle
                    , out var directoryConnectFileStatus
                    , targetFolder
                    , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.SYNCHRONIZE
                    , SMBLibrary.FileAttributes.Normal
                    , SMBLibrary.ShareAccess.Read
                    , SMBLibrary.CreateDisposition.FILE_CREATE
                    , SMBLibrary.CreateOptions.FILE_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                    , null);

                if (directoryHandle == null)
                {
                    fileStore.Disconnect();
                    throw new AccessViolationException($"Not able to connect directory {path}, error:{directoryConnectStatus}({directoryConnectFileStatus})");
                }
                else
                {
                    fileStore.CloseFile(directoryHandle);
                    fileStore.Disconnect();
                }
            }
        }

        public void DeleteDirectory(SMBPath path, bool deleteSubItems = false)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            else
            {
                if (Exists(path))
                {
                    if (deleteSubItems)
                    {
                        foreach (var subDirectory in GetDirectories(path))
                        {
                            DeleteDirectory(subDirectory.SMBPath, deleteSubItems: true);
                        }

                        var fileHandle = new SMBFile(this.client);
                        foreach (var subFile in GetFiles(path)) fileHandle.DeleteFile(subFile.SMBPath);
                    }

                    var fileStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
                    if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
                    {
                        throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
                    }

                    var targetFolder = path.Path;

                    if (client is SMB1Client)
                    {
                        targetFolder = $"{targetFolder}\\";
                    }

                    var directoryConnectStatus = fileStore.CreateFile(out var directoryHandle
                        , out var directoryConnectFileStatus
                        , targetFolder
                        , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.DELETE | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.Read
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null);

                    if (directoryHandle == null)
                    {
                        fileStore.Disconnect();
                        throw new AccessViolationException($"Not able to connect directory {path}, error:{directoryConnectStatus}({directoryConnectFileStatus})");
                    }
                    else
                    {
                        FileDispositionInformation fileDispositionInformation = new FileDispositionInformation();
                        fileDispositionInformation.DeletePending = true;
                        var setFileInformationStatus = fileStore.SetFileInformation(directoryHandle, fileDispositionInformation);
                        bool deleteSucceeded = (setFileInformationStatus == NTStatus.STATUS_SUCCESS);
                        if (deleteSucceeded == false) throw new AccessViolationException($"Not able to delete directory {path}, error:{setFileInformationStatus}");

                        fileStore.CloseFile(directoryHandle);
                        fileStore.Disconnect();
                    }
                }
                else
                {
                    // Not exist, No need to delete
                }
            }
        }

        public void Move(SMBPath from, SMBPath to)
        {
            if (from == null) throw new ArgumentNullException(nameof(from));
            if (to == null) throw new ArgumentNullException(nameof(to));

            if (Exists(to))
            {
                throw new ArgumentException($"{nameof(to)} directory {to} is already exist");
            }
            else
            {
                if (Exists(from))
                {
                    var fileStore = client.TreeConnect(from.ShareName, out var shareConnectStatus);
                    if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
                    {
                        throw new AccessViolationException($"Not able to connect share {from.ShareName} of {from.HostName}, error:{shareConnectStatus}");
                    }

                    var targetFolder = from.Path;

                    if (client is SMB1Client)
                    {
                        targetFolder = $"{targetFolder}\\";
                    }

                    var directoryConnectStatus = fileStore.CreateFile(out var directoryHandle
                        , out var directoryConnectFileStatus
                        , targetFolder
                        , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.None
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null);

                    if (directoryHandle == null)
                    {
                        fileStore.Disconnect();
                        throw new AccessViolationException($"Not able to connect directory {from}, error:{directoryConnectStatus}({directoryConnectFileStatus})");
                    }
                    else
                    {
                        var (toParentPathParsed, toParentPath, _) = to.GetRelative("..");
                        CreateDirectory(toParentPath);

                        NTStatus? setFileInformationStatus;

                        if (client is SMB1Client)
                        {
                            FileRenameInformationType1 fileRenameInformation = new FileRenameInformationType1();
                            fileRenameInformation.FileName = to.Path;
                            fileRenameInformation.ReplaceIfExists = false;
                            setFileInformationStatus = fileStore.SetFileInformation(directoryHandle, fileRenameInformation);
                        }
                        else
                        {
                            FileRenameInformationType2 fileRenameInformation = new FileRenameInformationType2();
                            fileRenameInformation.FileName = to.Path;
                            fileRenameInformation.ReplaceIfExists = false;
                            setFileInformationStatus = fileStore.SetFileInformation(directoryHandle, fileRenameInformation);
                        }

                        fileStore.CloseFile(directoryHandle);
                        fileStore.Disconnect();

                        if (setFileInformationStatus == NTStatus.STATUS_SUCCESS) // renameSucceeded
                        { }
                        else
                        {
                            throw new AccessViolationException($"Move operation from {from} to {to} is failed, error:{setFileInformationStatus}");
                        }
                    }
                }
                else throw new ArgumentException($"{nameof(from)} directory {from} is not exist");
            }
        }

        public bool Exists(SMBPath path)
        {
            try
            {
                DoSomethingAfterDirectoryConnect(path, null, out var isDirectoryConnected);
                return isDirectoryConnected;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public DirectoryInformation GetInfo(SMBPath path)
        {
            return DoSomethingAfterDirectoryConnect(path, func: (fileStore, directoryHandle) =>
            {
                var getFileInfoStatus = fileStore.GetFileInformation(out var fileInformation, directoryHandle, SMBLibrary.FileInformationClass.FileBasicInformation);
                if (getFileInfoStatus != NTStatus.STATUS_SUCCESS) throw new AccessViolationException($"Not able to get info of directory {path}, error:{getFileInfoStatus}");
                if (fileInformation == null) throw new AccessViolationException($"Not able to get info of directory {path}, error:NULL_RESULT");
                if (fileInformation is SMBLibrary.FileBasicInformation info)
                {
                    return DirectoryInformation.ParseFrom(info);
                }
                else throw new NotSupportedException($"Not able to get info of directory {path}, error:NOT_SUPPORT_RESULT_TYPE({fileInformation.GetType().FullName})");
            }, out var isDirectoryConnected);
        }

        public IEnumerable<FileDirectoryInformation> GetFiles(SMBPath path, string searchPattern = "*", SearchOption searchOption = SearchOption.TopDirectoryOnly)
        {
            switch (searchOption)
            {
                case SearchOption.TopDirectoryOnly:
                    return GetFileEntries(path, searchPattern);
                case SearchOption.AllDirectories:
                    return GetFileEntries_AllDirectory(path, searchPattern);
                default:
                    throw new NotSupportedException();
            }
        }

        public IEnumerable<FileDirectoryInformation> GetDirectories(SMBPath path, string searchPattern = "*", SearchOption searchOption = SearchOption.TopDirectoryOnly)
        {
            switch (searchOption)
            {
                case SearchOption.TopDirectoryOnly:
                    return GetDirectoryEntries(path, searchPattern);
                case SearchOption.AllDirectories:
                    return GetDirectoryEntries_AllDirectory(path, searchPattern);
                default:
                    throw new NotSupportedException();
            }
        }

        private IEnumerable<FileDirectoryInformation> GetDirectoryEntries(SMBPath path, string searchPattern = "*")
        {
            var entries = GetEntries(path, searchPattern);
            return GetDirectoryEntries(entries);
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

        private IEnumerable<FileDirectoryInformation> GetFileEntries(SMBPath path, string searchPattern = "*")
        {
            var entries = GetEntries(path, searchPattern);
            return GetFileEntries(entries);
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

        private IEnumerable<FileDirectoryInformation> GetFileEntries_AllDirectory(SMBPath path, string searchPattern = "*")
        {
            var patternMatchedEntries = GetEntries(path, searchPattern);
            var patternMatchedFileEntries = GetFileEntries(patternMatchedEntries);
            foreach (var patternMatchedFileEntry in patternMatchedFileEntries) yield return patternMatchedFileEntry;

            var allSubEntries = GetEntries(path, "*");
            var subDirectoryEntries = GetDirectoryEntries(allSubEntries);
            foreach (var subDirectoryEntry in subDirectoryEntries)
            {
                if (subDirectoryEntry.FileName.StartsWith(".") == false)   // Not parent folder or current folder
                {
                    var (subPathParsed, subPath, _) = path.GetRelative(subDirectoryEntry.FileName);
                    foreach (var fileEntryInSubFolder in GetFileEntries_AllDirectory(subPath, searchPattern))
                    {
                        yield return fileEntryInSubFolder;
                    }
                }
            }
        }

        private IEnumerable<FileDirectoryInformation> GetDirectoryEntries_AllDirectory(SMBPath path, string searchPattern = "*")
        {
            var patternMatchedEntries = GetEntries(path, searchPattern);
            var patternMatchedDirectoryEntries = GetDirectoryEntries(patternMatchedEntries);
            foreach (var patternMatchedDirectoryEntry in patternMatchedDirectoryEntries) yield return patternMatchedDirectoryEntry;

            var allSubEntries = GetEntries(path, "*");
            var subDirectoryEntries = GetDirectoryEntries(allSubEntries);
            foreach (var subDirectoryEntry in subDirectoryEntries)
            {
                if (subDirectoryEntry.FileName.StartsWith(".") == false)   // Not parent folder or current folder
                {
                    var(subPathParsed, subPath, _) = path.GetRelative(subDirectoryEntry.FileName);
                    foreach (var directoryEntryInSubFolder in GetDirectoryEntries_AllDirectory(subPath, searchPattern))
                    {
                        yield return directoryEntryInSubFolder;
                    }
                }
            }
        }

        private IEnumerable<FileDirectoryInformation> GetEntries(SMBPath path, string searchPattern = "*")
        {
            var result = DoSomethingAfterDirectoryConnect(path, func: (fileStore, directoryHandle) =>
            {
                return GetEntries(path, fileStore, directoryHandle, searchPattern).ToArray();

            }, out var isDirectoryConnected);

            return result ?? new FileDirectoryInformation[0];
        }

        private IEnumerable<FileDirectoryInformation> GetEntries(SMBPath path, ISMBFileStore fileStore, object directoryHandle, string searchPattern = "*")
        {
            var targetSearch = searchPattern?.Trim() ?? "*";

            if (client is SMB1Client)
            {
                targetSearch = $"\\{targetSearch}";
            }

            var queryStatus = fileStore.QueryDirectory(out var directoryFileInfos, directoryHandle, targetSearch, FileInformationClass.FileDirectoryInformation);
            if (queryStatus != NTStatus.STATUS_SUCCESS && queryStatus != NTStatus.STATUS_NO_MORE_FILES)
            {
                if(queryStatus == NTStatus.STATUS_NO_SUCH_FILE) yield break;    // 沒有任何結果回傳
                else throw new AccessViolationException($"Get entries from {path} is failed, error:{queryStatus}");
            }

            foreach (var entry in directoryFileInfos)
            {
                if (entry is SMBLibrary.FileDirectoryInformation entryResult)
                {
                    yield return FileDirectoryInformation.ParseFrom(entryResult, path);
                }
            }
        }

        private void DoSomethingAfterDirectoryConnect(SMBPath path, Action<ISMBFileStore, object> action, out bool isDirectoryConnected)
        {
            DoSomethingAfterDirectoryConnect<object>(path, func: null, out isDirectoryConnected);
        }

        private T DoSomethingAfterDirectoryConnect<T>(SMBPath path, Func<ISMBFileStore, object, T> func, out bool isDirectoryConnected)
        {
            if (path == null)
            {
                isDirectoryConnected = false;
                throw new ArgumentNullException(nameof(path));
            }
            else
            {
                var fileStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
                if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
                {
                    isDirectoryConnected = false;
                    throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
                } 

                var targetFolder = path.Path;

                if (client is SMB1Client)
                {
                    targetFolder = $"{targetFolder}\\";
                }

                var directoryConnectStatus = fileStore.CreateFile(out var directoryHandle
                    , out var directoryConnectFileStatus
                    , targetFolder
                    , SMBLibrary.AccessMask.GENERIC_READ
                    , SMBLibrary.FileAttributes.Directory
                    , SMBLibrary.ShareAccess.Read | SMBLibrary.ShareAccess.Write
                    , SMBLibrary.CreateDisposition.FILE_OPEN
                    , SMBLibrary.CreateOptions.FILE_DIRECTORY_FILE
                    , null);

                if (directoryHandle == null)
                {
                    isDirectoryConnected = false;
                    fileStore.Disconnect();
                    throw new AccessViolationException($"Not able to connect directory {path}, error:{directoryConnectStatus}({directoryConnectFileStatus})");
                }
                else
                {
                    isDirectoryConnected = true;

                    T result = default;
                    if (func != null) result = func(fileStore, directoryHandle);

                    fileStore.CloseFile(directoryHandle);
                    fileStore.Disconnect();
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
