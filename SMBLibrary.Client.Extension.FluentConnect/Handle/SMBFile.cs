using SMBLibrary.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.FluentConnect
{
    public class SMBFile
    {
        internal ISMBClient client;

        public SMBFile(ISMBClient client)
        {
            if (client == null) throw new ArgumentNullException("client");

            this.client = client;
        }

        public void CreateFile(SMBPath path, Stream stream)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var directoryHandle = new SMBDirectory(client);
            var (parentDirectoryParsed, parentDirectory, _) = path.GetRelative("..");
            if (parentDirectory != null && (directoryHandle.Exists(parentDirectory) == false))
            {
                directoryHandle.CreateDirectory(parentDirectory);
            }

            var fileStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
            if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
            {
                throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
            }

            var fileConnectStatus = fileStore.CreateFile(out var fileHandle
                , out var fileConnectFileStatus
                , path.Path
                , AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE, FileAttributes.Normal
                , ShareAccess.Read
                , CreateDisposition.FILE_SUPERSEDE
                , CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                , null);

            if (fileConnectStatus == NTStatus.STATUS_SUCCESS)
            {
                int writeOffset = 0;
                while (stream.Position < stream.Length)
                {
                    byte[] buffer = new byte[(int)client.MaxWriteSize];
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead < (int)client.MaxWriteSize)
                    {
                        Array.Resize<byte>(ref buffer, bytesRead);
                    }
                    int numberOfBytesWritten;
                    var writeStatus = fileStore.WriteFile(out numberOfBytesWritten, fileHandle, writeOffset, buffer);
                    if (writeStatus != NTStatus.STATUS_SUCCESS)
                    {
                        throw new AccessViolationException($"Failed to write file: {path}, error: {writeStatus}");
                    }
                    writeOffset += bytesRead;
                }
                var fileCloseStatus = fileStore.CloseFile(fileHandle);
            }
            else
            {
                throw new AccessViolationException($"Not able to connect file {path}, error: {fileConnectStatus}({fileConnectFileStatus})");
            }
            var fileStoreDisconnectStatus = fileStore.Disconnect();
        }

        public void CreateFile(SMBPath path, string content)
        {
            using (var stream = new MemoryStream())
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(content);
                writer.Flush();
                stream.Position = 0;

                CreateFile(path, stream);
            }
        }

        public void CreateFile(SMBPath path, byte[] content)
        {
            using (var stream = new MemoryStream(content))
            {
                stream.Position = 0;
                CreateFile(path, stream);
            }
        }

        public void DeleteFile(SMBPath path)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            else
            {
                if (Exists(path))
                {
                    var fileStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
                    if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
                    {
                        throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
                    }

                    var targetFilePath = path.Path;

                    if (client is SMB1Client)
                    {
                        targetFilePath = $"{targetFilePath}\\";
                    }

                    var fileConnectStatus = fileStore.CreateFile(out var fileHandle
                        , out var fileConnectFileStatus
                        , targetFilePath
                        , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.DELETE | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.None
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null);

                    if (fileHandle == null)
                    {
                        fileStore.Disconnect();
                        throw new AccessViolationException($"Not able to connect file {path}, error:{fileConnectStatus}({fileConnectFileStatus})");
                    }
                    else
                    {
                        FileDispositionInformation dispositionInformation = new FileDispositionInformation();
                        dispositionInformation.DeletePending = true;
                        var setFileInformationStatus = fileStore.SetFileInformation(fileHandle, dispositionInformation);
                        bool deleteSucceeded = (setFileInformationStatus == NTStatus.STATUS_SUCCESS);
                        if (deleteSucceeded == false) throw new AccessViolationException($"Not able to delete file {path}, error:{setFileInformationStatus}");

                        fileStore.CloseFile(fileHandle);
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
                throw new ArgumentException($"{nameof(to)} file {to} is already exist");
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

                    var fileConnectStatus = fileStore.CreateFile(out var fileHandle
                        , out var fileConnectFileStatus
                        , targetFolder
                        , SMBLibrary.AccessMask.GENERIC_WRITE | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.None
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null);

                    if (fileHandle == null)
                    {
                        fileStore.Disconnect();
                        throw new AccessViolationException($"Not able to connect file {from}, error:{fileConnectStatus}({fileConnectFileStatus})");
                    }
                    else
                    {
                        var directoryHnadle = new SMBDirectory(this.client);
                        var (toParentPathParsed, toParentPath, _) = to.GetRelative("..");
                        directoryHnadle.CreateDirectory(toParentPath);

                        NTStatus? setFileInformationStatus;

                        if (client is SMB1Client)
                        {
                            FileRenameInformationType1 fileRenameInformation = new FileRenameInformationType1();
                            fileRenameInformation.FileName = to.Path;
                            fileRenameInformation.ReplaceIfExists = false;
                            setFileInformationStatus = fileStore.SetFileInformation(fileHandle, fileRenameInformation);
                        }
                        else
                        {
                            FileRenameInformationType2 fileRenameInformation = new FileRenameInformationType2();
                            fileRenameInformation.FileName = to.Path;
                            fileRenameInformation.ReplaceIfExists = false;
                            setFileInformationStatus = fileStore.SetFileInformation(fileHandle, fileRenameInformation);
                        }

                        fileStore.CloseFile(fileHandle);
                        fileStore.Disconnect();

                        if (setFileInformationStatus == NTStatus.STATUS_SUCCESS) // renameSucceeded
                        { }
                        else
                        {
                            throw new AccessViolationException($"Move operation from {from} to {to} is failed, error:{setFileInformationStatus}");
                        }
                    }
                }
                else throw new ArgumentException($"{nameof(from)} file {from} is not exist");
            }
        }

        public bool Exists(SMBPath path)
        {
            try
            {
                DoSomethingAfterFileConnect(path, null, out var isFileConnected);
                return isFileConnected;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public FileInformation GetInfo(SMBPath path)
        {
            return DoSomethingAfterFileConnect(path, func: (fileStore, fileHandle) =>
            {
                var basicInfo = getInfo<FileBasicInformation>(path, fileStore, fileHandle, SMBLibrary.FileInformationClass.FileBasicInformation);
                var stdInfo = getInfo<FileStandardInformation>(path, fileStore, fileHandle, SMBLibrary.FileInformationClass.FileStandardInformation);
                return FileInformation.ParseFrom(basicInfo, stdInfo);
            }, out var isFileConnected);
        }

        public void SetInfo(SMBPath path, Action<SetInfoModel> infoSetter)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            if (infoSetter == null) throw new ArgumentNullException(nameof(infoSetter));

            var fileStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
            if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
            {
                throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
            }

            var fileConnectStatus = fileStore.CreateFile(out var fileHandle
                , out var fileConnectFileStatus
                , path.Path
                , AccessMask.GENERIC_READ | AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE
                , FileAttributes.Normal
                , ShareAccess.Read
                , CreateDisposition.FILE_OPEN
                , CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                , null);

            if (fileConnectStatus == NTStatus.STATUS_SUCCESS)
            {
                var basicInfo = getInfo<FileBasicInformation>(path, fileStore, fileHandle, SMBLibrary.FileInformationClass.FileBasicInformation);
                var setInfoModel = SetInfoModel.ParseFrom(basicInfo);
                infoSetter(setInfoModel);
                var renderedBasicInfo = setInfoModel.RenderBack(basicInfo);
                fileStore.SetFileInformation(fileHandle, renderedBasicInfo);
            }
            else
            {
                throw new AccessViolationException($"Not able to connect file {path}, error: {fileConnectStatus}({fileConnectFileStatus})");
            }

            var fileCloseStatus = fileStore.CloseFile(fileHandle);
            var fileStoreDisconnectStatus = fileStore.Disconnect();
        }

        private T getInfo<T>(SMBPath path, ISMBFileStore fileStore, object fileHandle, SMBLibrary.FileInformationClass queryInfoClass) where T : SMBLibrary.FileInformation
        {
            var getFileInformationStatus = fileStore.GetFileInformation(out var fileInformation, fileHandle, queryInfoClass);
            if (getFileInformationStatus != NTStatus.STATUS_SUCCESS) throw new AccessViolationException($"Not able to get {queryInfoClass} of file {path}, error:{getFileInformationStatus}");
            if (fileInformation == null) throw new AccessViolationException($"Not able to get {queryInfoClass} of file {path}, error:NULL_RESULT");
            if (fileInformation is T info)
            {
                return info;
            }
            else throw new NotSupportedException($"Not able to get {queryInfoClass} of file {path}, error:NOT_SUPPORT_RESULT_TYPE({fileInformation.GetType().FullName})");
        }

        internal MemoryStream OpenRead(SMBPath path, long offset = 0, long? length = null)
        {
            var result = new MemoryStream();
            OpenRead(result, path, offset, length);
            result.Position = 0;
            return result;
        }

        public void OpenRead(Stream stream, SMBPath path, long offset = 0, long? length = null)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            else
            {
                if (Exists(path))
                {
                    var fileStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
                    if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
                    {
                        throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
                    }

                    var targetFilePath = path.Path;

                    if (client is SMB1Client)
                    {
                        targetFilePath = $"{targetFilePath}\\";
                    }

                    var fileConnectStatus = fileStore.CreateFile(out var fileHandle
                        , out var fileConnectFileStatus
                        , targetFilePath
                        , SMBLibrary.AccessMask.GENERIC_READ | SMBLibrary.AccessMask.SYNCHRONIZE
                        , SMBLibrary.FileAttributes.Normal
                        , SMBLibrary.ShareAccess.Read | ShareAccess.Write
                        , SMBLibrary.CreateDisposition.FILE_OPEN
                        , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                        , null);

                    if (fileHandle == null)
                    {
                        fileStore.Disconnect();
                        throw new AccessViolationException($"Not able to connect file {path}, error:{fileConnectStatus}({fileConnectFileStatus})");
                    }
                    else
                    {
                        byte[] data;
                        long bytesRead = offset;
                        while (true)
                        {
                            var readLength = (int)client.MaxReadSize;
                            if (length.HasValue)
                            {
                                var remainLength = length.Value - (bytesRead - offset);
                                if (remainLength < readLength) readLength = (int)remainLength;
                            }

                            var readFileStatus = fileStore.ReadFile(out data, fileHandle, bytesRead, readLength);
                            if (readFileStatus != NTStatus.STATUS_SUCCESS && readFileStatus != NTStatus.STATUS_END_OF_FILE)
                            {
                                throw new AccessViolationException($"Failed to read from file {path}, error:{readFileStatus}");
                            }

                            if (readFileStatus == NTStatus.STATUS_END_OF_FILE || data.Length == 0)
                            {
                                break;
                            }
                            bytesRead += data.Length;
                            stream.Write(data, 0, data.Length);

                            if (length.HasValue && bytesRead >= length.Value)
                            {
                                break;
                            }
                        }

                        fileStore.CloseFile(fileHandle);
                        fileStore.Disconnect();
                    }
                }
                else throw new FileNotFoundException($"{path}");
            }
        }

        public byte[] ReadAllBytes(SMBPath path, int offset = 0, long? length = null)
        {
            using (var stream = OpenRead(path, offset, length))
            {
                stream.Position = 0;
                return stream.ToArray();
            }
        }

        public string ReadAllText(SMBPath path, int offset = 0, long? length = null)
        {
            using (var stream = OpenRead(path, offset, length))
            using (var streamReader = new StreamReader(stream))
            {
                return streamReader.ReadToEnd();
            }
        }

        public IEnumerable<string> ReadAllLines(SMBPath path, int offset = 0, long? length = null)
        {
            using (var stream = OpenRead(path, offset, length))
            using (var streamReader = new StreamReader(stream))
            {
                while (streamReader.Peek() >= 0)
                {
                    yield return streamReader.ReadLine();
                }
            }
        }

        private void DoSomethingAfterFileConnect(SMBPath path, Action<ISMBFileStore, object> action, out bool isFileConnected)
        {
            DoSomethingAfterFileConnect<object>(path, func: null, out isFileConnected);
        }

        private T DoSomethingAfterFileConnect<T>(SMBPath path, Func<ISMBFileStore, object, T> func, out bool isFileConnected)
        {
            if (path == null)
            {
                isFileConnected = false;
                throw new ArgumentNullException(nameof(path));
            }
            else
            {
                var fileStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
                if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
                {
                    isFileConnected = false;
                    throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
                }

                var targetFilePath = path.Path;

                if (client is SMB1Client)
                {
                    targetFilePath = $"{targetFilePath}\\";
                }

                var fileConnectStatus = fileStore.CreateFile(out var fileHandle
                    , out var fileConnectFileStatus
                    , targetFilePath
                    , SMBLibrary.AccessMask.GENERIC_READ
                    , SMBLibrary.FileAttributes.Directory
                    , SMBLibrary.ShareAccess.Read | SMBLibrary.ShareAccess.Write
                    , SMBLibrary.CreateDisposition.FILE_OPEN
                    , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE
                    , null);

                if (fileHandle == null)
                {
                    isFileConnected = false;
                    fileStore.Disconnect();
                    throw new AccessViolationException($"Not able to connect file {path}, error:{fileConnectStatus}({fileConnectFileStatus})");
                }
                else
                {
                    isFileConnected = true;

                    T result = default;
                    if (func != null) result = func(fileStore, fileHandle);

                    fileStore.CloseFile(fileHandle);
                    fileStore.Disconnect();
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
