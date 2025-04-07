using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    /// <summary>
    /// A file store (a.k.a. object store) interface to allow access to a file system or a named pipe in an NT-like manner dictated by the SMB protocol.
    /// </summary>
    public interface INTAsyncFileStore
    {
        Task<Result<CreateFileResponse>> CreateFile(string path
            , AccessMask desiredAccess
            , FileAttributes fileAttributes
            , ShareAccess shareAccess
            , CreateDisposition createDisposition
            , CreateOptions createOptions
            , SecurityContext securityContext
            , CancellationToken cancellationToken = default);

        Task<Result.NTStatus> CloseFile(object handle, CancellationToken cancellationToken = default);

        Task<Result<ReadFileResponse>> ReadFile(object handle, long offset, int maxCount, CancellationToken cancellationToken = default);

        Task<Result<int>> WriteFile(object handle, long offset, byte[] data, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> FlushFileBuffers(object handle, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> LockFile(object handle, long byteOffset, long length, bool exclusiveLock, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> UnlockFile(object handle, long byteOffset, long length, CancellationToken cancellationToken = default);

        Task<Result<List<QueryDirectoryFileInformation>>> QueryDirectory(object handle, string fileName, FileInformationClass informationClass, CancellationToken cancellationToken = default);

        Task<Result<FileInformation>> GetFileInformation(object handle, FileInformationClass informationClass, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> SetFileInformation(object handle, FileInformation information, CancellationToken cancellationToken = default);

        Task<Result<FileSystemInformation>> GetFileSystemInformation(FileSystemInformationClass informationClass, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> SetFileSystemInformation(FileSystemInformation information, CancellationToken cancellationToken = default);

        Task<Result<SecurityDescriptor>> GetSecurityInformation(object handle, SecurityInformation securityInformation, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor, CancellationToken cancellationToken = default);

        /// <summary>
        /// Monitor the contents of a directory (and its subdirectories) by using change notifications.
        /// When something changes within the directory being watched this operation is completed.
        /// </summary>
        /// <returns>
        /// STATUS_PENDING - The directory is being watched, change notification will be provided using callback method.
        /// STATUS_NOT_SUPPORTED - The underlying object store does not support change notifications.
        /// STATUS_INVALID_HANDLE - The handle supplied is invalid.
        /// </returns>
        Task<Result<object>> NotifyChange(object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context, CancellationToken cancellationToken = default);

        Task<Result.NTStatus> Cancel(object ioRequest, CancellationToken cancellationToken = default);

        Task<Result<byte[]>> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength, CancellationToken cancellationToken = default);
    }

    public interface ISMBAsyncFileStore : INTAsyncFileStore
    {
        Task<Result.NTStatus> Disconnect(CancellationToken cancellationToken = default);

        uint MaxReadSize
        {
            get;
        }

        uint MaxWriteSize
        {
            get;
        }

    }

    public class CreateFileResponse
    {
        public object Handle { get; internal set; } = null;
        public NTStatus ReplyHeaderStatus { get; internal set; }
        public FileStatus FileStatus { get; internal set; } = FileStatus.FILE_DOES_NOT_EXIST;
    }

    public class ReadFileResponse
    {
        public byte[] Data { get; internal set; }
        public NTStatus ReplyHeaderStatus { get; internal set; }
    }

    public class ErrorResponseException : Exception
    {
        public readonly NTStatus ReplyHeaderStatus;

        public ErrorResponseException(NTStatus replyHeaderStatus)
        {
            ReplyHeaderStatus = replyHeaderStatus;
        }
    }
}
