using SMBLibrary.SMB2;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public class SMB2AsyncFileStore : ISMBAsyncFileStore
    {
        private const int BytesPerCredit = 65536;

        private SMB2AsyncClient m_client;
        private uint m_treeID;
        private bool m_encryptShareData;

        public SMB2AsyncFileStore(SMB2AsyncClient client, uint treeID, bool encryptShareData)
        {
            m_client = client;
            m_treeID = treeID;
            m_encryptShareData = encryptShareData;
        }

        public async Task<Result<CreateFileResponse>> CreateFile(string path
            , AccessMask desiredAccess
            , FileAttributes fileAttributes
            , ShareAccess shareAccess
            , CreateDisposition createDisposition
            , CreateOptions createOptions
            , SecurityContext securityContext
            , CancellationToken cancellationToken = default)
        {
            CreateRequest request = new CreateRequest();
            request.Name = path;
            request.DesiredAccess = desiredAccess;
            request.FileAttributes = fileAttributes;
            request.ShareAccess = shareAccess;
            request.CreateDisposition = createDisposition;
            request.CreateOptions = createOptions;
            request.ImpersonationLevel = ImpersonationLevel.Impersonation;

            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is CreateResponse)
                {
                    CreateResponse createResponse = ((CreateResponse)response);
                    return new CreateFileResponse
                    {
                        Handle = createResponse.FileId,
                        ReplyHeaderStatus = NTStatus.STATUS_SUCCESS,
                        FileStatus = ToFileStatus(createResponse.CreateAction)
                    };
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public async Task<Result.NTStatus> CloseFile(object handle, CancellationToken cancellationToken = default)
        {
            CloseRequest request = new CloseRequest();
            request.FileId = (FileID)handle;
            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                // TODO: Check is NTStatus.STATUS_SUCCESS
                return response.Header.Status;
            }
            else return error;
        }

        public async Task<Result<ReadFileResponse>> ReadFile(object handle, long offset, int maxCount, CancellationToken cancellationToken = default)
        {
            ReadRequest request = new ReadRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxCount / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.ReadLength = (uint)maxCount;

            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse)
                {
                    return new ReadFileResponse()
                    {
                        ReplyHeaderStatus = NTStatus.STATUS_SUCCESS,
                        Data = ((ReadResponse)response).Data
                    };
                }
                else if (response.Header.Status == NTStatus.STATUS_END_OF_FILE)
                {
                    return new ReadFileResponse()
                    {
                        ReplyHeaderStatus = NTStatus.STATUS_END_OF_FILE,
                        Data = new byte[0]
                    };
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public async Task<Result<int>> WriteFile(object handle, long offset, byte[] data, CancellationToken cancellationToken = default)
        {
            WriteRequest request = new WriteRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)data.Length / BytesPerCredit);
            request.FileId = (FileID)handle;
            request.Offset = (ulong)offset;
            request.Data = data;

            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse)
                {
                    return (int)((WriteResponse)response).Count;
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public async Task<Result.NTStatus> FlushFileBuffers(object handle, CancellationToken cancellationToken = default)
        {
            FlushRequest request = new FlushRequest();
            request.FileId = (FileID)handle;

            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is FlushResponse)
                {
                    return NTStatus.STATUS_SUCCESS;
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public Task<Result.NTStatus> LockFile(object handle, long byteOffset, long length, bool exclusiveLock, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new NotImplementedException());
        }

        public Task<Result.NTStatus> UnlockFile(object handle, long byteOffset, long length, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new NotImplementedException());
        }

        public async Task<Result<List<QueryDirectoryFileInformation>>> QueryDirectory(object handle, string fileName, FileInformationClass informationClass, CancellationToken cancellationToken = default)
        {
            QueryDirectoryRequest request = new QueryDirectoryRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)m_client.MaxTransactSize / BytesPerCredit);
            request.FileInformationClass = informationClass;
            request.Reopen = true;
            request.FileId = (FileID)handle;
            request.OutputBufferLength = m_client.MaxTransactSize;
            request.FileName = fileName;

            var result = new List<QueryDirectoryFileInformation>();
            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                while (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryDirectoryResponse)
                {
                    List<QueryDirectoryFileInformation> page = ((QueryDirectoryResponse)response).GetFileInformationList(informationClass);
                    result.AddRange(page);
                    request.Reopen = false;
                    (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
                    if (response == null)
                    {
                        return error;
                    }
                }

                // TODO: Need to check response.Header.Status & type NTStatus.STATUS_NO_MORE_FILES, NTStatus.STATUS_NO_SUCH_FILE
                return result;
            }
            else return error;
        }

        public async Task<Result<FileInformation>> GetFileInformation(object handle, FileInformationClass informationClass, CancellationToken cancellationToken = default)
        {
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    return ((QueryInfoResponse)response).GetFileInformation(informationClass);
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public async Task<Result.NTStatus> SetFileInformation(object handle, FileInformation information, CancellationToken cancellationToken = default)
        {
            SetInfoRequest request = new SetInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = information.FileInformationClass;
            request.FileId = (FileID)handle;
            request.SetFileInformation(information);

            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                // TODO: Check is NTStatus.STATUS_SUCCESS
                return response.Header.Status;
            }
            else return error;
        }

        public async Task<Result<FileSystemInformation>> GetFileSystemInformation(FileSystemInformationClass informationClass, CancellationToken cancellationToken = default)
        {
            var createFileResponse = await CreateFile(String.Empty, (AccessMask)DirectoryAccessMask.FILE_LIST_DIRECTORY | (AccessMask)DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0, ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null, cancellationToken).ConfigureAwait(false);
            if (createFileResponse.IsSuccess == false)
            {
                return createFileResponse.Error;
            }

            var getFileSystemInformationResponse = await GetFileSystemInformation(createFileResponse.Value.Handle, informationClass, cancellationToken).ConfigureAwait(false);
            await CloseFile(createFileResponse.Value.Handle, cancellationToken).ConfigureAwait(false);

            if (getFileSystemInformationResponse.IsSuccess) return getFileSystemInformationResponse.Value;
            else return getFileSystemInformationResponse.Error;

        }

        public async Task<Result<FileSystemInformation>> GetFileSystemInformation(object handle, FileSystemInformationClass informationClass, CancellationToken cancellationToken = default)
        {
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.FileSystem;
            request.FileSystemInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    return ((QueryInfoResponse)response).GetFileSystemInformation(informationClass);
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public Task<Result.NTStatus> SetFileSystemInformation(FileSystemInformation information, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new NotImplementedException());
        }

        public async Task<Result<SecurityDescriptor>> GetSecurityInformation(object handle, SecurityInformation securityInformation, CancellationToken cancellationToken = default)
        {
            QueryInfoRequest request = new QueryInfoRequest();
            request.InfoType = InfoType.Security;
            request.SecurityInformation = securityInformation;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID)handle;

            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                {
                    return ((QueryInfoResponse)response).GetSecurityInformation();
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public Task<Result.NTStatus> SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new ErrorResponseException(NTStatus.STATUS_NOT_SUPPORTED));
        }

        public Task<Result<object>> NotifyChange(object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result<object>>(new NotImplementedException());
        }

        public Task<Result.NTStatus> Cancel(object ioRequest, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new NotImplementedException());
        }

        public async Task<Result<byte[]>> DeviceIOControl(object handle, uint ctlCode, byte[] input, int maxOutputLength, CancellationToken cancellationToken = default)
        {
            IOCtlRequest request = new IOCtlRequest();
            request.Header.CreditCharge = (ushort)Math.Ceiling((double)maxOutputLength / BytesPerCredit);
            request.CtlCode = ctlCode;
            request.IsFSCtl = true;
            request.FileId = (FileID)handle;
            request.Input = input;
            request.MaxOutputResponse = (uint)maxOutputLength;
            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                if ((response.Header.Status == NTStatus.STATUS_SUCCESS || response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) && response is IOCtlResponse)
                {
                    return ((IOCtlResponse)response).Output;
                }
                else return new ErrorResponseException(response.Header.Status);
            }
            else return error;
        }

        public async Task<Result.NTStatus> Disconnect(CancellationToken cancellationToken = default)
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            var (isSuccess, response, error) = await TrySendCommand(request, cancellationToken).ConfigureAwait(false);
            if (response != null)
            {
                // TODO: Check is NTStatus.STATUS_SUCCESS
                return response.Header.Status;
            }
            else return error;
        }

        private async Task<Result<SMB2Command>> TrySendCommand(SMB2Command request, CancellationToken cancellationToken = default)
        {
            request.Header.TreeID = m_treeID;
            if (!m_client.IsConnected)
            {
                return new InvalidOperationException("The client is no longer connected");
            }
            return await m_client.TrySendCommand(request, m_encryptShareData, cancellationToken).ConfigureAwait(false);
        }

        public uint MaxReadSize
        {
            get
            {
                return m_client.MaxReadSize;
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                return m_client.MaxWriteSize;
            }
        }

        private static FileStatus ToFileStatus(CreateAction createAction)
        {
            switch (createAction)
            {
                case CreateAction.FILE_SUPERSEDED:
                    return FileStatus.FILE_SUPERSEDED;
                case CreateAction.FILE_OPENED:
                    return FileStatus.FILE_OPENED;
                case CreateAction.FILE_CREATED:
                    return FileStatus.FILE_CREATED;
                case CreateAction.FILE_OVERWRITTEN:
                    return FileStatus.FILE_OVERWRITTEN;
                default:
                    return FileStatus.FILE_OPENED;
            }
        }
    }
}
