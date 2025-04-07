using SMBLibrary.SMB1;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public class SMB1AsyncFileStore : ISMBAsyncFileStore
    {
        private SMB1AsyncClient m_client;
        private ushort m_treeID;

        public SMB1AsyncFileStore(SMB1AsyncClient client, ushort treeID)
        {
            m_client = client;
            m_treeID = treeID;
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
            NTCreateAndXRequest request = new NTCreateAndXRequest();
            request.FileName = path;
            request.DesiredAccess = desiredAccess;
            request.ExtFileAttributes = ToExtendedFileAttributes(fileAttributes);
            request.ShareAccess = shareAccess;
            request.CreateDisposition = createDisposition;
            request.CreateOptions = createOptions;
            request.ImpersonationLevel = ImpersonationLevel.Impersonation;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_NT_CREATE_ANDX, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Commands[0] is NTCreateAndXResponse)
                {
                    NTCreateAndXResponse response = reply.Commands[0] as NTCreateAndXResponse;
                    return new CreateFileResponse
                    {
                        Handle = response.FID,
                        ReplyHeaderStatus = reply.Header.Status,
                        FileStatus = ToFileStatus(response.CreateDisposition),
                    };
                }
                else if (reply.Commands[0] is ErrorResponse)
                {
                    return new ErrorResponseException(reply.Header.Status);
                }
            }
            return error;
        }

        public async Task<Result.NTStatus> CloseFile(object handle, CancellationToken cancellationToken = default)
        {
            CloseRequest request = new CloseRequest();
            request.FID = (ushort)handle;
            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_CLOSE, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                // TODO: Check is NTStatus.STATUS_SUCCESS
                return reply.Header.Status;
            }
            return error;
        }

        public async Task<Result<ReadFileResponse>> ReadFile(object handle, long offset, int maxCount, CancellationToken cancellationToken = default)
        {
            ReadAndXRequest request = new ReadAndXRequest();
            request.FID = (ushort)handle;
            request.Offset = (ulong)offset;
            request.MaxCountLarge = (uint)maxCount;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_READ_ANDX, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is ReadAndXResponse)
                {
                    return new ReadFileResponse()
                    {
                        ReplyHeaderStatus = NTStatus.STATUS_SUCCESS,
                        Data = ((ReadAndXResponse)reply.Commands[0]).Data
                    };
                }
                else if (reply.Header.Status == NTStatus.STATUS_END_OF_FILE)
                {
                    return new ReadFileResponse()
                    {
                        ReplyHeaderStatus = NTStatus.STATUS_END_OF_FILE,
                        Data = new byte[0]
                    };
                }
                else return new ErrorResponseException(reply.Header.Status);
            }
            return error;
        }

        public async Task<Result<int>> WriteFile(object handle, long offset, byte[] data, CancellationToken cancellationToken = default)
        {
            WriteAndXRequest request = new WriteAndXRequest();
            request.FID = (ushort)handle;
            request.Offset = (ulong)offset;
            request.Data = data;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_WRITE_ANDX, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is WriteAndXResponse)
                {
                    return (int)((WriteAndXResponse)reply.Commands[0]).Count;
                }
                else return new ErrorResponseException(reply.Header.Status);
            }
            return error;
        }

        public Task<Result.NTStatus> FlushFileBuffers(object handle, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new NotImplementedException());
        }

        public Task<Result.NTStatus> LockFile(object handle, long byteOffset, long length, bool exclusiveLock, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new NotImplementedException());
        }

        public Task<Result.NTStatus> UnlockFile(object handle, long byteOffset, long length, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new NotImplementedException());
        }

        public Task<Result<List<QueryDirectoryFileInformation>>> QueryDirectory(object handle, string fileName, FileInformationClass informationClass, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result<List<QueryDirectoryFileInformation>>>(new NotImplementedException());
        }

        public async Task<Result<List<FindInformation>>> QueryDirectory(string fileName, FindInformationLevel informationLevel, CancellationToken cancellationToken = default)
        {
            int maxOutputLength = 4096;
            Transaction2FindFirst2Request subcommand = new Transaction2FindFirst2Request();
            subcommand.SearchAttributes = SMBFileAttributes.Hidden | SMBFileAttributes.System | SMBFileAttributes.Directory;
            subcommand.SearchCount = UInt16.MaxValue;
            subcommand.Flags = FindFlags.SMB_FIND_CLOSE_AT_EOS;
            subcommand.InformationLevel = informationLevel;
            subcommand.FileName = fileName;

            Transaction2Request request = new Transaction2Request();
            request.Setup = subcommand.GetSetup();
            request.TransParameters = subcommand.GetParameters(m_client.Unicode);
            request.TransData = subcommand.GetData(m_client.Unicode);
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = Transaction2FindFirst2Response.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION2, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
                {
                    var result = new List<FindInformation>();
                    Transaction2Response response = (Transaction2Response)reply.Commands[0];
                    Transaction2FindFirst2Response subcommandResponse = new Transaction2FindFirst2Response(response.TransParameters, response.TransData, reply.Header.UnicodeFlag);
                    FindInformationList findInformationList = subcommandResponse.GetFindInformationList(subcommand.InformationLevel, reply.Header.UnicodeFlag);
                    result.AddRange(findInformationList);
                    bool endOfSearch = subcommandResponse.EndOfSearch;
                    while (!endOfSearch)
                    {
                        Transaction2FindNext2Request nextSubcommand = new Transaction2FindNext2Request();
                        nextSubcommand.SID = subcommandResponse.SID;
                        nextSubcommand.SearchCount = UInt16.MaxValue;
                        nextSubcommand.Flags = FindFlags.SMB_FIND_CLOSE_AT_EOS | FindFlags.SMB_FIND_CONTINUE_FROM_LAST;
                        nextSubcommand.InformationLevel = informationLevel;
                        nextSubcommand.FileName = fileName;

                        request = new Transaction2Request();
                        request.Setup = nextSubcommand.GetSetup();
                        request.TransParameters = nextSubcommand.GetParameters(m_client.Unicode);
                        request.TransData = nextSubcommand.GetData(m_client.Unicode);
                        request.TotalDataCount = (ushort)request.TransData.Length;
                        request.TotalParameterCount = (ushort)request.TransParameters.Length;
                        request.MaxParameterCount = Transaction2FindNext2Response.ParametersLength;
                        request.MaxDataCount = (ushort)maxOutputLength;

                        (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION2, cancellationToken).ConfigureAwait(false);
                        if (reply == null)
                        {
                            return error;
                        }
                        else if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
                        {
                            response = (Transaction2Response)reply.Commands[0];
                            Transaction2FindNext2Response nextSubcommandResponse = new Transaction2FindNext2Response(response.TransParameters, response.TransData, reply.Header.UnicodeFlag);
                            findInformationList = nextSubcommandResponse.GetFindInformationList(subcommand.InformationLevel, reply.Header.UnicodeFlag);
                            result.AddRange(findInformationList);
                            endOfSearch = nextSubcommandResponse.EndOfSearch;
                        }
                        else
                        {
                            endOfSearch = true;
                        }
                    }

                    return result;
                }
                else return new ErrorResponseException(reply.Header.Status);
            }
            else return error;
        }

        public async Task<Result<FileInformation>> GetFileInformation(object handle, FileInformationClass informationClass, CancellationToken cancellationToken = default)
        {
            if (m_client.InfoLevelPassthrough)
            {
                int maxOutputLength = 4096;
                Transaction2QueryFileInformationRequest subcommand = new Transaction2QueryFileInformationRequest();
                subcommand.FID = (ushort)handle;
                subcommand.FileInformationClass = informationClass;

                Transaction2Request request = new Transaction2Request();
                request.Setup = subcommand.GetSetup();
                request.TransParameters = subcommand.GetParameters(m_client.Unicode);
                request.TransData = subcommand.GetData(m_client.Unicode);
                request.TotalDataCount = (ushort)request.TransData.Length;
                request.TotalParameterCount = (ushort)request.TransParameters.Length;
                request.MaxParameterCount = Transaction2QueryFileInformationResponse.ParametersLength;
                request.MaxDataCount = (ushort)maxOutputLength;

                var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION2, cancellationToken).ConfigureAwait(false);
                if (reply != null)
                {
                    if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
                    {
                        Transaction2Response response = (Transaction2Response)reply.Commands[0];
                        Transaction2QueryFileInformationResponse subcommandResponse = new Transaction2QueryFileInformationResponse(response.TransParameters, response.TransData, reply.Header.UnicodeFlag);
                        if (informationClass == FileInformationClass.FileAllInformation)
                        {
                            // Windows implementations return SMB_QUERY_FILE_ALL_INFO when a client specifies native NT passthrough level "FileAllInformation".
                            QueryInformation queryFileAllInfo = subcommandResponse.GetQueryInformation(QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO);
                            return QueryInformationHelper.ToFileInformation(queryFileAllInfo);
                        }
                        else
                        {
                            return subcommandResponse.GetFileInformation(informationClass);
                        }
                    }
                    else return new ErrorResponseException(reply.Header.Status);
                }
                else return error;
            }
            else
            {
                QueryInformationLevel informationLevel = QueryInformationHelper.ToFileInformationLevel(informationClass);
                var (isSuccess, queryInformation, error) = await GetFileInformation(handle, informationLevel, cancellationToken).ConfigureAwait(false);
                if (queryInformation != null)
                {
                    return QueryInformationHelper.ToFileInformation(queryInformation);
                }
                else return error;
            }
        }

        public async Task<Result<QueryInformation>> GetFileInformation(object handle, QueryInformationLevel informationLevel, CancellationToken cancellationToken = default)
        {
            int maxOutputLength = 4096;
            Transaction2QueryFileInformationRequest subcommand = new Transaction2QueryFileInformationRequest();
            subcommand.FID = (ushort)handle;
            subcommand.QueryInformationLevel = informationLevel;

            Transaction2Request request = new Transaction2Request();
            request.Setup = subcommand.GetSetup();
            request.TransParameters = subcommand.GetParameters(m_client.Unicode);
            request.TransData = subcommand.GetData(m_client.Unicode);
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = Transaction2QueryFileInformationResponse.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION2, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
                {
                    Transaction2Response response = (Transaction2Response)reply.Commands[0];
                    Transaction2QueryFileInformationResponse subcommandResponse = new Transaction2QueryFileInformationResponse(response.TransParameters, response.TransData, reply.Header.UnicodeFlag);
                    return subcommandResponse.GetQueryInformation(informationLevel);
                }
                else return new ErrorResponseException(reply.Header.Status);
            }
            else return error;
        }

        public async Task<Result.NTStatus> SetFileInformation(object handle, FileInformation information, CancellationToken cancellationToken = default)
        {
            if (m_client.InfoLevelPassthrough)
            {
	            if (information is FileRenameInformationType2)
	            {
	                FileRenameInformationType1 informationType1 = new FileRenameInformationType1();
	                informationType1.FileName = ((FileRenameInformationType2)information).FileName;
	                informationType1.ReplaceIfExists = ((FileRenameInformationType2)information).ReplaceIfExists;
	                informationType1.RootDirectory = (uint)((FileRenameInformationType2)information).RootDirectory;
	                information = informationType1;
	            }
	
	            int maxOutputLength = 4096;
	            Transaction2SetFileInformationRequest subcommand = new Transaction2SetFileInformationRequest();
	            subcommand.FID = (ushort)handle;
	            subcommand.SetInformation(information);
	
	            Transaction2Request request = new Transaction2Request();
	            request.Setup = subcommand.GetSetup();
	            request.TransParameters = subcommand.GetParameters(m_client.Unicode);
	            request.TransData = subcommand.GetData(m_client.Unicode);
	            request.TotalDataCount = (ushort)request.TransData.Length;
	            request.TotalParameterCount = (ushort)request.TransParameters.Length;
	            request.MaxParameterCount = Transaction2SetFileInformationResponse.ParametersLength;
	            request.MaxDataCount = (ushort)maxOutputLength;

                var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION2, cancellationToken).ConfigureAwait(false);
	            if (reply != null)
	            {
                    // TODO: Check is NTStatus.STATUS_SUCCESS
                    return reply.Header.Status;
	            }
                return error;
            }
			else
			{
				return new NotSupportedException("Server does not support InfoLevelPassthrough");
			}
        }

        public async Task<Result.NTStatus> SetFileInformation(object handle, SetInformation information, CancellationToken cancellationToken = default)
        {
            int maxOutputLength = 4096;
            Transaction2SetFileInformationRequest subcommand = new Transaction2SetFileInformationRequest();
            subcommand.FID = (ushort)handle;
            subcommand.SetInformation(information);

            Transaction2Request request = new Transaction2Request();
            request.Setup = subcommand.GetSetup();
            request.TransParameters = subcommand.GetParameters(m_client.Unicode);
            request.TransData = subcommand.GetData(m_client.Unicode);
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = Transaction2SetFileInformationResponse.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION2, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                // TODO: Check is NTStatus.STATUS_SUCCESS
                return reply.Header.Status;
            }
            else return error;
        }

        public async Task<Result<FileSystemInformation>> GetFileSystemInformation(FileSystemInformationClass informationClass, CancellationToken cancellationToken = default)
        {
            if (m_client.InfoLevelPassthrough)
            {
                int maxOutputLength = 4096;
                Transaction2QueryFSInformationRequest subcommand = new Transaction2QueryFSInformationRequest();
                subcommand.FileSystemInformationClass = informationClass;

                Transaction2Request request = new Transaction2Request();
                request.Setup = subcommand.GetSetup();
                request.TransParameters = subcommand.GetParameters(m_client.Unicode);
                request.TransData = subcommand.GetData(m_client.Unicode);
                request.TotalDataCount = (ushort)request.TransData.Length;
                request.TotalParameterCount = (ushort)request.TransParameters.Length;
                request.MaxParameterCount = Transaction2QueryFSInformationResponse.ParametersLength;
                request.MaxDataCount = (ushort)maxOutputLength;

                var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION2, cancellationToken).ConfigureAwait(false);
                if (reply != null)
                {
                    if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
                    {
                        Transaction2Response response = (Transaction2Response)reply.Commands[0];
                        Transaction2QueryFSInformationResponse subcommandResponse = new Transaction2QueryFSInformationResponse(response.TransParameters, response.TransData, reply.Header.UnicodeFlag);
                        return subcommandResponse.GetFileSystemInformation(informationClass);
                    }
                    else return new ErrorResponseException(reply.Header.Status);
                }
                else return error;
            }
            else
            {
                return new NotSupportedException("Server does not support InfoLevelPassthrough");
            }
        }

        public async Task<Result<QueryFSInformation>> GetFileSystemInformation(QueryFSInformationLevel informationLevel, CancellationToken cancellationToken = default)
        {
            int maxOutputLength = 4096;
            Transaction2QueryFSInformationRequest subcommand = new Transaction2QueryFSInformationRequest();
            subcommand.QueryFSInformationLevel = informationLevel;

            Transaction2Request request = new Transaction2Request();
            request.Setup = subcommand.GetSetup();
            request.TransParameters = subcommand.GetParameters(m_client.Unicode);
            request.TransData = subcommand.GetData(m_client.Unicode);
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = Transaction2QueryFSInformationResponse.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION2, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
                {
                    Transaction2Response response = (Transaction2Response)reply.Commands[0];
                    Transaction2QueryFSInformationResponse subcommandResponse = new Transaction2QueryFSInformationResponse(response.TransParameters, response.TransData, reply.Header.UnicodeFlag);
                    return subcommandResponse.GetQueryFSInformation(informationLevel, reply.Header.UnicodeFlag);
                }
                else return new ErrorResponseException(reply.Header.Status);
            }
            else return error;
        }

        public Task<Result.NTStatus> SetFileSystemInformation(FileSystemInformation information, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<Result.NTStatus>(new NotImplementedException());
        }

        public async Task<Result<SecurityDescriptor>> GetSecurityInformation(object handle, SecurityInformation securityInformation, CancellationToken cancellationToken = default)
        {
            int maxOutputLength = 4096;
            NTTransactQuerySecurityDescriptorRequest subcommand = new NTTransactQuerySecurityDescriptorRequest();
            subcommand.FID = (ushort)handle;
            subcommand.SecurityInfoFields = securityInformation;

            NTTransactRequest request = new NTTransactRequest();
            request.Function = subcommand.SubcommandName;
            request.Setup = subcommand.GetSetup();
            request.TransParameters = subcommand.GetParameters(m_client.Unicode);
            request.TransData = subcommand.GetData();
            request.TotalDataCount = (uint)request.TransData.Length;
            request.TotalParameterCount = (uint)request.TransParameters.Length;
            request.MaxParameterCount = NTTransactQuerySecurityDescriptorResponse.ParametersLength;
            request.MaxDataCount = (uint)maxOutputLength;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_NT_TRANSACT, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is NTTransactResponse)
                {
                    NTTransactResponse response = (NTTransactResponse)reply.Commands[0];
                    NTTransactQuerySecurityDescriptorResponse subcommandResponse = new NTTransactQuerySecurityDescriptorResponse(response.TransParameters, response.TransData);
                    return subcommandResponse.SecurityDescriptor;
                }
                else return new ErrorResponseException(reply.Header.Status);
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
            if ((IoControlCode)ctlCode == IoControlCode.FSCTL_PIPE_TRANSCEIVE)
            {
                return await FsCtlPipeTranscieve(handle, input, maxOutputLength, cancellationToken).ConfigureAwait(false);
            }

            NTTransactIOCTLRequest subcommand = new NTTransactIOCTLRequest();
            subcommand.FID = (ushort)handle;
            subcommand.FunctionCode = ctlCode;
            subcommand.IsFsctl = true;
            subcommand.Data = input;

            NTTransactRequest request = new NTTransactRequest();
            request.Function = subcommand.SubcommandName;
            request.Setup = subcommand.GetSetup();
            request.TransParameters = subcommand.GetParameters(m_client.Unicode);
            request.TransData = subcommand.GetData();
            request.TotalDataCount = (uint)request.TransData.Length;
            request.TotalParameterCount = (uint)request.TransParameters.Length;
            request.MaxParameterCount = NTTransactIOCTLResponse.ParametersLength;
            request.MaxDataCount = (uint)maxOutputLength;

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_NT_TRANSACT, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is NTTransactResponse)
                {
                    NTTransactResponse response = (NTTransactResponse)reply.Commands[0];
                    NTTransactIOCTLResponse subcommandResponse = new NTTransactIOCTLResponse(response.Setup, response.TransData);
                    return subcommandResponse.Data;
                }
                else return new ErrorResponseException(reply.Header.Status);
            }
            else return error;
        }

        public async Task<Result<byte[]>> FsCtlPipeTranscieve(object handle, byte[] input, int maxOutputLength, CancellationToken cancellationToken = default)
        {
            TransactionTransactNamedPipeRequest subcommand = new TransactionTransactNamedPipeRequest();
            subcommand.FID = (ushort)handle;
            subcommand.WriteData = input;

            TransactionRequest request = new TransactionRequest();
            request.Setup = subcommand.GetSetup();
            request.TransParameters = subcommand.GetParameters();
            request.TransData = subcommand.GetData(m_client.Unicode);
            request.TotalDataCount = (ushort)request.TransData.Length;
            request.TotalParameterCount = (ushort)request.TransParameters.Length;
            request.MaxParameterCount = TransactionTransactNamedPipeResponse.ParametersLength;
            request.MaxDataCount = (ushort)maxOutputLength;
            request.Name = @"\PIPE\";

            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TRANSACTION, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is TransactionResponse)
                {
                    TransactionResponse response = (TransactionResponse)reply.Commands[0];
                    TransactionTransactNamedPipeResponse subcommandResponse = new TransactionTransactNamedPipeResponse(response.TransData);
                    return subcommandResponse.ReadData;
                }
                else return new ErrorResponseException(reply.Header.Status);
            }
            else return error;
        }

        public async Task<Result.NTStatus> Disconnect(CancellationToken cancellationToken = default)
        {
            TreeDisconnectRequest request = new TreeDisconnectRequest();
            var (isSuccess, reply, error) = await TrySendMessage(request, CommandName.SMB_COM_TREE_DISCONNECT, cancellationToken).ConfigureAwait(false);
            if (reply != null)
            {
                // TODO: Check is NTStatus.STATUS_SUCCESS
                return reply.Header.Status;
            }
            else return error;
        }

        private async Task<Result<SMB1Message>> TrySendMessage(SMB1Command request, CommandName waitForRespnseCommandName, CancellationToken cancellationToken = default)
        {
            if (!m_client.IsConnected)
            {
                return new InvalidOperationException("The client is no longer connected");
            }
            return await m_client.TrySendMessage(request, m_treeID, waitForRespnseCommandName, cancellationToken).ConfigureAwait(false);
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

        private static ExtendedFileAttributes ToExtendedFileAttributes(FileAttributes fileAttributes)
        {
            // We only return flags that can be used with NtCreateFile
            ExtendedFileAttributes extendedFileAttributes = ExtendedFileAttributes.ReadOnly |
                                                            ExtendedFileAttributes.Hidden |
                                                            ExtendedFileAttributes.System |
                                                            ExtendedFileAttributes.Archive |
                                                            ExtendedFileAttributes.Normal |
                                                            ExtendedFileAttributes.Temporary |
                                                            ExtendedFileAttributes.Offline |
                                                            ExtendedFileAttributes.Encrypted;
            return (extendedFileAttributes & (ExtendedFileAttributes)fileAttributes);
        }

        private static FileStatus ToFileStatus(CreateDisposition createDisposition)
        {
            switch (createDisposition)
            {
                case CreateDisposition.FILE_SUPERSEDE:
                    return FileStatus.FILE_SUPERSEDED;
                case CreateDisposition.FILE_OPEN:
                    return FileStatus.FILE_OPENED;
                case CreateDisposition.FILE_CREATE:
                    return FileStatus.FILE_CREATED;
                case CreateDisposition.FILE_OPEN_IF:
                    return FileStatus.FILE_OVERWRITTEN;
                case CreateDisposition.FILE_OVERWRITE:
                    return FileStatus.FILE_EXISTS;
                case CreateDisposition.FILE_OVERWRITE_IF:
                    return FileStatus.FILE_DOES_NOT_EXIST;
                default:
                    return FileStatus.FILE_OPENED;
            }
        }
    }
}