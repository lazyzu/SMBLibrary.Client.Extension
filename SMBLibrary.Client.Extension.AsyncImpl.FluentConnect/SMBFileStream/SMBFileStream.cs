using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using SMBLibrary.Client.Extension.AsyncImpl.FluentConnect.Handle;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect
{
    public class SMBFileStream : Stream, IAsyncDisposable
    {
        private readonly SMBPath path;
        private ISMBAsyncClient client;
        private SMBTransaction transaction;
        private bool fromTransaction = false;
        private readonly ISMBAsyncFileStore shareStore;
        private readonly object fileHandle;
        private readonly SMBLibrary.AccessMask access;
        private long length;

        private readonly bool leaveConnectionOpenWhenDispose;
        private bool disposedValue = false;

        private SMBFileStream(SMBPath path, ISMBAsyncClient client, ISMBAsyncFileStore shareStore, object fileHandle, SMBLibrary.AccessMask access, long length, bool leaveConnectionOpenWhenDispose)
        {
            this.path = path;
            this.client = client;
            this.shareStore = shareStore;
            this.fileHandle = fileHandle;
            this.access = access;
            this.length = length;
            this.leaveConnectionOpenWhenDispose = leaveConnectionOpenWhenDispose;
        }

        //public static SMBFileStream CreateFrom(SMBPath path, ISMBClient client, FileMode mode, FileAccess access, FileShare share, bool disposeTransaction = true)
        //{
        //    var result = new SMBFileStream();

        //    this.path = path;
        //    this.disposeTransaction = disposeTransaction;
        //}

        public static async Task<Result<SMBFileStream>> CreateFrom(SMBPath path, ISMBAsyncClient client
            , SMBLibrary.CreateDisposition mode, SMBLibrary.AccessMask access, SMBLibrary.ShareAccess share
            , bool leaveConnectionOpenWhenDispose = true
            , CancellationToken cancellationToken = default)
        {
            if (path == null) return new ArgumentNullException(nameof(path));
            if (client == null) return new ArgumentNullException(nameof(client));

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

            var shareStore = shareConnectResponse.Value;
            var fileConnectResponse = await shareConnectResponse.Value.CreateFile(targetFilePath
                , access
                , SMBLibrary.FileAttributes.Normal
                , share
                , mode
                , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                , null
                , cancellationToken).ConfigureAwait(false);

            if (fileConnectResponse.IsSuccess)
            {
                var fileHandle = fileConnectResponse.Value.Handle;
                var endOfFileResponse = await getEndOfFile(path, shareStore, fileHandle, cancellationToken).ConfigureAwait(false);
                if (endOfFileResponse.IsSuccess)
                {
                    var fileLength = endOfFileResponse.Value;
                    return new SMBFileStream(path, client, shareStore, fileHandle, access, fileLength, leaveConnectionOpenWhenDispose);
                }
                else return new AccessViolationException($"Not able to read end of file location of file {path}", endOfFileResponse.Error);
            }
            else return new AccessViolationException($"Not able to connect file {path}", fileConnectResponse.Error);
        }

        public static async Task<Result<SMBFileStream>> CreateFrom(SMBPath path, SMBTransaction transaction
            , SMBLibrary.CreateDisposition mode, SMBLibrary.AccessMask access, SMBLibrary.ShareAccess share
            , bool leaveConnectionOpenWhenDispose = true
            , CancellationToken cancellationToken = default)
        {
            var createfileStreamResponse = await CreateFrom(path, transaction?.Client, mode, access, share, leaveConnectionOpenWhenDispose, cancellationToken).ConfigureAwait(false);
            if (createfileStreamResponse.IsSuccess)
            {
                var fileStream = createfileStreamResponse.Value;
                fileStream.fromTransaction = true;
                fileStream.transaction = transaction;
                return fileStream;
            }
            else return createfileStreamResponse.Error;
        }

        private static async Task<Result<long>> getEndOfFile(SMBPath path, ISMBAsyncFileStore shareStore, object fileHandle, CancellationToken cancellationToken = default)
        {
            var fileStandardInformationResponse = await SMBFile.GetInfo<SMBLibrary.FileStandardInformation>(path, shareStore, fileHandle, SMBLibrary.FileInformationClass.FileStandardInformation, cancellationToken).ConfigureAwait(false);

            if (fileStandardInformationResponse.IsSuccess == false) return fileStandardInformationResponse.Error;
            else return fileStandardInformationResponse.Value.EndOfFile;
        }

        public override bool CanRead => access.HasFlag(SMBLibrary.AccessMask.GENERIC_READ);

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer, offset, count).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (count <= 0) return 0;

            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (buffer.Length == 0) throw new ArgumentException($"Length of {nameof(buffer)} is 0");
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset), $"offset value: {offset}");

            var numBytesToRead = count;
            var numBytesReaded = 0;
            var blockSize = 4096;

            while (true)
            {
                var readFileResponse = await shareStore.ReadFile(fileHandle, position + numBytesReaded, Math.Min(numBytesToRead, blockSize), cancellationToken).ConfigureAwait(false);
                if (readFileResponse.IsSuccess)
                {
                    var responseStatus = readFileResponse.Value.ReplyHeaderStatus;
                    var data = readFileResponse.Value.Data;
                    var n = data.Length;
                    data.CopyTo(buffer, offset + numBytesReaded);
                    numBytesReaded += n;
                    numBytesToRead -= n;

                    if (responseStatus == NTStatus.STATUS_END_OF_FILE) break;
                    if (n == 0) break;
                    if (numBytesToRead == 0) break;
                }
                else throw new AccessViolationException($"Failed to read from file {path}", readFileResponse.Error);
            }

            this.Position += numBytesReaded;
            return numBytesReaded;
        }

        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            return TaskToApm.Begin(ReadAsync(buffer, offset, count, CancellationToken.None), callback, state);
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            return TaskToApm.End<int>(asyncResult);
        }

        private long position = 0;

        public override long Position
        {
            get => position;
            set
            {
                if (value < Length) position = value;
                else position = Length;
            }
        }

        public override long Length => length;

        public override void SetLength(long value)
        {
            if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));

            var endOfFileInformationResponse = shareStore.SetFileInformation(fileHandle, new FileEndOfFileInformation()
            {
                EndOfFile = value
            }).ConfigureAwait(false).GetAwaiter().GetResult();

            if (endOfFileInformationResponse.IsSuccess == false)
            {
                throw new AccessViolationException($"Set EndOfFile of {path} is failed", endOfFileInformationResponse.Error);
            }

            if (endOfFileInformationResponse.Value != NTStatus.STATUS_SUCCESS)
            {
                throw new AccessViolationException($"Set EndOfFile of {path} is failed with {endOfFileInformationResponse.Value}");
            }

            this.length = value;
        }

        public override bool CanSeek => true;

        public override long Seek(long offset, SeekOrigin origin)
        {
            long tempPos = -1;

            var endFileLength = Length;

            switch (origin)
            {
                case SeekOrigin.Begin:
                    tempPos = offset;
                    break;
                case SeekOrigin.Current:
                    tempPos = Position + offset;
                    break;
                case SeekOrigin.End:
                    tempPos = endFileLength + offset;
                    break;
            }

            if (tempPos >= 0 && (tempPos < endFileLength || endFileLength == 0))
            {
                Position = tempPos;
                return Position;
            }
            else throw new ArgumentOutOfRangeException($"{tempPos} is out of range, max file length: {endFileLength}");
        }

        public override bool CanWrite => access.HasFlag(SMBLibrary.AccessMask.GENERIC_WRITE);

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteAsync(buffer, offset, count).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            if (count <= 0) return;

            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (buffer.Length == 0) throw new ArgumentException($"Length of {nameof(buffer)} is 0");
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset), $"offset value: {offset}");

            var numBytesToWrite = count;
            var numBytesWrited = 0;
            var blockSize = (int)client.MaxWriteSize;

            while (numBytesToWrite > 0)
            {
                var gblockWriteBuffer = new byte[Math.Min(numBytesToWrite, blockSize)];
                Array.Copy(buffer, offset + numBytesWrited, gblockWriteBuffer, 0, gblockWriteBuffer.Length);

                var writeResponse = await shareStore.WriteFile(fileHandle, position + numBytesWrited, gblockWriteBuffer, cancellationToken).ConfigureAwait(false);
                var numberOfBytesWritten = writeResponse.Value;
                if (writeResponse.IsSuccess == false)
                {
                    throw new AccessViolationException($"Failed to write file: {path}", writeResponse.Error);
                }

                numBytesToWrite -= numberOfBytesWritten;
                numBytesWrited += numberOfBytesWritten;
            }

            var newPosition = this.Position + numBytesWrited;
            if (newPosition >= this.Length) this.length = newPosition + 1;

            this.Position = newPosition;
        }

        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            return TaskToApm.Begin(WriteAsync(buffer, offset, count, CancellationToken.None), callback, state);
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            TaskToApm.End(asyncResult);
        }

        public override void Flush()
        {
            this.FlushAsync().ConfigureAwait(false).GetAwaiter().GetResult();
        }

        public override async Task FlushAsync(CancellationToken cancellationToken = default)
        {
            var flushResponse = await shareStore.FlushFileBuffers(fileHandle, cancellationToken).ConfigureAwait(false);

            if (flushResponse.IsSuccess == false) throw new AccessViolationException("Flush is failed by error", flushResponse.Error);
            if (flushResponse.Value != NTStatus.STATUS_SUCCESS) throw new AccessViolationException($"Flush is failed with status: {flushResponse.Value}");
        }

        public override bool CanTimeout => false;

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            this.DisposeAsyncCore(disposing).ConfigureAwait(false).GetAwaiter().GetResult();
        }

#if NETSTANDARD2_0
        public async ValueTask DisposeAsync()
#else
        public override async ValueTask DisposeAsync()
#endif
        {
            await DisposeAsyncCore(disposing: true).ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }

        protected virtual async ValueTask DisposeAsyncCore(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: 處置受控狀態 (受控物件)

                    await shareStore.CloseFile(fileHandle).ConfigureAwait(false);

                    if (leaveConnectionOpenWhenDispose == false)
                    {
                        if (fromTransaction)
                        {
                            await transaction.DisposeAsync().ConfigureAwait(false);
                        }
                        else
                        {
                            // if (this.client.) await this.client?.Logoff();
#if NET6_0_OR_GREATER
                            if (this.client?.IsConnected ?? false) await this.client.Disconnect().ConfigureAwait(false);
#else
                            if (this.client?.IsConnected ?? false) this.client?.Disconnect();
#endif
                        }
                    }
                }

                this.client = null;

                disposedValue = true;
            }
        }
    }
}
