using System;
using System.IO;

namespace SMBLibrary.Client.Extension.FluentConnect
{
    public class SMBFileStream : Stream, IDisposable
    {
        private readonly SMBPath path;
        private ISMBClient client;
        private SMBTransaction transaction;
        private bool fromTransaction = false;
        private readonly ISMBFileStore shareStore;
        private readonly object fileHandle;
        private readonly SMBLibrary.AccessMask access;
        private long length;

        private readonly bool leaveConnectionOpenWhenDispose;
        private bool disposedValue = false;

        private SMBFileStream(SMBPath path, ISMBClient client, ISMBFileStore shareStore, object fileHandle, SMBLibrary.AccessMask access, long length, bool leaveConnectionOpenWhenDispose)
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

        public static SMBFileStream CreateFrom(SMBPath path, ISMBClient client
            , SMBLibrary.CreateDisposition mode, SMBLibrary.AccessMask access, SMBLibrary.ShareAccess share
            , bool leaveConnectionOpenWhenDispose = true)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            if (client == null) throw new ArgumentNullException(nameof(client));

            var shareStore = client.TreeConnect(path.ShareName, out var shareConnectStatus);
            if (shareConnectStatus != NTStatus.STATUS_SUCCESS)
            {
                throw new AccessViolationException($"Not able to connect share {path.ShareName} of {path.HostName}, error:{shareConnectStatus}");
            }

            var targetFilePath = path.Path;

            if (client is SMB1Client)
            {
                targetFilePath = $"{targetFilePath}\\";
            }

            var fileConnectStatus = shareStore.CreateFile(out var fileHandle
                , out var fileConnectFileStatus
                , targetFilePath
                , access
                , SMBLibrary.FileAttributes.Normal
                , share
                , mode
                , SMBLibrary.CreateOptions.FILE_NON_DIRECTORY_FILE | SMBLibrary.CreateOptions.FILE_SYNCHRONOUS_IO_ALERT
                , null);

            if (fileConnectStatus == NTStatus.STATUS_SUCCESS)
            {
                var fileLength = getEndOfFile(path, shareStore, fileHandle);
                return new SMBFileStream(path, client, shareStore, fileHandle, access, fileLength, leaveConnectionOpenWhenDispose);
            }
            else throw new AccessViolationException($"Not able to connect file {path}, error:{fileConnectStatus}({fileConnectFileStatus})");
        }

        public static SMBFileStream CreateFrom(SMBPath path, SMBTransaction transaction
            , SMBLibrary.CreateDisposition mode, SMBLibrary.AccessMask access, SMBLibrary.ShareAccess share
            , bool leaveConnectionOpenWhenDispose = true)
        {
            var fileStream = CreateFrom(path, transaction?.Client, mode, access, share, leaveConnectionOpenWhenDispose);
            fileStream.fromTransaction = true;
            fileStream.transaction = transaction;
            return fileStream;
        }

        private static long getEndOfFile(SMBPath path, ISMBFileStore shareStore, object fileHandle)
        {
            var fileStandardInformation = SMBFile.GetInfo<SMBLibrary.FileStandardInformation>(path, shareStore, fileHandle, SMBLibrary.FileInformationClass.FileStandardInformation);
            return fileStandardInformation.EndOfFile;
        }

        public override bool CanRead => access.HasFlag(SMBLibrary.AccessMask.GENERIC_READ);

        public override int Read(byte[] buffer, int offset, int count)
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
                var readFileStatus = shareStore.ReadFile(out var data, fileHandle, position + numBytesReaded, Math.Min(numBytesToRead, blockSize));
                if (readFileStatus == NTStatus.STATUS_SUCCESS || readFileStatus == NTStatus.STATUS_END_OF_FILE)
                {
                    var n = data.Length;
                    data.CopyTo(buffer, offset + numBytesReaded);
                    numBytesReaded += n;
                    numBytesToRead -= n;

                    if (readFileStatus == NTStatus.STATUS_END_OF_FILE) break;
                    if (n == 0) break;
                    if (numBytesToRead == 0) break;
                }
                else throw new AccessViolationException($"Failed to read from file {path}, error:{readFileStatus}");
            }

            this.Position += numBytesReaded;
            return numBytesReaded;
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
            });

            if (endOfFileInformationResponse != NTStatus.STATUS_SUCCESS)
            {
                throw new AccessViolationException($"Set EndOfFile of {path} is failed with {endOfFileInformationResponse}");
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

                var writeStatus = shareStore.WriteFile(out var numberOfBytesWritten, fileHandle, position + numBytesWrited, gblockWriteBuffer);
                if (writeStatus != NTStatus.STATUS_SUCCESS)
                {
                    throw new AccessViolationException($"Failed to write file: {path}, error: {writeStatus}");
                }

                numBytesToWrite -= numberOfBytesWritten;
                numBytesWrited += numberOfBytesWritten;
            }

            var newPosition = this.Position + numBytesWrited;
            if (newPosition >= this.Length) this.length = newPosition + 1;

            this.Position = newPosition;
        }

        public override void Flush()
        {
            var response = shareStore.FlushFileBuffers(fileHandle);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: 處置受控狀態 (受控物件)

                    shareStore.CloseFile(fileHandle);

                    if (leaveConnectionOpenWhenDispose == false)
                    {
                        if (this.client?.IsConnected ?? false)
                        {
                            if (this.fromTransaction)
                            {
                                this.transaction?.Dispose();
                            }
                            else
                            {
                                // var logoffStatus = this.client.Logoff();   // Just try to log off
                                this.client?.Disconnect();
                            }
                        }
                    }
                }

                // TODO: 釋出非受控資源 (非受控物件) 並覆寫完成項
                // TODO: 將大型欄位設為 Null

                this.client = null;
                this.transaction = null;

                disposedValue = true;
            }
        }
    }
}
