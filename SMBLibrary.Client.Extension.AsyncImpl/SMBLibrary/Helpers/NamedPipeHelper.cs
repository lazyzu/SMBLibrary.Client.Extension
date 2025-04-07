/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using SMBLibrary.RPC;
using SMBLibrary.Services;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public class NamedPipeHelper
    {
        public static async Task<Result<BindPipeResponse>> BindPipe(INTAsyncFileStore namedPipeShare, string pipeName, Guid interfaceGuid, uint interfaceVersion, CancellationToken cancellationToken = default)
        {
            var createFileResponse = await namedPipeShare.CreateFile(pipeName, (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA), 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, null, cancellationToken);
            if (createFileResponse.IsSuccess == false)
            {
                return createFileResponse.Error;
            }
            BindPDU bindPDU = new BindPDU();
            bindPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            bindPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            bindPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            bindPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            bindPDU.MaxTransmitFragmentSize = 5680;
            bindPDU.MaxReceiveFragmentSize = 5680;

            ContextElement serviceContext = new ContextElement();
            serviceContext.AbstractSyntax = new SyntaxID(interfaceGuid, interfaceVersion);
            serviceContext.TransferSyntaxList.Add(new SyntaxID(RemoteServiceHelper.NDRTransferSyntaxIdentifier, RemoteServiceHelper.NDRTransferSyntaxVersion));

            bindPDU.ContextList.Add(serviceContext);

            byte[] input = bindPDU.GetBytes();

            var deviceIOControlResponse = await namedPipeShare.DeviceIOControl(createFileResponse.Value.Handle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, 4096, cancellationToken);
            if (deviceIOControlResponse.IsSuccess == false)
            {
                return deviceIOControlResponse.Error;
            }
            BindAckPDU bindAckPDU = RPCPDU.GetPDU(deviceIOControlResponse.Value, 0) as BindAckPDU;
            if (bindAckPDU == null)
            {
                return new ErrorResponseException(NTStatus.STATUS_NOT_SUPPORTED);
            }

            return new BindPipeResponse(pipeHandle: createFileResponse.Value.Handle, bindAckPDU.MaxTransmitFragmentSize);
        }

        public class BindPipeResponse
        {
            public readonly object PipeHandle;
            public readonly int MaxTransmitFragmentSize;

            public BindPipeResponse(object pipeHandle, int maxTransmitFragmentSize)
            {
                this.PipeHandle = pipeHandle;
                this.MaxTransmitFragmentSize = maxTransmitFragmentSize;
            }
        }
    }
}
