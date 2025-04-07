/* Copyright (C) 2014-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using SMBLibrary.RPC;
using SMBLibrary.Services;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Utilities;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public class ServerServiceHelper
    {
        public static async Task<Result<List<string>>> ListShares(INTAsyncFileStore namedPipeShare, ShareType? shareType, CancellationToken cancellationToken = default)
        {
            return await ListShares(namedPipeShare, "*", shareType, cancellationToken);
        }

        /// <param name="serverName">
        /// When a Windows Server host is using Failover Cluster and Cluster Shared Volumes, each of those CSV file shares is associated
        /// with a specific host name associated with the cluster and is not accessible using the node IP address or node host name.
        /// </param>
        public static async Task<Result<List<string>>> ListShares(INTAsyncFileStore namedPipeShare, string serverName, ShareType? shareType, CancellationToken cancellationToken = default)
        {
            var bindPipeResponse = await NamedPipeHelper.BindPipe(namedPipeShare, ServerService.ServicePipeName, ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion, cancellationToken);
            if (bindPipeResponse.IsSuccess == false)
            {
                return bindPipeResponse.Error;
            }

            NetrShareEnumRequest shareEnumRequest = new NetrShareEnumRequest();
            shareEnumRequest.InfoStruct = new ShareEnum();
            shareEnumRequest.InfoStruct.Level = 1;
            shareEnumRequest.InfoStruct.Info = new ShareInfo1Container();
            shareEnumRequest.PreferedMaximumLength = UInt32.MaxValue;
            shareEnumRequest.ServerName = @"\\" + serverName;
            RequestPDU requestPDU = new RequestPDU();
            requestPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            requestPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            requestPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            requestPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            requestPDU.OpNum = (ushort)ServerServiceOpName.NetrShareEnum;
            requestPDU.Data = shareEnumRequest.GetBytes();
            requestPDU.AllocationHint = (uint)requestPDU.Data.Length;
            byte[] input = requestPDU.GetBytes();
            int maxOutputLength = bindPipeResponse.Value.MaxTransmitFragmentSize;
            var deviceIOControlResponse = await namedPipeShare.DeviceIOControl(bindPipeResponse.Value.PipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, maxOutputLength, cancellationToken);
            if (deviceIOControlResponse.IsSuccess == false)
            {
                return deviceIOControlResponse.Error;
            }
            ResponsePDU responsePDU = RPCPDU.GetPDU(deviceIOControlResponse.Value, 0) as ResponsePDU;
            if (responsePDU == null)
            {
                return new ErrorResponseException(NTStatus.STATUS_NOT_SUPPORTED);
            }

            byte[] responseData = responsePDU.Data;
            while ((responsePDU.Flags & PacketFlags.LastFragment) == 0)
            {
                var readFileResponse = await namedPipeShare.ReadFile(bindPipeResponse.Value.PipeHandle, 0, maxOutputLength, cancellationToken);
                if (readFileResponse.IsSuccess == false)
                {
                    return readFileResponse.Error;
                }
                responsePDU = RPCPDU.GetPDU(readFileResponse.Value.Data, 0) as ResponsePDU;
                if (responsePDU == null)
                {
                    return new ErrorResponseException(NTStatus.STATUS_NOT_SUPPORTED);
                }
                responseData = ByteUtils.Concatenate(responseData, responsePDU.Data);
            }
            await namedPipeShare.CloseFile(bindPipeResponse.Value.PipeHandle, cancellationToken);
            NetrShareEnumResponse shareEnumResponse = new NetrShareEnumResponse(responseData);
            ShareInfo1Container shareInfo1 = shareEnumResponse.InfoStruct.Info as ShareInfo1Container;
            if (shareInfo1 == null || shareInfo1.Entries == null)
            {
                if (shareEnumResponse.Result == Win32Error.ERROR_ACCESS_DENIED)
                {
                    return new ErrorResponseException(NTStatus.STATUS_ACCESS_DENIED);
                }
                else
                {
                    return new ErrorResponseException(NTStatus.STATUS_NOT_SUPPORTED);
                }
            }

            List<string> result = new List<string>();
            foreach (ShareInfo1Entry entry in shareInfo1.Entries)
            {
                if (!shareType.HasValue || shareType.Value == entry.ShareType.ShareType)
                {
                    result.Add(entry.NetName.Value);
                }
            }
            return result;
        }
    }
}
