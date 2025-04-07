using System;

namespace SMBLibrary.Client.Extension.AsyncImpl.FluentConnect.Handle
{
    public class YieldReturnProcessHandle
    {
        private readonly bool endProcessOnError = false;
        private readonly Action<Exception> errorHandle = null;

        public bool EndProcessRequested { get; set; }

        public YieldReturnProcessHandle(bool endProcessOnError, Action<Exception> errorHandle = null)
        {
            this.endProcessOnError = endProcessOnError;
            this.errorHandle = errorHandle;
        }

        internal virtual void ErrorHandle(Exception ex)
        {
            EndProcessRequested = this.endProcessOnError;
            errorHandle?.Invoke(ex);
        }

        public static YieldReturnProcessHandle GetDefault()
        {
            return new YieldReturnProcessHandle(true, errorHandle: (ex) => throw ex);
        }
    }
}
