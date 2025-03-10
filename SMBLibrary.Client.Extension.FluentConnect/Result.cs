using System;
using System.Collections.Generic;
using System.Text;

namespace SMBLibrary.Client.Extension.FluentConnect
{
    public class Result<TValue, TError>
    {
        public readonly bool IsSuccess;
        public readonly TValue Value;
        public readonly TError Error;

        private Result(TValue value)
        {
            this.IsSuccess = true;
            this.Value = value;
            this.Error = default;
        }

        private Result(TError error)
        {
            this.IsSuccess = false;
            this.Value = default;
            this.Error = error;
        }

        public void Deconstruct(out bool isSuccess, out TValue value, out TError error)
        {
            isSuccess = IsSuccess;
            value = Value;
            error = Error;
        }

        //happy path
        public static implicit operator Result<TValue, TError>(TValue value) => new Result<TValue, TError>(value);

        //error path
        public static implicit operator Result<TValue, TError>(TError error) => new Result<TValue, TError>(error);
    }
}
