using System;

namespace SMBLibrary.Client.Extension.AsyncImpl
{
    public class Result<TValue, TError>
    {
        public readonly bool IsSuccess;
        public readonly TValue Value;
        public readonly TError Error;

        protected Result(TValue value)
        {
            this.IsSuccess = true;
            this.Value = value;
            this.Error = default;
        }

        protected Result(TError error)
        {
            this.IsSuccess = false;
            this.Value = default;
            this.Error = error;
        }

        public static implicit operator Result<TValue, TError>(TValue value) => new Result<TValue, TError>(value);

        //error path
        public static implicit operator Result<TValue, TError>(TError error) => new Result<TValue, TError>(error);

        public void Deconstruct(out bool isSuccess, out TValue value, out TError error)
        {
            isSuccess = IsSuccess;
            value = Value;
            error = Error;
        }
    }

    public class Result<TValue> : Result<TValue, Exception>
    {
        protected Result(TValue value) : base(value)
        { }

        protected Result(Exception error) : base(error)
        { }

        public static implicit operator Result<TValue>(TValue value) => new Result<TValue>(value);

        //error path
        public static implicit operator Result<TValue>(Exception error) => new Result<TValue>(error);
    }

    public class Result
    {
        public class NTStatus : Result<SMBLibrary.NTStatus, Exception>
        {
            protected NTStatus(SMBLibrary.NTStatus value) : base(value)
            {
            }

            protected NTStatus(Exception error) : base(error) 
            { }

            public static implicit operator Result.NTStatus(SMBLibrary.NTStatus value) => new Result.NTStatus(value);

            //error path
            public static implicit operator Result.NTStatus(Exception error) => new Result.NTStatus(error);
        }

        public class None
        {
            public readonly bool IsSuccess;
            public readonly Exception Error;

            public None() => IsSuccess = true;

            public None(Exception error)
            {
                this.IsSuccess = false;
                this.Error = error;
            }

            public static implicit operator Result.None(Exception error) => new Result.None(error);
        }
    }
}
