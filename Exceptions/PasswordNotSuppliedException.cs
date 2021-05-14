using System;
namespace Encryptor.Exceptions
{
    public class PasswordNotSuppliedException : Exception
    {
        public PasswordNotSuppliedException (string message) : base(message)
        {
            
        }
    }

}