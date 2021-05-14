using Org.BouncyCastle.OpenSsl;

namespace Encryptor.Util
{
    class PemPasswordFinder : IPasswordFinder
    {

        private string password;
        public PemPasswordFinder(string passwd)
        {
            this.password = passwd;
        }

        public char[] GetPassword()
        {
            return this.password.ToCharArray();
        }

    }
}