namespace Encryptor.Data 
{
    public static class KeyPhraseConstants 
    {
        public static readonly string PrivateKeyStart = "-----BEGIN RSA PRIVATE KEY-----";
        public static readonly string PrivateKeyEnd = "-----END RSA PRIVATE KEY-----";

        public static readonly string PublicKeyStart = "-----BEGIN PUBLIC KEY-----";
        public static readonly string PublicKeyEnd = "-----END PUBLIC KEY-----";
        public static readonly string PrivateKeyEncryptionInfo="Proc-Type: 4,ENCRYPTED";

    }


}