using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Encryptor.Data;
using Encryptor.Util;

namespace Encryptor
{
    public class FileEncryptor
    {
    
        public bool DecryptFile(string privateKeyFile,string inputFileName, string outputFileName)
        {
            FileStream fs;
            StringBuilder sb ;
            try 
            {
                using (fs = File.Open(privateKeyFile,FileMode.Open))
                {
                    StreamReader sr = new StreamReader(fs);
                    sb = new StringBuilder();
                    sb.Append(sr.ReadToEnd());
                    sr.Close();

                }
                string pemkey = sb.ToString();
                int startkeyphraseindex = pemkey.IndexOf(KeyPhraseConstants.PrivateKeyStart,0);
                int keystartindex = startkeyphraseindex + KeyPhraseConstants.PrivateKeyStart.Length;

                //Console.WriteLine(startkeyphraseindex);
                int endkeyphraseindex = pemkey.IndexOf(KeyPhraseConstants.PrivateKeyEnd,0);
                //Console.WriteLine(endkeyphraseindex);
                string key = pemkey.Substring(keystartindex,pemkey.Length - (keystartindex+1) - (pemkey.Length-endkeyphraseindex-1));
                sb = new StringBuilder();
                //Console.WriteLine(key);
                sb.Append(key.Replace("\r",""));
                sb.Replace("\n","");
                key = sb.ToString().Trim();
                byte[] keydata = Convert.FromBase64String(key);
                RSACryptoServiceProvider rsa = new PemFileLoader().LoadPemPrivateKeyFile(keydata);
                Console.WriteLine(" File to decrypt " + inputFileName);
                Console.WriteLine(" File to be decrypted " + outputFileName);
                if ((inputFileName!="") && (outputFileName!=""))
                {
                    using (fs = File.Open(inputFileName,FileMode.Open))
                    {
                        byte[] decryptedbuffer;
                        using (FileStream fsout = File.Open(outputFileName, FileMode.Create))
                        {
                            int currentoffset =0,currentdecryptedoffset = 0;
                            byte[] outbuffer = new byte[fs.Length];
                            fs.Read(outbuffer,currentoffset,(int)fs.Length);
                            decryptedbuffer = rsa.Decrypt(outbuffer,RSAEncryptionPadding.Pkcs1);
                            fsout.Write(decryptedbuffer,currentdecryptedoffset,decryptedbuffer.Length);
                        }

                    }
                }
                return true;
            }
            catch (FileNotFoundException fex)
            {
                Console.WriteLine("COuld not find key file " + fex.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("General exception " + ex.ToString());
            }
            return false;
        }

        public bool EncryptFile (string publicKeyFile, string inputFileName, string outputFileName)
        {
                FileStream fs;
            StringBuilder sb ;
            try 
            {
                using (fs = File.Open(publicKeyFile,FileMode.Open))
                {
                    StreamReader sr = new StreamReader(fs);
                    sb = new StringBuilder();
                    sb.Append(sr.ReadToEnd());
                    sr.Close();

                }
                string pemkey = sb.ToString();
                int startkeyphraseindex = pemkey.IndexOf(KeyPhraseConstants.PublicKeyStart,0);
                int keystartindex = startkeyphraseindex + KeyPhraseConstants.PublicKeyStart.Length;

                //Console.WriteLine(startkeyphraseindex);
                int endkeyphraseindex = pemkey.IndexOf(KeyPhraseConstants.PublicKeyEnd,0);
                //Console.WriteLine(endkeyphraseindex);
                string key = pemkey.Substring(keystartindex,pemkey.Length - (keystartindex+1) - (pemkey.Length-endkeyphraseindex-1));
                sb = new StringBuilder();
                //Console.WriteLine(key);
                sb.Append(key.Replace("\r",""));
                sb.Replace("\n","");
                key = sb.ToString().Trim();
                byte[] keydata = Convert.FromBase64String(key);
                RSACryptoServiceProvider rsa = new PemFileLoader().LoadPemPublicKeyFile(keydata);
                Console.WriteLine(" File to encrypt " + inputFileName);
                Console.WriteLine(" Output File " + outputFileName);
                if ((inputFileName!="") && (outputFileName!=""))
                {
                    using (fs = File.Open(inputFileName,FileMode.Open))
                    {
                        byte[] decryptedbuffer;
                        using (FileStream fsout = File.Open(outputFileName, FileMode.Create))
                        {
                            int currentoffset =0,currentdecryptedoffset = 0;
                            byte[] outbuffer = new byte[fs.Length];
                            fs.Read(outbuffer,currentoffset,(int)fs.Length);
                            decryptedbuffer = rsa.Encrypt(outbuffer,RSAEncryptionPadding.Pkcs1);
                            fsout.Write(decryptedbuffer,currentdecryptedoffset,decryptedbuffer.Length);
                        }

                    }
                }
                return true;
            }
            catch (FileNotFoundException fex)
            {
                Console.WriteLine("COuld not find key file " + fex.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("General exception " + ex.ToString());
            }
            return false;

        }

        public bool PerformOperation (string keyfile, string inputFileName, string outputFileName, ParamNameConstantsEnum operation)
        {
            switch (operation)
            {
                case ParamNameConstantsEnum.Decrypt:
                    return this.DecryptFile(keyfile,inputFileName,outputFileName);
                case ParamNameConstantsEnum.Encrypt:
                    return this.EncryptFile(keyfile,inputFileName,outputFileName);
                default:
                    break;
            }
            return false;
        }
    }
}

