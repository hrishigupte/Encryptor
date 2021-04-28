using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Encryptor.Data;
using Encryptor.Util;
using Encryptor.Exceptions;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Encryptor
{
    public class FileEncryptor
    {
        private const bool optionalAsymmetricEncryptionPadding = false;
        private string privateKeyEncryptionpassword="";
        public bool DecryptFile(string privateKeyFile,string inputFileName, string outputFileName, ParamNameConstantsEnum encpreference)
        {
            FileStream fs;
            StringBuilder sb ;
            RSACryptoServiceProvider rsa;
            string outputkeyfileName = inputFileName + ".info";;
            if (encpreference==ParamNameConstantsEnum.Base64)
            {
                outputkeyfileName = outputkeyfileName.Replace(".base64","");
            }
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

                int encryptedkeyindex = pemkey.IndexOf(KeyPhraseConstants.PrivateKeyEncryptionInfo,0);
                if (encryptedkeyindex >=0)
                {
                    using (MemoryStream memrd = new MemoryStream())
                    {
                        StreamWriter wr = new StreamWriter(memrd);
                        wr.Write(sb.ToString());
                        wr.Flush();
                        //wr.Close();
                        memrd.Position=0;
                        StreamReader rd = new StreamReader(memrd);
                        if (string.IsNullOrEmpty(this.privateKeyEncryptionpassword.Trim()))
                        {
                            throw new PasswordNotSuppliedException("Private key is encrypted...Password for Decrypting private key not provided");
                        }
                        PemReader pemreader= new PemReader(rd,new PemPasswordFinder(privateKeyEncryptionpassword));
                        AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair) pemreader.ReadObject();
                        RsaPrivateCrtKeyParameters rsaparams  = (RsaPrivateCrtKeyParameters) keyPair.Private;
                        RSAParameters rsp = DotNetUtilities.ToRSAParameters(rsaparams);
                        rsa = new RSACryptoServiceProvider();
                        rsa.ImportParameters(rsp);
                        rd.Close();
                        wr.Close();
                        memrd.Close();
                    }
                }
                else 
                {
                    int startkeyphraseindex = pemkey.IndexOf(KeyPhraseConstants.PrivateKeyStart,0);
                    int keystartindex = startkeyphraseindex + KeyPhraseConstants.PrivateKeyStart.Length;
                    int endkeyphraseindex = pemkey.IndexOf(KeyPhraseConstants.PrivateKeyEnd,0);
                    string key = pemkey.Substring(keystartindex,pemkey.Length - (keystartindex+1) - (pemkey.Length-endkeyphraseindex-1));
                    sb = new StringBuilder();
                    sb.Append(key.Replace("\r",""));
                    sb.Replace("\n","");
                    key = sb.ToString().Trim();
                    byte[] keydata = Convert.FromBase64String(key);
                    rsa = new PemFileLoader().LoadPemPrivateKeyFile(keydata);
                }
                //Console.WriteLine(" File to decrypt " + inputFileName);
                //Console.WriteLine(" decrypted file" + outputFileName);
                if ((inputFileName!="") && (outputFileName!=""))
                {
                    using (fs = File.Open(outputkeyfileName,FileMode.Open))
                    {
                        byte[] decryptedbuffer;
                        StreamReader reader = new StreamReader(fs);
                        byte[] outbuffer = Convert.FromBase64String(reader.ReadToEnd());
                        reader.Close();
                        decryptedbuffer = rsa.Decrypt(outbuffer,RSAEncryptionPadding.Pkcs1);
                        SymmetricFileEncryptor flencryptor = new SymmetricFileEncryptor();
                        switch (encpreference)
                        {
                            case ParamNameConstantsEnum.Base64:
                                if (File.Exists (inputFileName))
                                {
                                    flencryptor.DecryptFromBase64EncodedFile(inputFileName,outputFileName,decryptedbuffer);
                                }
                                break;
                            case ParamNameConstantsEnum.Binary:
                                if (File.Exists(inputFileName))
                                {
                                    flencryptor.DecryptFile(inputFileName,outputFileName,decryptedbuffer);
                                }
                                break;
                            default:
                                if (File.Exists(inputFileName))
                                {
                                    flencryptor.DecryptFile(inputFileName,outputFileName,decryptedbuffer);
                                }
                                if (File.Exists(inputFileName + ".base64"))
                                {
                                     flencryptor.DecryptFromBase64EncodedFile(inputFileName +".base64",outputFileName + ".base64out",decryptedbuffer);
                                }
                                break;
                        }
                    }
                }
                return true;
            }
            catch (FileNotFoundException fex)
            {
                Console.WriteLine("COuld not find key file " + fex.ToString());
            }
            catch (PasswordNotSuppliedException pex)
            {
                Console.WriteLine("Could not decrypt private key to decrypt file : " + pex.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("General exception " + ex.ToString());
            }
            return false;
        }

        public bool EncryptFile (string publicKeyFile, string inputFileName, string outputFileName,ParamNameConstantsEnum encpreference)
        {
            FileStream fs;
            StringBuilder sb ;
            string outputkeyfileName = outputFileName + ".info";
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

                int endkeyphraseindex = pemkey.IndexOf(KeyPhraseConstants.PublicKeyEnd,0);
                string key = pemkey.Substring(keystartindex,pemkey.Length - (keystartindex+1) - (pemkey.Length-endkeyphraseindex-1));
                sb = new StringBuilder();
                sb.Append(key.Replace("\r",""));
                sb.Replace("\n","");
                key = sb.ToString().Trim();
                byte[] keydata = Convert.FromBase64String(key);
                RSACryptoServiceProvider rsa = new PemFileLoader().LoadPemPublicKeyFile(keydata);
                Console.WriteLine(" File to encrypt " + inputFileName);
                Console.WriteLine(" Output File " + outputFileName);
                if ((inputFileName!="") && (outputFileName!=""))
                {
                    SymmetricFileEncryptor flencryptor = new SymmetricFileEncryptor();
                    byte[] data =  flencryptor.EncryptFile(inputFileName,outputFileName);
                    byte[] plaintextbuffer;
                    using (FileStream fsout = File.Open(outputkeyfileName, FileMode.Create))
                    {
                        plaintextbuffer = rsa.Encrypt(data,RSAEncryptionPadding.Pkcs1);
                        //fsout.Write(plaintextbuffer,0,plaintextbuffer.Length);
                        StreamWriter writer = new StreamWriter(fsout);
                        writer.Write(Convert.ToBase64String(plaintextbuffer));
                        writer.Flush();
                        writer.Close();
                        fsout.Close();
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

        public bool PerformOperation (string keyfile, string inputFileName, string outputFileName, ParamNameConstantsEnum operation,ParamNameConstantsEnum encpreference)
        {
            switch (operation)
            {
                case ParamNameConstantsEnum.Decrypt:
                    return this.DecryptFile(keyfile,inputFileName,outputFileName,encpreference);
                case ParamNameConstantsEnum.Encrypt:
                    return this.EncryptFile(keyfile,inputFileName,outputFileName,encpreference);
                default:
                    break;
            }
            return false;
        }
        private int GetMaxDataSize(int keySize)
        {
            if (optionalAsymmetricEncryptionPadding)
            {
                return ((keySize - 384)/8) + 7;
            }
            else 
            {
                return ((keySize - 384)/8) + 37;
            }
        }

        private string GetString (byte[] keydata)
        {
            char[] chars = new char[keydata.Length/sizeof(char)];
            System.Buffer.BlockCopy(keydata,0,chars,0,keydata.Length);
            return new String(chars);
        }

        private byte[] GetBytes (string keydata)
        {
            char[] chars = keydata.ToCharArray();
            byte[] password = new byte[keydata.Length * sizeof(char)];
            System.Buffer.BlockCopy(chars,0,password,0,chars.Length);
            return password;

        }

        public string PrivateKeyEncryptionpassword 
        {
            get 
            {
                return this.privateKeyEncryptionpassword;
            }
            set 
            {
                this.privateKeyEncryptionpassword = value;
            }

        }
    }
}

