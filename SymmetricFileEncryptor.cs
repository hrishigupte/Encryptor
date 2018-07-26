using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


public class SymmetricFileEncryptor 
{
    private const bool optionencryptionsymmetricpadding = false;
    private const string passphrase = "wswvw@28m";
    private const string initvector = "@@epx2rvuw##$&*!";
    private const int keysize = 256;
    private const int passworditerations = 10;
    private const int saltsize = 16;

    private const int buffersize = 1024;
    private const int base64buffersize = 24;

    public byte[] EncryptFile(string inputFileName, string outputFileName)
    {
        StringBuilder sb = new StringBuilder();
        byte[] key;
        using (FileStream fs = File.Open(inputFileName,FileMode.Open))
        {
            byte[] salt = this.GetRandomSalt(saltsize);

            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passphrase,salt);

            RijndaelManaged symmetrickey = new RijndaelManaged();
            key = password.GetBytes(keysize/8);
            symmetrickey.Key = key;
            symmetrickey.Mode = CipherMode.CBC;
            symmetrickey.IV = Encoding.ASCII.GetBytes(initvector);

            ICryptoTransform crypto = symmetrickey.CreateEncryptor();
            
            byte[] data;
            MemoryStream memstream  = new MemoryStream();
            CryptoStream cryptostream = new CryptoStream(memstream,crypto,CryptoStreamMode.Write);
            int totalblocks =  (int)fs.Length / buffersize;
            int finalblocksize = (int)fs.Length % buffersize;
            for (int i = 0; i< totalblocks;i++)
            {
                data = new byte[buffersize];
                fs.Read(data,0,buffersize);
                cryptostream.Write(data,0,buffersize);
            }
            data = new byte[finalblocksize];
            cryptostream.Write(data,0,finalblocksize);
            cryptostream.FlushFinalBlock();
            memstream.Flush();
            
            this.WriteStreamToBase64EncodedFile(memstream,outputFileName + ".base64");
            File.WriteAllBytes(outputFileName,memstream.ToArray());
            cryptostream.Close();
            memstream.Close();
            sb.Append(this.GetString(key));
            /* Console.WriteLine(sb.ToString());
            Console.WriteLine(Convert.ToBase64String(key)); */
        }
        return key;
    }
    public bool WriteStreamToBase64EncodedFile(MemoryStream input, string outputFileName)
    {
        using (FileStream fso = File.Open(outputFileName,FileMode.Create))
        {
            StreamWriter writer = new StreamWriter(fso);
            byte[] data;
            StringBuilder base64data = new StringBuilder();
            base64data.Append(Convert.ToBase64String(input.ToArray()));
            writer.Write(base64data.ToString());
            writer.Close();
            fso.Close();
        }
        return true;
    }

    public MemoryStream ReadStreamFromBase64EncodedFile(string inputFileName)
    {
        StreamReader reader;
        MemoryStream output;
        StringBuilder sb = new StringBuilder();
        byte[] data;
        using (FileStream fsi = File.Open(inputFileName,FileMode.Open))
        {
            reader = new StreamReader(fsi);
            sb.Append(reader.ReadToEnd());
            reader.Close();
            data = Convert.FromBase64String(sb.ToString());
            output = new MemoryStream(data);
            fsi.Close();
        }
        return output;
    }


    public void DecryptFile(string inputFileName, string outputFileName, byte[] key)
    {
        StringBuilder sb = new StringBuilder();
        sb.Append(this.GetString(key));
        //Console.WriteLine(sb.ToString());
        RijndaelManaged symmetrickey = new RijndaelManaged();
        symmetrickey.Key = key;
        symmetrickey.IV = Encoding.ASCII.GetBytes(initvector);

        ICryptoTransform crypto = symmetrickey.CreateDecryptor();
        MemoryStream output = new MemoryStream();
        CryptoStream symmetriccryptostream  = new CryptoStream(output,crypto,CryptoStreamMode.Write);

        using (FileStream fs = File.Open(inputFileName,FileMode.Open))
        {
            //Stream
            byte[] data;
            int totalblocks = (int)fs.Length/buffersize;
            int finalblocksize = (int)fs.Length % buffersize;
            for (int i =0 ; i < totalblocks; i++)
            {
                data = new byte[buffersize];
                fs.Read(data,0,buffersize);
                symmetriccryptostream.Write(data,0,buffersize);
            }
            data = new byte[finalblocksize];
            fs.Read(data,0,finalblocksize);
            symmetriccryptostream.Write(data,0,finalblocksize);
            symmetriccryptostream.FlushFinalBlock();
            output.Flush();
            File.WriteAllBytes(outputFileName,output.ToArray()); 
            output.Close();
            symmetriccryptostream.Close();
            fs.Close();

        }
       

    }

    public void DecryptFromBase64EncodedFile(string inputFileName, string outputFileName, byte[] key)
    {
        RijndaelManaged symmetrickey = new RijndaelManaged();
        symmetrickey.Key = key;
        symmetrickey.IV = Encoding.ASCII.GetBytes(initvector);

        ICryptoTransform crypto = symmetrickey.CreateDecryptor();
        MemoryStream output = new MemoryStream();
        CryptoStream symmetriccryptostream  = new CryptoStream(output,crypto,CryptoStreamMode.Write);
        
        symmetriccryptostream = new CryptoStream(output,crypto,CryptoStreamMode.Write);
        
        byte[] data;
        MemoryStream input = this.ReadStreamFromBase64EncodedFile(inputFileName);
        int totalblocks = (int)input.Length/buffersize;
        int finalblocksize = (int)input.Length % buffersize;
        for (int i=0; i< totalblocks;i++)
        {
            data = new byte[buffersize];
            input.Read(data,0,buffersize);
            symmetriccryptostream.Write(data,0,buffersize);
        }
        data = new byte[finalblocksize];
        input.Read(data,0,finalblocksize);
        symmetriccryptostream.Write(data,0,finalblocksize);
        symmetriccryptostream.Flush();
        output.Flush();
        File.WriteAllBytes(outputFileName,output.ToArray());
        symmetriccryptostream.Close();

    }
    private string GetString(byte[] keyvalue)
    {
        char[] chars = new char[keyvalue.Length/sizeof(char)];
        Buffer.BlockCopy(keyvalue,0,chars,0,keyvalue.Length);
        return new String(chars);
    }
    private byte[] GetBytes (string key)
    {
        char[] chars = key.ToCharArray();
        byte[] keyvalue = new byte[chars.Length * sizeof(char)];
        Buffer.BlockCopy(chars,0,keyvalue,0,keyvalue.Length);
        return keyvalue;
    }
    private byte[] GetRandomSalt(int size)
    {
        byte[] random;
        if (size >=1)
        {
            random = new byte[size];
        }
        else 
        {
            random = new byte[1];
        }
        RNGCryptoServiceProvider prov = new RNGCryptoServiceProvider();
        prov.GetBytes(random);
        return random;
    }





}