using System;
using System.Security.Cryptography;
using System.IO;

namespace Encryptor.Util
{
    public class PemFileLoader
    {
        public RSACryptoServiceProvider LoadPemPrivateKeyFile(byte[] key)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            MemoryStream mem = new MemoryStream(key);
            BinaryReader rd = new BinaryReader(mem);
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try 
            {
                twobytes = rd.ReadUInt16();
                if (twobytes == 0x8130)
                {
                    rd.ReadByte();
                }
                else if (twobytes == 0x8230)
                {
                    rd.ReadUInt16();
                }
                else 
                    return null;

                twobytes = rd.ReadUInt16();
                if (twobytes != 0x0102)
                {
                    return null;
                }    
                bt = rd.ReadByte();
                if (bt!=0x00)
                {
                    return null;
                }
                elems = GetInterSize(rd);
                MODULUS = rd.ReadBytes(elems);
                
                elems = GetInterSize(rd);
                E = rd.ReadBytes(elems);

                elems = GetInterSize(rd);
                D = rd.ReadBytes(elems);

                elems = GetInterSize(rd);
                P = rd.ReadBytes(elems);

                elems = GetInterSize(rd);
                Q = rd.ReadBytes(elems);

                elems = GetInterSize(rd);
                DP = rd.ReadBytes(elems);

                elems = GetInterSize(rd);
                DQ = rd.ReadBytes(elems);

                elems = GetInterSize(rd);
                IQ = rd.ReadBytes(elems);

                RSAParameters rsaparameters = new RSAParameters();
                rsaparameters.Modulus = MODULUS;
                rsaparameters.Exponent = E;
                rsaparameters.D = D;
                rsaparameters.P = P;
                rsaparameters.Q = Q;
                rsaparameters.DP = DP;
                rsaparameters.DQ = DQ;
                rsaparameters.InverseQ = IQ;

                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                provider.ImportParameters(rsaparameters);
                return provider;

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                rd.Close();
            }
            return null;
        }

        private int GetInterSize(BinaryReader r)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;

            bt = r.ReadByte();

            if (bt!=0x02)
                return 0;
            
            bt = r.ReadByte();

            if (bt==0x81)
                count = r.ReadByte();
            else if (bt==0x82)
            {
                highbyte = r.ReadByte();
                lowbyte = r.ReadByte();
                byte[] cd = {lowbyte,highbyte,0x00,0x00};
                count = BitConverter.ToInt32(cd,0);
            }
            else
                count = bt;
            
            while (r.ReadByte()==0x00)
                count -= 1;

            r.BaseStream.Seek(-1,SeekOrigin.Current);

            return count;
        }


        public RSACryptoServiceProvider LoadPemPublicKeyFile(byte[] key)
        {
            try {
                byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,0x48,0x86, 0xF7, 0x0D , 0x01, 0x01, 0x01,0x05, 0x00 };
                byte[] seq = new byte[15];

                MemoryStream stream = new MemoryStream(key);
                BinaryReader rd = new BinaryReader(stream);

                byte bt = 0;
                ushort twobytes = 0;

                twobytes = rd.ReadUInt16();

                if (twobytes==0x8130)
                {
                    rd.ReadByte();
                }
                else if (twobytes==0x8230)
                {
                    rd.ReadUInt16();
                }
                else
                    return null;
                seq = rd.ReadBytes(15);
                if (!CompareByteArrays(seq,SeqOID))
                    return null;

                twobytes = rd.ReadUInt16();
                if (twobytes==0x8103)
                    rd.ReadByte();
                else if (twobytes==0x8203)
                    rd.ReadUInt16();
                else
                    return null;
                
                bt = rd.ReadByte();

                if (bt!=0x00)
                    return null;
                
                twobytes = rd.ReadUInt16();

                if (twobytes==0x8130)
                    rd.ReadByte();
                else if (twobytes==0x8230)
                    rd.ReadUInt16();
                else 
                    return null;

                twobytes = rd.ReadUInt16();
                byte lowbyte = 0x00;
                byte highbyte = 0x00;

                if (twobytes==0x8102)
                    lowbyte = rd.ReadByte();
                else if (twobytes==0x8202)
                {
                    highbyte = rd.ReadByte();
                    lowbyte = rd.ReadByte();
                }
                else 
                    return null;
                byte[] modint = new byte[]{lowbyte,highbyte,0x00,0x00};
                int modsize = BitConverter.ToInt32(modint,0);

                byte firstbyte = rd.ReadByte(); 
                rd.BaseStream.Seek(-1,SeekOrigin.Current);

                if (firstbyte==0x00)
                {
                    modsize -= 1;
                    rd.ReadByte();
                }

                byte[] modulus = rd.ReadBytes(modsize);
                if (rd.ReadByte()!=0x02)
                    return null;

                int expbytes = (int)rd.ReadByte();

                byte[] exponent = rd.ReadBytes(expbytes);

                RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
                RSAParameters parameters = new RSAParameters();
                parameters.Modulus = modulus;
                parameters.Exponent = exponent;
                provider.ImportParameters(parameters);

                return provider;

            }
            catch (Exception ex)
            {
                Console.WriteLine(" Exception " + ex.ToString());
                return null;
            }
        }
        private bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c!=b[i])
                return false;
                i++;
            }
            return true;
        }
    }
}