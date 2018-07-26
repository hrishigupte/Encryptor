using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Encryptor.Data;
using Encryptor.Util;

namespace Encryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            string keyfile = "", inputFileName = "", outputFileName = "";
            ParamNameConstantsEnum encodingPreference = ParamNameConstantsEnum.Default;
            if (args==null || args.Length==0)
            {
                Console.WriteLine("No Params provided");
            }
            
            ParamNameConstantsEnum optype = ParamNameConstants.GetParamType(args[0]);
            switch (optype)
            {
                case ParamNameConstantsEnum.Unknown:

                    Console.WriteLine("Operation not specified as first parameter " + Environment.NewLine +
                    " Operation switches --d for Decrypt " + Environment.NewLine +
                    " --e for Encrypt " + Environment.NewLine);
                    break;
                case ParamNameConstantsEnum n when (n==ParamNameConstantsEnum.Encrypt|| n==ParamNameConstantsEnum.Decrypt):
                    int argcounter = 1, argsreceived = 0;
                    while (argsreceived<3)
                    {
                        try 
                        {
                            if (args[argcounter].Contains("--"))
                            {
                                ParamNameConstantsEnum argtype = ParamNameConstants.GetParamType(args[argcounter]);
                                switch (argtype)
                                {   
                                    case ParamNameConstantsEnum.Unknown:
                                        Console.WriteLine("Unknown parameter");
                                        argcounter++;
                                        break;
                                    case ParamNameConstantsEnum.InputFile:
                                        argcounter++;
                                        if (String.IsNullOrEmpty(args[argcounter]))
                                        {
                                            Console.WriteLine("Input file not specified");
                                            throw new ArgumentNullException("Input file not specified");
                                        }
                                        else 
                                        {
                                            inputFileName = args[argcounter];
                                            argsreceived++;
                                        }
                                        break;
                                    case ParamNameConstantsEnum.OutputFile:
                                         argcounter++;
                                        if (String.IsNullOrEmpty(args[argcounter]))
                                        {
                                            Console.WriteLine("Output file not specified");
                                            throw new ArgumentNullException("Output file not specified");
                                        }
                                        else 
                                        {
                                            outputFileName = args[argcounter];
                                            argsreceived++;
                                        }
                                        break;
                                    case ParamNameConstantsEnum.KeyFile:
                                         argcounter++;
                                        if (String.IsNullOrEmpty(args[argcounter]))
                                        {
                                            Console.WriteLine("Key file not specified");
                                            throw new ArgumentNullException("Key file not specified");
                                        }
                                        else 
                                        {
                                            keyfile = args[argcounter];
                                            argsreceived++;
                                        }
                                        break;
                                    case ParamNameConstantsEnum pref when(pref == ParamNameConstantsEnum.Binary || pref ==ParamNameConstantsEnum.Base64):
                                        encodingPreference = pref;
                                        break;
                                }
                            }
                            argcounter++;
                            if (args.Length <= argcounter)
                                break;
                        }
                        catch (ArgumentOutOfRangeException aorex)
                        {
                            Console.WriteLine("All required information was not provided " + aorex.ToString());
                            break;
                        }
                        catch (ArgumentNullException)
                        {
                            Console.WriteLine("All information required for operation was not specified correctly");
                        }
                    }
                    if (argsreceived==3)
                    {
                        bool success = new FileEncryptor().PerformOperation(keyfile,inputFileName,outputFileName,optype,encodingPreference);
                        Console.WriteLine(" Operation was {0}", success? "Successful": "Unsuccessful");
                    }
                    break;
                default:
                    Console.WriteLine("Something went wrong, program will now exit..");
                    break;
            }
        }
            
    }
}

