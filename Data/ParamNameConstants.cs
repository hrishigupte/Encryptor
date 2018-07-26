using System;


namespace Encryptor.Data
{
    public enum ParamNameConstantsEnum
    {
        Encrypt = 1,
        Decrypt = 2,
        InputFile = 3,
        OutputFile =4,
        KeyFile = 5,
        Base64 = 6,
        Binary = 7,
        Default = 8,
        Unknown = 10


    }
    public static class ParamNameConstants
    {
        public static ParamNameConstantsEnum GetParamType(string arg)
        {
            switch (arg)
            {
                case "--d":
                    return ParamNameConstantsEnum.Decrypt;
                case "--e":
                    return ParamNameConstantsEnum.Encrypt;
                case "--i":
                    return ParamNameConstantsEnum.InputFile;
                case "--o":
                    return ParamNameConstantsEnum.OutputFile;
                case "--k":
                    return ParamNameConstantsEnum.KeyFile;
                case "--base64":
                    return ParamNameConstantsEnum.Base64;
                case "--binary":
                    return ParamNameConstantsEnum.Binary;
                default:
                    return ParamNameConstantsEnum.Unknown;
            }

        } 


    }
}