using System;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionTest
{
    class Program
    {
        static void Main(string[] args)
        {

            Tool.RSACryption te = new Tool.RSACryption();
            Tool.SelfEncryption te1 = new Tool.SelfEncryption();


            var en = te1.RSAEncrypt(Tool.SelfEncryption.publicKey, "qweqweqwe");

            var de = te1.RSADecrypt(Tool.SelfEncryption.privateKey, en);

            var sign = te1.HashAndSignString("qweqweqwe", Tool.SelfEncryption.privateKey);

            var b = te1.VerifySigned("qweqweqwe1", sign, Tool.SelfEncryption.publicKey);

            Console.ReadKey();
        }
    }
}
