using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Tool
{
    public class Encryption
    {
        /// <summary>
        /// MD5加密
        /// </summary>
        /// <param name="myString">密码</param>
        /// <returns></returns>
        public static string GetMD5(string myString)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] fromData = System.Text.Encoding.Unicode.GetBytes(myString);
            byte[] targetData = md5.ComputeHash(fromData);
            string byte2String = null;
            for (int i = 0; i < targetData.Length; i++)
            {
                byte2String += targetData[i].ToString("x");
            }
            return byte2String;
        }



        #region  对称算法-加密解密
        //公钥
        private const string keyString = "MudbA1mpYXw=";
        //向量
        private const string ivString = "YuanN3+Cb6M=";


        #region 加密和解密字符串
        /// <summary>
        /// 加密字符串
        /// </summary>
        /// <param name="Value">加密前的字符串</param>
        ///  <param name="privateKey">用户持有的私钥</param>
        /// <returns>加密后返回的字符串</returns>
        public static string EncryptString(string Value)
        {
            //key=公钥+私钥
            string key = keyString;//privateKey+

            SymmetricAlgorithm mCSP = new DESCryptoServiceProvider();

            mCSP.Key = Convert.FromBase64String(key);
            mCSP.IV = Convert.FromBase64String(ivString);

            ICryptoTransform ct;
            MemoryStream ms;
            CryptoStream cs;
            byte[] byt;

            ct = mCSP.CreateEncryptor(mCSP.Key, mCSP.IV);

            byt = Encoding.UTF8.GetBytes(Value);

            ms = new MemoryStream();
            cs = new CryptoStream(ms, ct, CryptoStreamMode.Write);
            cs.Write(byt, 0, byt.Length);
            cs.FlushFinalBlock();

            cs.Close();

            return Convert.ToBase64String(ms.ToArray());

        }
        /// <summary>
        /// 解密字符串
        /// </summary>
        /// <param name="Value">解密前的字符串</param>
        /// <returns>返回解密后的字符串</returns>
        public static string DecryptString(string Value)
        {
            try
            {
                //key=公钥+私钥
                string key = keyString;//privateKey+

                SymmetricAlgorithm mCSP = new DESCryptoServiceProvider();
                mCSP.Key = Convert.FromBase64String(key);
                mCSP.IV = Convert.FromBase64String(ivString);

                ICryptoTransform ct;
                MemoryStream ms;
                CryptoStream cs;
                byte[] byt;

                ct = mCSP.CreateDecryptor(mCSP.Key, mCSP.IV);

                byt = Convert.FromBase64String(Value);

                ms = new MemoryStream();
                cs = new CryptoStream(ms, ct, CryptoStreamMode.Write);
                cs.Write(byt, 0, byt.Length);
                cs.FlushFinalBlock();

                cs.Close();

                return Encoding.UTF8.GetString(ms.ToArray());
            }
            catch (Exception e)
            {
                return "-100";

            }

        }
        #endregion
        #endregion

        #region 非对称算法-加密解密
        /// <summary>
        /// 数字签名
        /// </summary>
        /// <param name="plaintext">原文</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>签名</returns>
        public static string HashAndSignString(string plaintext, string privateKey)
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes(plaintext);

            using (RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider())
            {
                RSAalg.FromXmlString(privateKey);
                //使用SHA1进行摘要算法，生成签名
                byte[] encryptedData = RSAalg.SignData(dataToEncrypt, new SHA1CryptoServiceProvider());
                return Convert.ToBase64String(encryptedData);
            }
        }

        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="plaintext">原文</param>
        /// <param name="SignedData">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public static bool VerifySigned(string plaintext, string SignedData, string publicKey)
        {
            using (RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider())
            {
                RSAalg.FromXmlString(publicKey);
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                byte[] dataToVerifyBytes = ByteConverter.GetBytes(plaintext);
                byte[] signedDataBytes = Convert.FromBase64String(SignedData);
                return RSAalg.VerifyData(dataToVerifyBytes, new SHA1CryptoServiceProvider(), signedDataBytes);
            }
        }

        public static void TestSign()
        {
            string originalData = "文章不错，这是我的签名：奥巴马！";
            Console.WriteLine("签名数为：{0}", originalData);
            //string privateKey = "";
            //string publicKey = "";
            //CreateRSAKey(out privateKey, out publicKey);
            //1、生成签名，通过摘要算法
            string signedData = HashAndSignString(originalData, "<RSAKeyValue><Modulus>pFU/qTV09AdDl7TjrJv8kusLEuF9cdATGnL9zwr4yyyvaYZ4NWwxV8zuEguS5CdL1gExT/68lxd5apPl69D79fnSfs8HNCIZueJfqW78jSVUh2mtcNQiEis/ZvCG2OCL3ainHrkggmVT1Q9SoIJWP++iabz+ig6xm+22S57eI/U=</Modulus><Exponent>AQAB</Exponent><P>zAWIevtYRcE5P8RhQjOfI5TIRTSSOi0BVOAWU4lV/eUA4dAh4irdn6U5DnLDjLprSgXk6UrBVuY7lXplXL4Kvw==</P><Q>zjMwmlyU8NylRwpfaRcpISaQC2l7TjTPaWc1JYlecnrkczhJNr+NVyEd80R6eXQZNw6ZYRBwAIqwhBeSqUSCSw==</Q><DP>b0IZMk+8zJVZfe++xhZWk1XAfRT1JSqDzmBBbJ65OTLX70zMHYUYxMWaPsnQ3/6NIZnjQmGU26nEFnjfq9qrCw==</DP><DQ>GhLQ/4PbdYWBBLWkEObT1ZRJvJeu9tmorHxXdRKktbcicgtY/qpEFhNi9SLglcD/ez3GWUa50ue2oE1Wxz6Zdw==</DQ><InverseQ>Gsxx0d/sBa4Y2Yt6QAgR1P4wtUN7d6k9M6Xn/KCK2m9EC06DHQythbPbmTuC+M27PqX3ffIguWWaIpgGIhQ8Tg==</InverseQ><D>kc19TUE7wiQLybdZ5dUEdMoMKjVc2rU1rdrm7GMcuQ+tluATGbsj0HXnqKUSMFHZTEgEm6g1ZY0TUgdlESR716dWxQLpy++1FbwZRxwSRs7LuujuKTiVnLb1L1F9/7JyoMJ4ZYE5XPLeoT+rZOcpTXhafNNasKTuxNJhZLaT5kU=</D></RSAKeyValue>");
            Console.WriteLine("数字签名:{0}", signedData);

            //2、验证签名
            bool verify = VerifySigned(originalData, signedData, "<RSAKeyValue><Modulus>pFU/qTV09AdDl7TjrJv8kusLEuF9cdATGnL9zwr4yyyvaYZ4NWwxV8zuEguS5CdL1gExT/68lxd5apPl69D79fnSfs8HNCIZueJfqW78jSVUh2mtcNQiEis/ZvCG2OCL3ainHrkggmVT1Q9SoIJWP++iabz+ig6xm+22S57eI/U=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>");
            Console.WriteLine("签名验证结果：{0}", verify);
        }

        /// <summary>
        /// 生成公钥、私钥
        /// </summary>
        /// <param name="PrivateKeyPath">私钥文件保存路径，包含文件名</param>
        /// <param name="PublicKeyPath">公钥文件保存路径，包含文件名</param>
        public static void CreateRSAKey(out string privateKey, out string publicKey)
        {
            RSACryptoServiceProvider.UseMachineKeyStore = true;
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            privateKey = provider.ToXmlString(true);
            publicKey = provider.ToXmlString(false);
        }
        #endregion
    }
}