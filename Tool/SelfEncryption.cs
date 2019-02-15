using System;
using System.Security.Cryptography;
using System.Text;

namespace Tool
{
    public class SelfEncryption
    {
        #region 公钥-私钥
        public static string publicKey = "<RSAKeyValue><Modulus>pFU/qTV09AdDl7TjrJv8kusLEuF9cdATGnL9zwr4yyyvaYZ4NWwxV8zuEguS5CdL1gExT/68lxd5apPl69D79fnSfs8HNCIZueJfqW78jSVUh2mtcNQiEis/ZvCG2OCL3ainHrkggmVT1Q9SoIJWP++iabz+ig6xm+22S57eI/U=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        public static string privateKey = "<RSAKeyValue><Modulus>pFU/qTV09AdDl7TjrJv8kusLEuF9cdATGnL9zwr4yyyvaYZ4NWwxV8zuEguS5CdL1gExT/68lxd5apPl69D79fnSfs8HNCIZueJfqW78jSVUh2mtcNQiEis/ZvCG2OCL3ainHrkggmVT1Q9SoIJWP++iabz+ig6xm+22S57eI/U=</Modulus><Exponent>AQAB</Exponent><P>zAWIevtYRcE5P8RhQjOfI5TIRTSSOi0BVOAWU4lV/eUA4dAh4irdn6U5DnLDjLprSgXk6UrBVuY7lXplXL4Kvw==</P><Q>zjMwmlyU8NylRwpfaRcpISaQC2l7TjTPaWc1JYlecnrkczhJNr+NVyEd80R6eXQZNw6ZYRBwAIqwhBeSqUSCSw==</Q><DP>b0IZMk+8zJVZfe++xhZWk1XAfRT1JSqDzmBBbJ65OTLX70zMHYUYxMWaPsnQ3/6NIZnjQmGU26nEFnjfq9qrCw==</DP><DQ>GhLQ/4PbdYWBBLWkEObT1ZRJvJeu9tmorHxXdRKktbcicgtY/qpEFhNi9SLglcD/ez3GWUa50ue2oE1Wxz6Zdw==</DQ><InverseQ>Gsxx0d/sBa4Y2Yt6QAgR1P4wtUN7d6k9M6Xn/KCK2m9EC06DHQythbPbmTuC+M27PqX3ffIguWWaIpgGIhQ8Tg==</InverseQ><D>kc19TUE7wiQLybdZ5dUEdMoMKjVc2rU1rdrm7GMcuQ+tluATGbsj0HXnqKUSMFHZTEgEm6g1ZY0TUgdlESR716dWxQLpy++1FbwZRxwSRs7LuujuKTiVnLb1L1F9/7JyoMJ4ZYE5XPLeoT+rZOcpTXhafNNasKTuxNJhZLaT5kU=</D></RSAKeyValue>";
        #endregion





        #region 加密
        //############################################################################## 
        //RSA 方式加密 
        //KEY必须是XML的形式,返回的是字符串 
        //该加密方式有长度限制的！
        //############################################################################## 

        /// <summary>
        /// RSA的加密函数
        /// </summary>
        /// <param name="xmlPublicKey">公钥</param>
        /// <param name="encryptString">待加密的字符串</param>
        /// <returns></returns>
        public string RSAEncrypt(string xmlPublicKey, string encryptString)
        {
            try
            {
                byte[] PlainTextBArray;
                byte[] CypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlPublicKey);
                PlainTextBArray = (new UnicodeEncoding()).GetBytes(encryptString);
                CypherTextBArray = rsa.Encrypt(PlainTextBArray, false);
                Result = Convert.ToBase64String(CypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// RSA的加密函数 
        /// </summary>
        /// <param name="xmlPublicKey">公钥</param>
        /// <param name="EncryptString">待加密的字节数组</param>
        /// <returns></returns>
        public string RSAEncrypt(string xmlPublicKey, byte[] EncryptString)
        {
            try
            {
                byte[] CypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlPublicKey);
                CypherTextBArray = rsa.Encrypt(EncryptString, false);
                Result = Convert.ToBase64String(CypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion







        #region 解密
        /// <summary>
        /// RSA的解密函数
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="decryptString">待解密的字符串</param>
        /// <returns></returns>
        public string RSADecrypt(string xmlPrivateKey, string decryptString)
        {
            try
            {
                byte[] PlainTextBArray;
                byte[] DypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlPrivateKey);
                PlainTextBArray = Convert.FromBase64String(decryptString);
                DypherTextBArray = rsa.Decrypt(PlainTextBArray, false);
                Result = (new UnicodeEncoding()).GetString(DypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// RSA的解密函数 
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="DecryptString">待解密的字节数组</param>
        /// <returns></returns>
        public string RSADecrypt(string xmlPrivateKey, byte[] DecryptString)
        {
            try
            {
                byte[] DypherTextBArray;
                string Result;
                System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xmlPrivateKey);
                DypherTextBArray = rsa.Decrypt(DecryptString, false);
                Result = (new UnicodeEncoding()).GetString(DypherTextBArray);
                return Result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion





        #region 验签
        /// <summary>
        /// 数字签名
        /// </summary>
        /// <param name="plaintext">原文</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>签名</returns>
        public string HashAndSignString(string plaintext, string privateKey)
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
        public bool VerifySigned(string plaintext, string SignedData, string publicKey)
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
        #endregion
    }
}
