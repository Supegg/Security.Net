using System;
using System.Collections.Generic;
using System.Linq;
//using System.Numerics;
using System.Security.Cryptography;
using System.Text;


namespace RSAUtil
{
    public class RsaUtil
    {
        /// <summary>
        /// RSA算法对象，此处主要用于获取密钥对
        /// </summary>
        private RSACryptoServiceProvider rsaService;

        public RsaUtil(int keySize =1024)
        {
            rsaService = new RSACryptoServiceProvider(keySize);
        }

        public RsaUtil(string key)
        {
            rsaService = new RSACryptoServiceProvider();
            rsaService.FromXmlString(key);
        }

        /// <summary>
        /// 取得密钥
        /// </summary>
        /// <param name="includPrivateKey">true：包含私钥   false：不包含私钥</param>
        /// <returns></returns>
        public string ToXmlString(bool includPrivateKey)
        {
            if (includPrivateKey)
            {
                return rsaService.ToXmlString(true);
            }
            else
            {
                return rsaService.ToXmlString(false);
            }
        }

        /// <summary>
        /// 取得密钥对
        /// </summary>
        /// <param name="n">大整数</param>
        /// <param name="e">公钥</param>
        /// <param name="d">密钥</param>
        public void GetKey(out string n, out string e, out string d)
        {
            byte[] pseudoPrime1 = {
                        (byte)0x85, (byte)0x84, (byte)0x64, (byte)0xFD, (byte)0x70, (byte)0x6A,
                        (byte)0x9F, (byte)0xF0, (byte)0x94, (byte)0x0C, (byte)0x3E, (byte)0x2C,
                        (byte)0x74, (byte)0x34, (byte)0x05, (byte)0xC9, (byte)0x55, (byte)0xB3,
                        (byte)0x85, (byte)0x32, (byte)0x98, (byte)0x71, (byte)0xF9, (byte)0x41,
                        (byte)0x21, (byte)0x5F, (byte)0x02, (byte)0x9E, (byte)0xEA, (byte)0x56,
                        (byte)0x8D, (byte)0x8C, (byte)0x44, (byte)0xCC, (byte)0xEE, (byte)0xEE,
                        (byte)0x3D, (byte)0x2C, (byte)0x9D, (byte)0x2C, (byte)0x12, (byte)0x41,
                        (byte)0x1E, (byte)0xF1, (byte)0xC5, (byte)0x32, (byte)0xC3, (byte)0xAA,
                        (byte)0x31, (byte)0x4A, (byte)0x52, (byte)0xD8, (byte)0xE8, (byte)0xAF,
                        (byte)0x42, (byte)0xF4, (byte)0x72, (byte)0xA1, (byte)0x2A, (byte)0x0D,
                        (byte)0x97, (byte)0xB1, (byte)0x31, (byte)0xB3,
                };

            byte[] pseudoPrime2 = {
                        (byte)0x99, (byte)0x98, (byte)0xCA, (byte)0xB8, (byte)0x5E, (byte)0xD7,
                        (byte)0xE5, (byte)0xDC, (byte)0x28, (byte)0x5C, (byte)0x6F, (byte)0x0E,
                        (byte)0x15, (byte)0x09, (byte)0x59, (byte)0x6E, (byte)0x84, (byte)0xF3,
                        (byte)0x81, (byte)0xCD, (byte)0xDE, (byte)0x42, (byte)0xDC, (byte)0x93,
                        (byte)0xC2, (byte)0x7A, (byte)0x62, (byte)0xAC, (byte)0x6C, (byte)0xAF,
                        (byte)0xDE, (byte)0x74, (byte)0xE3, (byte)0xCB, (byte)0x60, (byte)0x20,
                        (byte)0x38, (byte)0x9C, (byte)0x21, (byte)0xC3, (byte)0xDC, (byte)0xC8,
                        (byte)0xA2, (byte)0x4D, (byte)0xC6, (byte)0x2A, (byte)0x35, (byte)0x7F,
                        (byte)0xF3, (byte)0xA9, (byte)0xE8, (byte)0x1D, (byte)0x7B, (byte)0x2C,
                        (byte)0x78, (byte)0xFA, (byte)0xB8, (byte)0x02, (byte)0x55, (byte)0x80,
                        (byte)0x9B, (byte)0xC2, (byte)0xA5, (byte)0xCB,
                };


            BigInteger bi_p = new BigInteger(pseudoPrime1);
            BigInteger bi_q = new BigInteger(pseudoPrime2);
            BigInteger bi_pq = (bi_p - 1) * (bi_q - 1);
            BigInteger bi_n = bi_p * bi_q;
            Random rand = new Random();
            BigInteger bi_e = bi_pq.genCoPrime(512, rand);
            BigInteger bi_d = bi_e.modInverse(bi_pq);
            n = bi_n.ToHexString();
            e = bi_e.ToHexString();
            d = bi_d.ToHexString();
        }

        #region Encrypt&Decrypt
        /// <summary>
        /// 通过公钥加密
        /// </summary>
        /// <param name="dataStr">待加密字符串</param>
        /// <returns>加密结果</returns>
        public byte[] EncryptByPublicKey(string dataStr)
        {
            //取得公钥参数
            RSAParameters rsaparameters = rsaService.ExportParameters(false);
            byte[] keyN = rsaparameters.Modulus;
            byte[] keyE = rsaparameters.Exponent;
            //大整数N
            BigInteger biN = new BigInteger(keyN);
            //公钥大素数
            BigInteger biE = new BigInteger(keyE);
            //加密
            return EncryptString(dataStr, biE, biN);
        }

        /// <summary>
        /// 通过公钥加密
        /// </summary>
        /// <param name="dataStr">待加密字符串</param>
        /// <param name="n">大整数n</param>
        /// <param name="e">公钥</param>
        /// <returns>加密结果</returns>
        public byte[] EncryptByPublicKey(string dataStr, string n, string e)
        {
            //大整数N
            BigInteger biN = new BigInteger(n, 16);
            //公钥大素数
            BigInteger biE = new BigInteger(e, 16);
            //加密
            return EncryptString(dataStr, biE, biN);
        }

        /// <summary>
        /// 通过私钥解密
        /// </summary>
        /// <param name="dataBytes">待解密字符数组</param>
        /// <returns>解密结果</returns>
        public string DecryptByPrivateKey(byte[] dataBytes)
        {
            //取得私钥参数
            RSAParameters rsaparameters = rsaService.ExportParameters(true);
            byte[] keyN = rsaparameters.Modulus;
            byte[] keyD = rsaparameters.D;
            //大整数N
            BigInteger biN = new BigInteger(keyN);
            //私钥大素数
            BigInteger biD = new BigInteger(keyD);
            //解密
            return DecryptBytes(dataBytes, biD, biN);
        }

        /// <summary>
        /// 通过私钥解密
        /// </summary>
        /// <param name="dataBytes">待解密字符数组</param>
        /// <param name="n">大整数n</param>
        /// <param name="d">私钥</param>
        /// <returns>解密结果</returns>
        public string DecryptByPrivateKey(byte[] dataBytes, string n, string d)
        {
            //大整数N
            BigInteger biN = new BigInteger(n, 16);
            //私钥大素数
            BigInteger biD = new BigInteger(d, 16);
            //解密
            return DecryptBytes(dataBytes, biD, biN);
        }

        /// <summary>
        /// 通过私钥加密
        /// </summary>
        /// <param name="dataStr">待加密字符串</param>
        /// <returns>加密结果</returns>
        public byte[] EncryptByPrivateKey(string dataStr)
        {
            //取得私钥参数
            RSAParameters rsaparameters = rsaService.ExportParameters(true);
            byte[] keyN = rsaparameters.Modulus;
            byte[] keyD = rsaparameters.D;
            //大整数N
            BigInteger biN = new BigInteger(keyN);
            //私钥大素数
            BigInteger biD = new BigInteger(keyD);
            //加密
            return EncryptString(dataStr, biD, biN);
        }

        /// <summary>
        /// 通过私钥加密
        /// </summary>
        /// <param name="dataStr">待加密字符串</param>
        /// <param name="n">大整数n</param>
        /// <param name="d">私钥</param>
        /// <returns>加密结果</returns>
        public byte[] EncryptByPrivateKey(string dataStr, string n, string d)
        {
            //大整数N
            BigInteger biN = new BigInteger(n, 16);
            //私钥大素数
            BigInteger biD = new BigInteger(d, 16);
            //加密
            return EncryptString(dataStr, biD, biN);
        }
        /// <summary>
        /// 通过公钥解密
        /// </summary>
        /// <param name="dataBytes">待解密字符数组</param>
        /// <returns>解密结果</returns>
        public string DecryptByPublicKey(byte[] dataBytes)
        {
            //取得公钥参数
            RSAParameters rsaparameters = rsaService.ExportParameters(false);
            byte[] keyN = rsaparameters.Modulus;
            byte[] keyE = rsaparameters.Exponent;
            //大整数N
            BigInteger biN = new BigInteger(keyN);
            //公钥大素数
            BigInteger biE = new BigInteger(keyE);
            //解密
            return DecryptBytes(dataBytes, biE, biN);
        }

        /// <summary>
        /// 通过公钥解密
        /// </summary>
        /// <param name="dataBytes">待加密字符串</param>
        /// <param name="n">大整数n</param>
        /// <param name="e">公钥</param>
        /// <returns>解密结果</returns>
        public string DecryptByPublicKey(byte[] dataBytes, string n, string e)
        {
            //大整数N
            BigInteger biN = new BigInteger(n, 16);
            //公钥大素数
            BigInteger biE = new BigInteger(e, 16);
            //解密
            return DecryptBytes(dataBytes, biE, biN);
        }

        /// <summary>
        /// 加密字符串
        /// </summary>
        /// <param name="dataStr">待加密字符串</param>
        /// <param name="keyNmu">密钥大素数</param>
        /// <param name="nNum">大整数N</param>
        /// <returns>加密结果</returns>
        private byte[] EncryptString(string dataStr, BigInteger keyNum, BigInteger nNum)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(dataStr);
            int len = bytes.Length;
            int len1 = 0;
            int blockLen = 0;
            if ((len % 120) == 0)
                len1 = len / 120;
            else
                len1 = len / 120 + 1;
            List<byte> tempbytes = new List<byte>();
            for (int i = 0; i < len1; i++)
            {
                if (len >= 120)
                {
                    blockLen = 120;
                }
                else
                {
                    blockLen = len;
                }
                byte[] oText = new byte[blockLen];
                Array.Copy(bytes, i * 120, oText, 0, blockLen);
                string res = Encoding.UTF8.GetString(oText);
                BigInteger biText = new BigInteger(oText);
                BigInteger biEnText = biText.modPow(keyNum, nNum);
                //补位
                //byte[] testbyte = null;
                string resultStr = biEnText.ToHexString();
                if (resultStr.Length < 256)
                {
                    while (resultStr.Length != 256)
                    {
                        resultStr = "0" + resultStr;
                    }
                }
                byte[] returnBytes = new byte[128];
                for (int j = 0; j < returnBytes.Length; j++)
                    returnBytes[j] = Convert.ToByte(resultStr.Substring(j * 2, 2), 16);
                tempbytes.AddRange(returnBytes);
                len -= blockLen;
            }
            return tempbytes.ToArray();
        }

        /// <summary>
        /// 解密字节数组
        /// </summary>
        /// <param name="dataBytes">待解密字节数组</param>
        /// <param name="KeyNum">密钥大素数</param>
        /// <param name="nNum">大整数N</param>
        /// <returns>解密结果</returns>
        private string DecryptBytes(byte[] dataBytes, BigInteger KeyNum, BigInteger nNum)
        {
            int len = dataBytes.Length;
            int len1 = 0;
            int blockLen = 0;
            if (len % 128 == 0)
            {
                len1 = len / 128;
            }
            else
            {
                len1 = len / 128 + 1;
            }
            List<byte> tempbytes = new List<byte>();
            for (int i = 0; i < len1; i++)
            {
                if (len >= 128)
                {
                    blockLen = 128;
                }
                else
                {
                    blockLen = len;
                }
                byte[] oText = new byte[blockLen];
                Array.Copy(dataBytes, i * 128, oText, 0, blockLen);
                BigInteger biText = new BigInteger(oText);
                BigInteger biEnText = biText.modPow(KeyNum, nNum);
                byte[] testbyte = biEnText.getBytes();
                string str = Encoding.UTF8.GetString(testbyte);
                tempbytes.AddRange(testbyte);
                len -= blockLen;
            }
            return System.Text.Encoding.UTF8.GetString(tempbytes.ToArray());
        }
        #endregion
    }
}
