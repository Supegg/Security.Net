using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RSAUtil
{
    public class CertificateUtil
    {
        #region 生成证书
        /// <summary>   
        /// 根据指定的证书名和makecert全路径生成证书（包含公钥和私钥，并保存在MY存储区）   
        /// </summary>   
        /// <param name="subjectName"></param>   
        /// <param name="makecertPath"></param>   
        /// <returns></returns>   
        public static void MakeCertificate(string subjectName, string makecertPath)
        {
            subjectName = "CN=" + subjectName;
            string param = " -pe -ss my -n \"" + subjectName + "\" ";
            Process p = Process.Start(makecertPath, param);
            p.WaitForExit();
            p.Close();
        }
        #endregion

        #region 保存证书
        /// <summary>   
        /// 从WINDOWS证书存储区的个人MY区找到主题为subjectName的证书，   
        /// 并导出为pfx文件，同时为其指定一个密码   
        /// 并将证书从个人区删除(如果isDelFromstor为true)   
        /// </summary>   
        /// <param name="subjectName">证书主题，不包含CN=</param>   
        /// <param name="pfxFileName">pfx文件名</param>   
        /// <param name="password">pfx文件密码</param>   
        /// <param name="isDelFromStore">是否从存储区删除</param>   
        /// <returns></returns>   
        public static bool SaveToPfxFile(string subjectName, string pfxFileName,
            string password, bool isDelFromStore)
        {
            subjectName = "CN=" + subjectName;
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            X509Certificate2Collection storecollection = (X509Certificate2Collection)store.Certificates;
            foreach (X509Certificate2 x509 in storecollection)
            {
                if (x509.Subject == subjectName)
                {
                    byte[] pfxByte = x509.Export(X509ContentType.Pfx, password);
                    using (FileStream fileStream = new FileStream(pfxFileName, FileMode.Create))
                    {
                        // Write the data to the file, byte by byte.   
                        for (int i = 0; i < pfxByte.Length; i++)
                            fileStream.WriteByte(pfxByte[i]);
                        // Set the stream position to the beginning of the file.   
                        fileStream.Seek(0, SeekOrigin.Begin);
                        // Read and verify the data.   
                        for (int i = 0; i < fileStream.Length; i++)
                        {
                            if (pfxByte[i] != fileStream.ReadByte())
                            {
                                fileStream.Close();
                                throw new Exception("Export pfx error while verify the pfx file");
                            }
                        }
                        fileStream.Close();
                    }
                    if (isDelFromStore == true)
                        store.Remove(x509);
                }
            }
            store.Close();
            store = null;
            storecollection = null;
            return true;
        }

        /// <summary>   
        /// 从WINDOWS证书存储区的个人MY区找到主题为subjectName的证书，   
        /// 并导出为CER文件（即，只含公钥的）   
        /// </summary>   
        /// <param name="subjectName"></param>   
        /// <param name="cerFileName"></param>   
        /// <returns></returns>   
        public static bool SaveToCerFile(string subjectName, string cerFileName)
        {
            subjectName = "CN=" + subjectName;
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            X509Certificate2Collection storecollection = (X509Certificate2Collection)store.Certificates;
            foreach (X509Certificate2 x509 in storecollection)
            {
                if (x509.Subject == subjectName)
                {
                    //byte[] pfxByte = x509.Export(X509ContentType.Pfx, password);   
                    byte[] cerByte = x509.Export(X509ContentType.Cert);
                    using (FileStream fileStream = new FileStream(cerFileName, FileMode.Create))
                    {
                        // Write the data to the file, byte by byte.   
                        for (int i = 0; i < cerByte.Length; i++)
                            fileStream.WriteByte(cerByte[i]);
                        // Set the stream position to the beginning of the file.   
                        fileStream.Seek(0, SeekOrigin.Begin);
                        // Read and verify the data.   
                        for (int i = 0; i < fileStream.Length; i++)
                        {
                            if (cerByte[i] != fileStream.ReadByte())
                            {
                                fileStream.Close();
                                throw new Exception("Export CER error while verify the CERT file");
                            }
                        }
                        fileStream.Close();
                    }
                }
            }
            store.Close();
            store = null;
            storecollection = null;
            return true;
        }
        #endregion

        #region 载入证书
        /// <summary>   
        /// 根据私钥证书得到证书实体，得到实体后可以根据其公钥和私钥进行加解密   
        /// 加解密函数使用DEncrypt的RSACryption类   
        /// </summary>   
        /// <param name="pfxFileName"></param>   
        /// <param name="password"></param>   
        /// <returns></returns>   
        public static X509Certificate2 LoadFromPfxFile(string pfxFileName,
            string password)
        {
            return new X509Certificate2(pfxFileName, password, X509KeyStorageFlags.Exportable);
        }

        /// <summary>   
        /// 根据公钥证书，返回证书实体   
        /// </summary>   
        /// <param name="cerPath"></param>   
        public static X509Certificate2 LoadFromCerFile(string cerPath)
        {
            return new X509Certificate2(cerPath); ;
        }

        /// <summary>   
        /// 到My存储区获取证书   
        /// </summary>   
        /// <param name="subjectName"></param>   
        /// <returns></returns>   
        public static X509Certificate2 LoadFromStore(string subjectName)
        {
            subjectName = "CN=" + subjectName;
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            X509Certificate2Collection storecollection = (X509Certificate2Collection)store.Certificates;
            foreach (X509Certificate2 x509 in storecollection)
            {
                if (x509.Subject == subjectName)
                {
                    return x509;
                }
            }
            store.Close();
            store = null;
            storecollection = null;
            return null;
        }
        #endregion          
    }
}
