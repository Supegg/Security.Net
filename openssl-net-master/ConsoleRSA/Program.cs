using System;
using System.Text;
using OpenSSL.Crypto;
using OpenSSL.Core;
using System.IO;
using System.Diagnostics;
using System.Security;

namespace ConsoleRSA
{
    class Program
    {
        static void Main(string[] args)
        {
            //rsaTime();

            BIO b = BIO.MemoryBuffer();

            //RSA p = RSA.FromPublicKey(BIO.File("test_pub.pem", "r"));
            RSA p = RSA.FromPublicKey(new BIO(@"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvJGESYl8IXFowaLLcMAmGMKRU
UrnC5+ZjL/u6UE+U3Hvz1cJ11npfe4xou0QIwc0q+PY63cSEYa2cYGLhIsKCi3RM
RG2lyLCNFs8BlzL8ZryWBsNf0ejXE+qUS5nbJ2UPO1/ixxGkJ8LgpWxxqK2Fpm/f
Nugl3Cws99Cg0kK9+QIDAQAB
-----END PUBLIC KEY-----"));
            File.WriteAllBytes("hello.de", p.PublicEncrypt(File.ReadAllBytes("hello"), RSA.Padding.PKCS1));

            RSA s = RSA.FromPrivateKey(BIO.File("test.des", "r"));
            byte[] de = s.PrivateDecrypt(File.ReadAllBytes("hello.en"), RSA.Padding.PKCS1);//, RSA.Padding.SSLv23);
            string v = Encoding.UTF8.GetString(de);
            Console.WriteLine(v);

            Console.Read();
        }

        /// <summary>
        /// 1ms or less
        /// </summary>
        static void rsaTime()
        {
            RSA p = RSA.FromPublicKey(BIO.File("test_pub.pem", "r"));
            RSA s = RSA.FromPrivateKey(BIO.File("test.pem", "r"));
            Stopwatch watch = new Stopwatch();

            do
            {
                watch.Restart();
                Console.WriteLine(Encoding.UTF8.GetString(s.PrivateDecrypt(p.PublicEncrypt(Encoding.UTF8.GetBytes("0123456789ABCDEF"), RSA.Padding.PKCS1), RSA.Padding.PKCS1)) + "\t" + watch.ElapsedMilliseconds);
            } while (true);
        }
    }
}
