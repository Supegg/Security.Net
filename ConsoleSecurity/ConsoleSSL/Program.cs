using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ConsoleSSL
{
    class Program
    {
        /// <summary>
        /// SSL 加密通信
        /// makecert 制作证书
        /// MMC 的证书单元导入导出证书
        /// http://www.it165.net/pro/html/201305/5826.html
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            HttpsRequest();

            //Parallel.For(0, 1, i =>
            //{
            //    server();
            //});
            Task.Factory.StartNew(() =>
            {
                server();
            });
            Console.WriteLine("SSL server starts...");

            do
            {
                Console.Write("Say something: ");
                string hi = Console.ReadLine();
                if(hi.ToUpper() == "QUIT")
                {
                    break;
                }
                client(hi + " ");
            } while (true);
        }

        #region CS ssl
        static void server()
        {
            X509Certificate ServerCertificate = new X509Certificate("SslSocket.pfx", "123456");
            TcpListener listener = new TcpListener(System.Net.IPAddress.Any, 17170);
            listener.Start();

            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();
                echo(client);
            }

        }

        private static void echo(TcpClient client)
        {
            SslStream sslStream = new SslStream(client.GetStream(), true);

            try
            {
                sslStream.AuthenticateAsServer(new X509Certificate("SslSocket.pfx", "123456"), true, SslProtocols.Tls, true);

                byte[] buf = new byte[1024];
                int len = sslStream.Read(buf, 0, buf.Length);
                string message = Encoding.UTF8.GetString(buf,0,len);
                Console.WriteLine("Client: {0}", message);
                string answer = string.Format("Banaaaana {0}", message);
                sslStream.Write(Encoding.UTF8.GetBytes(answer));
            }
            catch (Exception ex)
            {
                sslStream.Close();
                client.Close();
                Console.WriteLine(ex);
                return;
            }
            finally
            {
                sslStream.Close();
                client.Close();
            }
        }

        static void client(string hi)
        {
            TcpClient client = new TcpClient("127.0.0.1", 17170);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            X509CertificateCollection certs = new X509CertificateCollection();
            //web服务器路径
            //X509Certificate cert = X509Certificate.CreateFromCertFile(HttpContext.Current.Server.MapPath(@"~/cer/SslSocket.cer"));
            //本地文件
            X509Certificate cert = X509Certificate.CreateFromCertFile("SslSocket.cer");
            //从本机/当前用户的证书管理器获取
            //X509Store store = new X509Store("My", StoreLocation.CurrentUser);
            //store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            //X509Certificate cert = new X509Certificate(store.Certificates.Find(X509FindType.FindBySubjectName,"SslSocket",true)[0]);

            certs.Add(cert);
            try
            {
                sslStream.AuthenticateAsClient("SslSocket", certs, System.Security.Authentication.SslProtocols.Tls, true);
            }
            catch(Exception ex)
            {
                client.Close();
                Console.WriteLine(ex);
                return;
            }

            byte[] messsage = Encoding.UTF8.GetBytes(hi);
            sslStream.Write(messsage);
            sslStream.Flush();
            byte[] buf = new byte[1024];
            int len = sslStream.Read(buf, 0, buf.Length);
            Console.WriteLine("Server: {0}", Encoding.UTF8.GetString(buf, 0, len));
            client.Close();
        }

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;
            return false;
        }
        #endregion

        #region https
        public static void HttpsRequest()
        {
            //类似浏览器确认证书合法方法的绑定
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://cn.bing.com/");

            string param = "test=true";
            byte[] bs = Encoding.UTF8.GetBytes(param);

            //这2句代码表示如果要求客户端证书，将客户端证书加入request，不需要客户端证书的https请求则不需要此代码
            X509Certificate cer = new X509Certificate("bing.cer");
            request.ClientCertificates.Add(cer);

            request.UserAgent = "test";
            request.Method = "post";

            using (Stream reqStram = request.GetRequestStream())
            {
                reqStram.Write(bs, 0, bs.Length);
            }

            using (HttpWebResponse response = request.GetResponse() as HttpWebResponse)
            {
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    string bing = reader.ReadToEnd();
                    Console.WriteLine("Bingo ssl web request");
                }
            }
        }

        //该方法用于验证服务器证书是否合法，当然可以直接返回true来表示验证永远通过。服务器证书具体内容在参数certificate中。可根据个人需求验证
        //该方法在request.GetResponse()时触发
        public static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;
            return false;
        }
        #endregion
    }
}
