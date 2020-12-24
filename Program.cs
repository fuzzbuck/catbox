using System;
using System.Net;
using catbox.Arkose;

namespace catbox
{
    class Program
    {
        static void Main(string[] args)
        {
            // RestSharp shenanigans
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            ServicePointManager.UseNagleAlgorithm = false;
            
            BdaGen.Init();
            
            var captcha = new SplitCaptcha("947319BF-9607-4799-B53D-472BE98E2B19", "Android");
            captcha.Solve();
            
            Console.WriteLine($"success? {captcha.success}, token: {captcha.token}");
        }
    }
}