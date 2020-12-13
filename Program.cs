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
            
            // Start the Bda Generator [NOTE; funcaptcha updates will require internal changes to BdaGen]
            BdaGen.Init();

            // create a new captcha instance
            var captcha = new SplitCaptcha("476068BF-9607-4799-B53D-966BE98E2B81", "Android", "https://roblox.com/", "login-field-data");
            
            // you can also use a proxy, like this
            // var captcha2 = new RotateCaptcha("476068BF-9607-4799-B53D-966BE98E2B81", "Windows", "https://roblox.com/", "login-field-data", new WebProxy("http://192.168.0.1", 8888), "https://roblox-api.arkoselabs.com");
            
            // you can directly manipulate this instance, but for now lets jus solve it
            // this implementation includes a makeshift manual solver, refer to Solver.cs
            captcha.Solve();
            
            Console.WriteLine($"success? {captcha.success}, token: {captcha.token}");
        }
    }
}