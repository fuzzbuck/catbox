using System;
using System.IO;

namespace catbox
{
    public static class Solver
    {
        
        // Asks an user for an answer to a challenge.
        // NOTE; I am not responsible for whatever you do with this,
        // it is against funcaptchas' Terms of Service to automate & abuse this process.
        
        public static string GetSolution(string b64image)
        {
            string path = Guid.NewGuid().ToString("N").Substring(0, 4) + ".png";
            FileStream file = File.Create(path);

            var img = Convert.FromBase64String(b64image);
            file.Write(img, 0, img.Length);
            file.Flush();
            file.Close();
            
            // send this query to an user, expects a number answer between 0-360 (for rotate captcha) or 1-6 (for gametype 3 [splitcaptcha, dice])
            Console.Write($"{path} has been saved to the disk. Please insert the solution for this image: ");
            return Console.ReadLine() ?? "1";
        }
    }
}