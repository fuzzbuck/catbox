using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using catbox.Arkose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace catbox.Utils
{
    
    // contains useful functions which you will use a lot
    // most are not used in this implementation since it is stripped off of most features
    public static class Funcs
    {
        public static string Base64EncodeUTF8(string plainText) {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));
        }
        
        public static string Base64DecodeUTF8(string plainText) {
            return Encoding.UTF8.GetString(Convert.FromBase64String(plainText));
        }
        
        private static Random random = new Random();
        public static int RandomInt(int min, int max)  
        {
            return new Random().Next(min, max);  
        }
        
        // Returns a WebProxy from a string structured of ip:port or ip:port:user:pass
        public static WebProxy ParseProxy(string text)
        {
            bool isAuthProxy = text.Count(f => f == ':') == 3 ? true : false;
            string[] proxyElements = text.Split(":".ToCharArray());

            string address = "http://" + proxyElements[0] + ":" + proxyElements[1];
            WebProxy proxy = new WebProxy(address);

            if (isAuthProxy)
                proxy.Credentials = new NetworkCredential(proxyElements[2], proxyElements[3]);

            return proxy;
        }
        
        #region arkose
        
        // generates ScDc for X-* type headers in submitGuess methods
        public static int[] ScDc()
        {
            int int1 = RandomInt(120, 140);
            int int2 = RandomInt(180, 240);

            int int3 = RandomInt(120, 140);
            int int4 = RandomInt(180, 240);

            return new[] {int1, int2, int3, int4};
        }
        
        // ripped straight out of arkose's source js files
        public static string TimestampHeader()
        {
            string epoch = DateTimeOffset.Now.ToUnixTimeMilliseconds().ToString();

            string j8Q = epoch.Substring(0, 7);
            string V9Q = epoch.Substring(7, 13 - 7);

            string L9Q = j8Q + "00" + V9Q;

            return L9Q;
        }
        
        // converts a guess angle to the specified multiplicand (eg. if guess is 37 degrees, but increment is in 51.40, rounds guess to 51.40)
        public static float GuessToAngle(float orig, float angle)
        {
            var multiplicand = Math.Round (orig / angle);
            return (float) (angle * multiplicand);
        }
        
        // generate a valid encoded bda
        public static string GenerateBda(string userbrowser, string os_type)
        {
            decimal epoch = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            
            decimal K3D = epoch / 1000;
            int q3D = 21600;
            
            string O3D = userbrowser;
            var h3D = Math.Round(K3D - K3D % q3D);

            string str = BdaGen.get_bda_from_list(os_type);
            str = str.Replace("B64TIME", Base64EncodeUTF8(Math.Round(K3D).ToString(CultureInfo.InvariantCulture)));

            return Base64EncodeUTF8(Crypto.Encrypt(str, O3D + h3D));
        }
        
        // requestID wrapper for X-Requested-ID Headers
        public static string requestID(string sessionToken)
        {
            return "REQUESTED" + sessionToken + "ID";
        }
        
        // get angle increment from guiFontClr
        public static float angle(string fontClr)
        {
            var tp = fontClr.Replace("#", "").Substring(3);
            int angle = Convert.ToInt32(tp, 16);

            float newAngle = angle;
            if (angle > 113)
                newAngle = (float) (angle / 10.00);
            
            return newAngle; // W H A T
        }
        
        // image manipulation(s)
        public static string RotateImage(string b64Img, float angle) {
            MemoryStream stream = new MemoryStream(Convert.FromBase64String(b64Img));
            Bitmap bmp = new Bitmap(Image.FromStream(stream));
            
            Bitmap rotatedImage = new Bitmap(bmp.Width, bmp.Height);
            rotatedImage.SetResolution(bmp.HorizontalResolution, bmp.VerticalResolution);

            using (Graphics g = Graphics.FromImage(rotatedImage)) {
                // Set the rotation point to the center in the matrix
                g.TranslateTransform(bmp.Width / 2, bmp.Height / 2);
                // Rotate
                g.RotateTransform(angle);
                // Restore rotation point in the matrix
                g.TranslateTransform(- bmp.Width / 2, - bmp.Height / 2);
                // Set white color
                g.Clear(Color.White);
                // Draw the image on the bitmap
                g.DrawImage(bmp, new Point(0, 0));
            }
            
            MemoryStream ms = new MemoryStream();
            rotatedImage.Save(ms, ImageFormat.Png);

            return Convert.ToBase64String(ms.GetBuffer());
        }
        
        // dice -> 320x320 for yolo format
        public static string YoloEncode(string b64Img)
        {
            MemoryStream stream = new MemoryStream(Convert.FromBase64String(b64Img));
            Bitmap bmp = new Bitmap(Image.FromStream(stream));
            Bitmap nbmp = new Bitmap(320, 320);
            nbmp.SetResolution(bmp.HorizontalResolution, bmp.VerticalResolution);

            using (Graphics g = Graphics.FromImage(nbmp))
            {
                g.Clear(Color.FromArgb(114, 114, 114));
                g.DrawImage(bmp, 0, (bmp.Height - 213/2)/2 + 4, 320, 213); // aspect ratio: 1.5
            }
            
            MemoryStream ms = new MemoryStream();
            nbmp.Save(ms, ImageFormat.Jpeg);

            return Convert.ToBase64String(ms.GetBuffer());
        }
        
        // any format > jpeg (compression)
        public static string RecodeImage(string b64Img) {
            MemoryStream stream = new MemoryStream(Convert.FromBase64String(b64Img));
            Bitmap bmp = new Bitmap(Image.FromStream(stream));

            MemoryStream ms = new MemoryStream();
            bmp.Save(ms, ImageFormat.Jpeg);

            return Convert.ToBase64String(ms.GetBuffer());
        }
        
        // encryption/decryption keys [NOTE; changes with every funcaptcha update]
        public static Dictionary<string, string> query_keys = new Dictionary<string, string>
        {
            {"setupChallenge", "e689abfe0539b86d4312be70ba086eaa5"},
            {"checkAnswer", "e0dcd069d8a2c549c42579d4924dc20eb"},
            {"getEncryptionKey", "e0d214325fb9c442cb0ec67555c3d775a"},
            {"sendAnalytics", "eb866b553420803381c07e1fc3a979c57"},
        };
        
        public static Dictionary<string, string> enc_keys = new Dictionary<string, string>
        {
            {"setupChallenge", "ead90bae4038ede134e46ba88c41e589f"},
            {"checkAnswer", "eaf2c0e161fd40704b63e53a20ec3322e"},
            {"getEncryptionKey", "e362eef6a5f1605be246f1c01abd60b61"},
            {"sendAnalytics", "e290a90170beee7a5551e07f1cabde37c"},
        };

        public static string[] encrypt_query(string query, string method, string session)
        {
            var k = "secure" + enc_keys[method] + "mode";
            var d_k = String.Empty;

            switch (method)
            {
                case "setupChallenge":
                    d_k = "init" + session + "key";
                    break;
                case "sendAnalytics":
                    d_k = "analytical" + session + "key";
                    break;
                case "checkAnswer":
                    d_k = "cat" + session + "key";
                    break;
                case "getEncryptionKey":
                    d_k = "timed" + session + "key";
                    break;
            }

            d_k = "secure" + d_k + "mode";
            
            try{
                JObject o = new JObject();
                o.Add(new JProperty("token", session));
                o.Add(new JProperty("data", Crypto.Encrypt(query, d_k)));
            
                var toEnc = o.ToString();
                var enc = Crypto.Encrypt(toEnc, k);

                return new []{query_keys[method], enc};
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static JObject decrypt_query(string query, string method, string session)
        {
            var d_k = String.Empty;
            switch (method)
            {
                case "setupChallenge":
                    d_k = "init_return" + session;
                    break;
                case "checkAnswer":
                    d_k = "ca_reply" + session;
                    break;
                case "getEncryptionKey":
                    d_k = "ekey_reply" + session;
                    break;
            }

            try
            {
                var dec = Funcs.Base64DecodeUTF8(Crypto.Decrypt(query, d_k));

                return (JObject) JsonConvert.DeserializeObject(dec);
            }
            catch (Exception)
            {
                return null;
            }
        }
        
        #endregion
        
        
        // converts the square number of SplitCaptcha to a valid coordinate to be sent over the network
        public static string GuessToCoordinate(string resp)
        {
            // possible resp: { 1, 2, 3, 4, 5, 6 }
            var rnd = new Random();

            string px, py;
            float x = 0, y = 0;

            switch (int.Parse(resp))
            {
                case 1:
                    y = rnd.Next(1, 99);
                    x = rnd.Next(1, 99);
                    break;
                case 2:
                    y = rnd.Next(101, 199);
                    x = rnd.Next(1, 99);
                    break;
                case 3:
                    y = rnd.Next(201, 299);
                    x = rnd.Next(1, 99);
                    break;
                case 4:
                    y = rnd.Next(1, 99);
                    x = rnd.Next(101, 199);
                    break;
                case 5:
                    y = rnd.Next(101, 199);
                    x = rnd.Next(101, 199);
                    break;
                case 6:
                    y = rnd.Next(201, 299);
                    x = rnd.Next(101, 199);
                    break;
            }

            float xx = x;
            float yy = y;


            
            x = yy;
            y = xx;
            

            py = (y / 200).ToString("0.00");
            px = (x / 300).ToString("0.00");

            string rx = (rnd.Next(1848907, 677083015).ToString() + rnd.Next(1848907, 677083015).ToString()).Substring(rnd.Next(1, 17));
            string ry = (rnd.Next(1848907, 677083015).ToString() + rnd.Next(1848907, 677083015).ToString()).Substring(rnd.Next(1, 17));

            // [NOTE; funcaptcha changes this a lot, you have to manually check what kind of format guesses are being sent as]
            /*
             * Various methods used by arkose to serialize guesses
             * method_1: serializeGuesses((function(e) {
                    var t = e.x;
                    return {
                        x: e.y,
                        y: t
                    }
                }
                )),
                method_2: serializeGuesses((function(e) {
                    var t = e.x;
                    return {
                        x: t,
                        y: (e.y + t) * t
                    }
                }
                )),
                method_3: serializeGuesses((function(e) {
                    return {
                        a: e.x,
                        b: e.y
                    }
                }
                )),
                method_4: serializeGuesses((function(e) {
                    return [e.x, e.y]
                }
                )),
                method_5: serializeGuesses((function(e) {
                    var t = e.x;
                    return [e.y, t].map(Math.sqrt)
                }
             */
            
            //return $"[{x},{y}.0078125]";
            //return "{\"x\":" + y + ",\"y\":" + x + "}";
            return "{\"px\":" + "\"" + px + "\"" + ",\"py\":" + "\"" + py + "\"," + "\"x\":" + x + ",\"y\":" + y + "}";
            //return "{\"a\":" + y + ",\"b\":" + x + "}";
        }
    }
}