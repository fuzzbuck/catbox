using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using catbox.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RestSharp;

namespace catbox.Arkose
{
    public class RotateCaptcha
    {
        public bool success;
        public string response;
        public Stopwatch sw = new Stopwatch();

        public RestClient client;
        private RestClient alt_client;
        protected int max_retries = 3;
        private WebProxy proxy;
        protected string base_url = "https://client.arkoselabs.com";
        protected string host_url;
        public string site_url = "https://outlook.live.com";
        protected string os_type;
        
        private string public_key;
        public int game_type=1;
        public string field_data;
        private string bda;
        public string token;
        protected string session_id;
        protected string challenge_id;
        protected string key;
        protected string sid;
        protected bool secure_mode = false;
        protected List<string> challenges = new List<string>();
        protected Dictionary<string, string> image_stash = new Dictionary<string, string>();
        private float angle;
        protected bool encrypted_mode;
        protected JArray example_images;

        protected bool do_cookie_timestamps = true;
        protected bool simulated = false;
        

        private string[] lang;
        private string useragent;

        public RotateCaptcha(string _public_key, string _os_type="Android", string _site_url="", string _field_data=null, WebProxy _proxy=null, string baseUrl=null)
        {
            if (_site_url != String.Empty)
                site_url = _site_url;
            
            host_url = base_url.Replace("https://", "").Replace("http://", "").Replace("/", "");
            
            client = new RestClient();
            alt_client = new RestClient();
            
            alt_client.ConfigureWebRequest(wr =>
            {
                wr.AutomaticDecompression = DecompressionMethods.None;
            });
            
            public_key = _public_key;
            proxy = _proxy;
            os_type = _os_type;

            if (baseUrl != null)
                base_url = baseUrl;

            if (_field_data != null)
                field_data = _field_data;

            if (proxy != null)
            {
                client.Proxy = proxy;
                alt_client.Proxy = proxy;
            }

            Init();
        }
        
        public void Test()
        {
            var req = new RestRequest(Method.GET);
            
            client.BaseUrl = new Uri("https://wikipedia.org");

            var resp = client.Execute(req);
            Console.WriteLine(resp.Content);
        }

        public virtual void Init()
        {
            // generate browser info
            useragent = BdaGen.get_userbrowser(os_type);
            lang = BdaGen.gen_lang();
            bda = Funcs.GenerateBda(useragent, os_type);

            client.AddDefaultHeader("Accept", "*/*");
            client.AddDefaultHeader("Accept-Encoding", "gzip, deflate");
            client.AddDefaultHeader("Accept-Language", lang[1]);
            
            alt_client.AddDefaultHeader("Accept-Language", lang[1]);
            alt_client.AddDefaultHeader("Accept-Encoding", "gzip, deflate");

            client.AddDefaultHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            client.AddDefaultHeader("Host", host_url);
            client.AddDefaultHeader("Origin", site_url);

            client.AddDefaultHeader("Sec-Fetch-Dest", "empty");
            client.AddDefaultHeader("Sec-Fetch-Mode", "cors");
            client.AddDefaultHeader("Sec-Fetch-Site", "cross-site");

            client.ConnectionGroupName = "keep-alive";
            
            client.UserAgent = useragent;
            alt_client.UserAgent = useragent;
        }
        
        public void ObtainToken()
        {
            client.BaseUrl = new Uri(base_url + "/fc/gt2/public_key/" + public_key);
            var req = new RestRequest(Method.POST);

            req.AddParameter("bda", bda);
            req.AddParameter("public_key", public_key);
            req.AddParameter("site", site_url);
            req.AddParameter("userbrowser", useragent);

            if (simulated)
            {
                req.AddParameter("simulate_rate_limit", 0);
                req.AddParameter("simulated", 0);
            }

            req.AddParameter("language", "en");
            req.AddParameter("rnd", new Random().NextDouble());
            if (field_data != null)
                req.AddParameter("data[blob]", field_data);
            
            req.AddHeader("Connection", "keep-alive");
            req.AddHeader("Referer", site_url);
            
            var resp = client.Execute(req);

            if (resp.StatusCode != HttpStatusCode.OK)
                return;
            
            var json = (JObject) JsonConvert.DeserializeObject(resp.Content);
                
            if (json != null && json.ContainsKey("token"))
            {
                sid = resp.Headers.Where(x => x.Name == "SRegion").Select(x => x.Value).FirstOrDefault() as string;
                token = (string) json["token"];
                session_id = token.Split("|".ToCharArray(), 2)[0];
                secure_mode = ((string) json["challenge_url_cdn"]).Contains("secure");
            }
        }

        public void ReportLoaded()
        {
            client.BaseUrl = new Uri(base_url + "/fc/api/?onload=reportFunCaptchaLoaded");
            var req = new RestRequest(Method.GET);

            req.AddHeader("Connection", "keep-alive");
            req.AddHeader("Referer", site_url);
            
            client.Execute(req);
        }
        
        public void Refresh()
        {
            client.BaseUrl = new Uri(base_url + "/fc/misc/refresh");
            var req = new RestRequest(Method.POST);

            var ts = Funcs.TimestampHeader();

            req.AddHeader("Origin", base_url);
            
            if(do_cookie_timestamps)
                req.AddParameter("timestamp", ts, ParameterType.Cookie);

            req.AddHeader("Connection", "keep-alive");
            req.AddHeader("Referer", base_url + "/fc/gc/?token=" + token.Replace("|", "&"));
            req.AddHeader("X-Requested-With", "XMLHttpRequest");
            req.AddHeader("cache-control", "no-cache");
            req.AddHeader("X-NewRelic-Timestamp", ts);
            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{}", Funcs.requestID(session_id)));
            
            JObject data = new JObject();
            
            data.Add(new JProperty("analytics_tier", 40));
            data.Add(new JProperty("sid", sid));
            data.Add(new JProperty("cache_key", session_id));


            if (secure_mode)
            {
                var enc_data = Funcs.encrypt_query(data.ToString(), "setupChallenge", session_id);
                req.AddParameter(enc_data[0], enc_data[1]);
            }
            else
            {
                foreach (KeyValuePair<string, JToken> p in data)
                {
                    req.AddParameter(p.Key, p.Value.ToString());
                }
            }
            
            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{}", Funcs.requestID(session_id)));
            client.Execute(req);
        }
        

        public void ObtainChallenge(int retries=0)
        {
            if (retries >= max_retries)
                throw new Exception("Max retries exceeded");
            
            client.BaseUrl = new Uri(base_url + "/fc/gfct/");
            var req = new RestRequest(Method.POST);

            var ts = Funcs.TimestampHeader();

            req.AddHeader("Origin", base_url);
            
            if(do_cookie_timestamps)
                req.AddParameter("timestamp", ts, ParameterType.Cookie);

            req.AddHeader("Connection", "keep-alive");
            req.AddHeader("Referer", base_url + "/fc/gc/?token=" + token.Replace("|", "&"));
            req.AddHeader("X-Requested-With", "XMLHttpRequest");
            req.AddHeader("cache-control", "no-cache");
            req.AddHeader("X-NewRelic-Timestamp", ts);
            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{}", Funcs.requestID(session_id)));
            
            JObject data = new JObject();
            
            data.Add(new JProperty("render_type", "canvas"));
            data.Add(new JProperty("lang", "en"));
            data.Add(new JProperty("token", session_id));
            data.Add(new JProperty("analytics_tier", 40));
            data.Add(new JProperty("sid", sid));
            data.Add(new JProperty("data[status]", "init"));


            if (secure_mode)
            {
                var enc_data = Funcs.encrypt_query(data.ToString(), "setupChallenge", session_id);
                req.AddParameter(enc_data[0], enc_data[1]);
            }
            else
            {
                foreach (KeyValuePair<string, JToken> p in data)
                {
                    req.AddParameter(p.Key, p.Value.ToString());
                }
            }

            var resp = client.Execute(req);
            if (resp.StatusCode != HttpStatusCode.OK) 
                ObtainChallenge(retries + 1);
            
            try
            {
                JObject content;
                if (secure_mode)
                {
                    content = Funcs.decrypt_query(resp.Content, "setupChallenge", session_id);
                }
                else
                {
                    content = JObject.Parse(resp.Content);
                }

                var json = content;

                if (json == null || !json.ContainsKey("challengeID"))
                {
                    ObtainChallenge(retries + 1);
                }


                challenge_id = (string) json["challengeID"];
                challenges = ((JArray) json["game_data"]["customGUI"]["_challenge_imgs"]).ToObject<List<string>>();
                angle = 6;
                if(json["game_data"]["customGUI"].Contains("_guiFontColr"))
                    angle = Funcs.angle((string) json["game_data"]["customGUI"]["_guiFontColr"]);
                encrypted_mode = json["game_data"]["customGUI"].ToObject<JObject>().ContainsKey("encrypted_mode");
                example_images = json["game_data"]["customGUI"]["example_images"] as JArray;
            }
            catch (Exception e)
            {
                ObtainChallenge(retries + 1);
            }
            
        }

        public void ObtainKey(int retries = 0)
        {
            if (retries >= max_retries)
                throw new Exception("Max retries exceeded");
            
            client.BaseUrl = new Uri(base_url + "/fc/ekey/");
            var req = new RestRequest(Method.POST);

            JObject data = new JObject();
            
            data.Add(new JProperty("game_token", challenge_id));
            data.Add(new JProperty("sid", sid));
            data.Add(new JProperty("session_token", session_id));
            
            foreach (KeyValuePair<string, JToken> p in data)
            {
                req.AddParameter(p.Key, p.Value.ToString());
            }
            
            int[] scdc = Funcs.ScDc();

            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{\"sc\":[" + scdc[0] + "," + scdc[1] + "]}", Funcs.requestID(session_id)));
            
            var ts = Funcs.TimestampHeader();

            req.AddHeader("X-Requested-With", "XMLHttpRequest");
            req.AddHeader("X-NewRelic-Timestamp", ts);
            req.AddHeader("Origin", base_url);
            
            if(do_cookie_timestamps)
                req.AddParameter("timestamp", ts, ParameterType.Cookie);
            
            var resp = client.Execute(req);
            if (resp.StatusCode != HttpStatusCode.OK)
                ObtainKey(retries + 1);
            try
            {
                var json =  JObject.Parse(resp.Content);

                if (json.ContainsKey("decryption_key"))
                    key = (string) json["decryption_key"];
            }
            catch (Exception)
            {
                ObtainKey(retries + 1);
            }
        }

        protected string DownloadImage(string url, int retries=0)
        {
            if (retries >= max_retries)
                return null;
            
            alt_client.BaseUrl = new Uri(url);
            var req = new RestRequest(Method.GET);
            req.AddHeader("Referer", base_url + "/fc/apps/canvas/001/?meta=6");
            req.AddHeader("Host", url.Split(":".ToCharArray(), 2)[1].Split(".".ToCharArray(), 2)[0].Substring(2) + ".cloudfront.net");
            req.AddHeader("Accept", "application/json, text/plain, */*");
            

            var resp = alt_client.Execute(req);
            var content = Encoding.UTF8.GetString(resp.RawBytes);

            if (resp.StatusCode == HttpStatusCode.OK && !resp.Content.ToLower().Contains("denied access"))
            {
                if (!encrypted_mode)
                    return Convert.ToBase64String(resp.RawBytes);

                return content;
            }

            return DownloadImage(url, retries + 1);
        }

        
        // returns true or false dependent on wheter it solved it or not
        public virtual bool SubmitGuess(string guess, string raw_guess, bool is_last = false, int retries = 0)
        {
            if (retries >= max_retries)
                return true;
            
            client.BaseUrl = new Uri(base_url + "/fc/ca/");
            var req = new RestRequest(Method.POST);
            
            JObject data = new JObject();
            data.Add(new JProperty("session_token", session_id));
            data.Add(new JProperty("game_token", challenge_id));
            data.Add(new JProperty("sid", sid));
            data.Add(new JProperty("guess", Crypto.Encrypt(guess, session_id)));
            data.Add(new JProperty("analytics_tier", 40));

            if (secure_mode)
            {
                var enc_data = Funcs.encrypt_query(data.ToString(), "checkAnswer", session_id);
                req.AddParameter(enc_data[0], enc_data[1]);
            }
            else
            {
                foreach (KeyValuePair<string, JToken> p in data)
                {
                    req.AddParameter(p.Key, p.Value.ToString());
                }
            }
            
            req.AddHeader("Connection", is_last ? "close" : "keep-alive");
            req.AddHeader("Referer", base_url + "/fc/gc/?token=" + token.Replace("|", "&"));
            req.AddHeader("cache-control", "no-cache");
            req.AddHeader("Origin", base_url);
            
            var ts = Funcs.TimestampHeader();
            req.AddHeader("X-Requested-With", "XMLHttpRequest");
            req.AddHeader("X-NewRelic-Timestamp", ts);
            
            if(do_cookie_timestamps)
                req.AddParameter("timestamp", ts, ParameterType.Cookie);
            
            int[] SCDC = Funcs.ScDc();
            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{\"sc\":[" + SCDC[0] + "," + SCDC[1] + "],\"dc\":[" + SCDC[2] + "," + SCDC[3] + "]" + (is_last ? ",\"ech\":\"" + raw_guess + "\"}" : "}"), Funcs.requestID(session_id)));
            
            var resp = client.Execute(req);
            if (resp.StatusCode != HttpStatusCode.OK)
                SubmitGuess(guess, raw_guess, is_last, retries + 1);
            
            JObject content;
            if (secure_mode)
            {
                var fresp = (string) JObject.Parse(resp.Content)["data"];
                content = Funcs.decrypt_query(fresp, "checkAnswer", session_id);
            }
            else
            {
                content = JObject.Parse(resp.Content);
            }

            var json = content;
            if (json == null || !json.ContainsKey("response"))
                SubmitGuess(guess, raw_guess, is_last, retries + 1);
            
            if(json.ContainsKey("solved"))
                success = (bool) json["solved"];
            
            key = (string) json["decryption_key"];
            response = (string) json["response"];

            return success;
        }

        // overwriteable solver function
        public virtual void Process()
        {
            string rotations = String.Empty;
            foreach (string image_url in challenges)
            {
                string encoded_img = DownloadImage(image_url);
                if (encoded_img == null)
                    return;
                
                // TODO: Use CatNet here
                string rotation = Solver.GetSolution(Funcs.RecodeImage(encoded_img));
                
                image_stash.Add(encoded_img, rotation);
                if (rotations == String.Empty)
                { rotations = rotation; } else { rotations = rotations + "," + rotation; }

                var done = SubmitGuess(rotations, rotation, challenges.IndexOf(image_url) == challenges.Count - 1);
                if (response == "timed_mode_timeout")
                {
                    sw.Stop();
                    Console.WriteLine($"{session_id} timed out! took {sw.Elapsed.Seconds} seconds");
                    
                    return;
                }

                if (success)
                {
                    sw.Stop();
                    Console.WriteLine($"{session_id} solved! took {sw.Elapsed.Seconds} seconds");
                    return;
                }
            }
            sw.Stop();
            Console.WriteLine($"{session_id} failed! took {sw.Elapsed.Seconds} seconds");
        }

        public string Solve(string field_data=null)
        {
            try
            {
                ReportLoaded();
                ObtainToken();
                
                sw.Start();
                
                LogTokenReceived(); // al
                ObtainChallenge();
                Refresh();
                
                Console.WriteLine($"{sid} => secure: {secure_mode}, encrypted: {encrypted_mode}, waves: {challenges.Count}, increment: {angle}, token: {session_id}");
     
                LogLoaded(); // al
                
                ObtainKey();
                
                LogVerified();
                Process();
                
                return token;
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error occured while trying to solve {session_id}: {e.Message}\n{e.StackTrace}");

                return null;
            }
        }
        
        # region logging
        public void LogTokenReceived()
        {
            var ts = Funcs.TimestampHeader();
            
            client.BaseUrl = new Uri(base_url + "/fc/a/");
            
            var req = new RestRequest(Method.POST);
            
            if(do_cookie_timestamps)
                req.AddParameter("timestamp", ts, ParameterType.Cookie);
            
            req.AddHeader("Origin", base_url);
            req.AddHeader("X-Requested-With", "XMLHttpRequest");
            req.AddHeader("cache-control", "no-cache");
            req.AddHeader("X-NewRelic-Timestamp", ts);
            req.AddHeader("Referer", base_url + "/fc/gc/?token=" + token.Replace("|", "&"));
            
            var body = new
            {
                session_token = session_id,
                render_type = "canvas",
                category = "Site+URL",
                action = site_url.Replace(":", "%3A").Replace("/", "%2F"), // << html formatting for some reason they want it here
                sid = sid,
                analytics_tier = 40
            };
            
            if (secure_mode)
            {
                var enc_data = Funcs.encrypt_query(JsonConvert.SerializeObject(body), "sendAnalytics", session_id);
                req.AddParameter(enc_data[0], enc_data[1]);
            }
            else
            {
                req.AddParameter("application/x-www-form-urlencoded",
                    $"category={body.category}&analytics_tier={body.analytics_tier}&render_type={body.render_type}&session_token={body.session_token}&sid={body.sid}&action={body.action}",
                    ParameterType.RequestBody);
            }
            
            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{}", Funcs.requestID(session_id)));
            client.Execute(req);
        }
        
        public void LogLoaded()
        {
            client.BaseUrl = new Uri(base_url + "/fc/a/");

            var req = new RestRequest(Method.POST);

            var ts = Funcs.TimestampHeader();

            req.AddHeader("Connection", "keep-alive");
            req.AddHeader("Origin", base_url);
            
            if(do_cookie_timestamps)
                req.AddParameter("timestamp", ts, ParameterType.Cookie);
            
            req.AddHeader("X-Requested-With", "XMLHttpRequest");
            req.AddHeader("cache-control", "no-cache");
            req.AddHeader("X-NewRelic-Timestamp", ts);
            req.AddHeader("Referer", base_url + "/fc/gc/?token=" + token.Replace("|", "&"));
            
            var body = new
            {
                session_token = session_id,
                render_type = "canvas",
                category = "loaded",
                action = "game+loaded",
                game_token = challenge_id,
                game_type = game_type,
                sid = sid,
                analytics_tier = 40
            };
            
            if (secure_mode)
            {
                var enc_data = Funcs.encrypt_query(JsonConvert.SerializeObject(body), "sendAnalytics", session_id);
                req.AddParameter(enc_data[0], enc_data[1]);
            }
            else
            {
                req.AddParameter("application/x-www-form-urlencoded",
                    $"category={body.category}&analytics_tier={body.analytics_tier}&render_type={body.render_type}&game_token={body.game_token}&game_type={body.game_type}&session_token={body.session_token}&sid={body.sid}&action={body.action}",
                    ParameterType.RequestBody);
            }
            
            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{}", Funcs.requestID(session_id)));

            client.Execute(req);
        }
        
        public void LogVerified()
        {
            client.BaseUrl = new Uri(base_url + "/fc/a/");
 
            var req = new RestRequest(Method.POST);

            var ts = Funcs.TimestampHeader();
            
            req.AddHeader("Origin", base_url);
            req.AddHeader("Cookie", "timestamp=" + ts);
            
            req.AddHeader("X-Requested-With", "XMLHttpRequest");
            req.AddHeader("cache-control", "no-cache");
            req.AddHeader("X-NewRelic-Timestamp", ts);
            req.AddHeader("Referer", base_url + "/fc/gc/?token=" + token.Replace("|", "&"));
            
            var body = new
            {
                render_type = "canvas",
                sid = sid,
                category = "begin+app",
                game_token = challenge_id,
                analytics_tier = 40,
                game_type = game_type,
                session_token = session_id,
                action = "user+clicked+verify"
            };
            
            if (secure_mode)
            {
                var enc_data = Funcs.encrypt_query(JsonConvert.SerializeObject(body), "sendAnalytics", session_id);
                req.AddParameter(enc_data[0], enc_data[1]);
            }
            else
            {
                req.AddParameter("application/x-www-form-urlencoded",
                    $"category={body.category}&analytics_tier={body.analytics_tier}&render_type={body.render_type}&game_token={body.game_token}&game_type={body.game_type}&session_token={body.session_token}&sid={body.sid}&action={body.action}",
                    ParameterType.RequestBody);
            }

            int[] scdc = Funcs.ScDc();
            
            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{\"sc\":[" + scdc[0] + "," + scdc[1] + "],\"dc\":[" + scdc[2] + "," + scdc[3] + "]}", Funcs.requestID(session_id)));
            
            if(do_cookie_timestamps)
                req.AddParameter("timestamp", ts, ParameterType.Cookie);

            client.Execute(req);   
        }
        
        # endregion
    }
}