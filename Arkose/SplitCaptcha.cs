using System;
using System.Collections.Generic;
using System.Net;
using catbox.Utils;
using Newtonsoft.Json.Linq;
using RestSharp;

namespace catbox.Arkose
{
    public class SplitCaptcha : RotateCaptcha
    {
        public SplitCaptcha(string _public_key, string _os_type="Android", string _site_url="", string _field_data=null, WebProxy _proxy = null, string baseUrl = null) : base(_public_key, _os_type, _site_url, _field_data, _proxy, baseUrl)
        {
        }

        public override void Init()
        {
            base.Init();
            game_type = 3;
        }


        public override bool SubmitGuess(string guess, string raw_guess, bool is_last = false, int retries = 0)
        {
            if (retries >= max_retries)
                return true;
            
            client.BaseUrl = new Uri(base_url + "/fc/ca/");
            var req = new RestRequest(Method.POST);
            
            JObject data = new JObject();
            data.Add(new JProperty("game_token", challenge_id));
            data.Add(new JProperty("session_token", session_id));
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
            
            req.AddHeader("X-Requested-ID", Crypto.Encrypt("{}", Funcs.requestID(session_id)));
            
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
        public override void Process()
        {
            string solutions = String.Empty;
            foreach (string image_url in challenges)
            {
                string encoded_img = DownloadImage(image_url);
                if (encoded_img == null)
                    return;

                if (encrypted_mode)
                {
                    encoded_img = Crypto.Decrypt(encoded_img, key);
                    encoded_img = Funcs.Base64DecodeUTF8(encoded_img);
                }
                
                string result = Solver.GetSolution(Funcs.RecodeImage(encoded_img));
                image_stash.Add(encoded_img, result);

                if (solutions == String.Empty)
                { solutions = Funcs.GuessToCoordinate(result); } else { solutions = solutions + "," + Funcs.GuessToCoordinate(result); }

                SubmitGuess($"[{solutions}]", result, challenges.IndexOf(image_url) == challenges.Count - 1);
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
    }
}