using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using Flurl.Http;
using Jurassic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace catbox.Arkose
{
    public class BdaGen
    {
        // This is ugly. I know.
        // NOTE: funcaptcha messes with this A LOT, you will have to manually change a lot of stuff frequently to
        // keep getting the easiest possible challenges
        private static object[] fp() // returns cfp, f
        {
            var csprng = new RNGCryptoServiceProvider();
            var bytes = new byte[16];
            csprng.GetNonZeroBytes(bytes);
            
            var rnd = new Random();

            int cfp = rnd.Next(1000000, 99999999);
            if (rnd.Next(1, 2) == 1)
                cfp = cfp * -1;

            return new object[] {string.Join("", bytes.Select(b => b.ToString("x2"))), cfp};
        }
        
        public static ScriptEngine engine = new ScriptEngine();
        public static JArray jsonagents;

        public static string getSpecificAgent(string os_type)
        {
            var rnd = new Random();
            while (true)
            {
                var agent = jsonagents[rnd.Next(0, jsonagents.Count - 1)];
                if ((string) agent["os_type"] == os_type && (os_type == "Android" || (string) agent["device_type"] == "Desktop"))
                    return (string) agent["agent_string"];
            }
        }
        public static void Init()
        {
            // load agents.json
            var resp = "http://catbox.wtf/agents.json".GetAsync().Result.GetStringAsync().Result;
            jsonagents = JArray.Parse(resp);

            // funcaptchas' functions for generating hashes
            engine.Evaluate(
                "var x64Add=function(t,r){t=[t[0]>>>16,65535&t[0],t[1]>>>16,65535&t[1]],r=[r[0]>>>16,65535&r[0],r[1]>>>16,65535&r[1]];var x=[0,0,0,0];return x[3]+=t[3]+r[3],x[2]+=x[3]>>>16,x[3]&=65535,x[2]+=t[2]+r[2],x[1]+=x[2]>>>16,x[2]&=65535,x[1]+=t[1]+r[1],x[0]+=x[1]>>>16,x[1]&=65535,x[0]+=t[0]+r[0],x[0]&=65535,[x[0]<<16|x[1],x[2]<<16|x[3]]},x64Multiply=function(t,r){t=[t[0]>>>16,65535&t[0],t[1]>>>16,65535&t[1]],r=[r[0]>>>16,65535&r[0],r[1]>>>16,65535&r[1]];var x=[0,0,0,0];return x[3]+=t[3]*r[3],x[2]+=x[3]>>>16,x[3]&=65535,x[2]+=t[2]*r[3],x[1]+=x[2]>>>16,x[2]&=65535,x[2]+=t[3]*r[2],x[1]+=x[2]>>>16,x[2]&=65535,x[1]+=t[1]*r[3],x[0]+=x[1]>>>16,x[1]&=65535,x[1]+=t[2]*r[2],x[0]+=x[1]>>>16,x[1]&=65535,x[1]+=t[3]*r[1],x[0]+=x[1]>>>16,x[1]&=65535,x[0]+=t[0]*r[3]+t[1]*r[2]+t[2]*r[1]+t[3]*r[0],x[0]&=65535,[x[0]<<16|x[1],x[2]<<16|x[3]]},x64Rotl=function(t,r){return 32===(r%=64)?[t[1],t[0]]:r<32?[t[0]<<r|t[1]>>>32-r,t[1]<<r|t[0]>>>32-r]:(r-=32,[t[1]<<r|t[0]>>>32-r,t[0]<<r|t[1]>>>32-r])},x64LeftShift=function(t,r){return 0===(r%=64)?t:r<32?[t[0]<<r|t[1]>>>32-r,t[1]<<r]:[t[1]<<r-32,0]},x64Xor=function(t,r){return[t[0]^r[0],t[1]^r[1]]},x64Fmix=function(t){return t=x64Xor(t,[0,t[0]>>>1]),t=x64Multiply(t,[4283543511,3981806797]),t=x64Xor(t,[0,t[0]>>>1]),t=x64Multiply(t,[3301882366,444984403]),t=x64Xor(t,[0,t[0]>>>1])},x64hash128=function(t,r){r=r||0;for(var x=(t=t||\"\").length%16,e=t.length-x,o=[0,r],c=[0,r],h=[0,0],a=[0,0],d=[2277735313,289559509],i=[1291169091,658871167],A=0;A<e;A+=16)h=[255&t.charCodeAt(A+4)|(255&t.charCodeAt(A+5))<<8|(255&t.charCodeAt(A+6))<<16|(255&t.charCodeAt(A+7))<<24,255&t.charCodeAt(A)|(255&t.charCodeAt(A+1))<<8|(255&t.charCodeAt(A+2))<<16|(255&t.charCodeAt(A+3))<<24],a=[255&t.charCodeAt(A+12)|(255&t.charCodeAt(A+13))<<8|(255&t.charCodeAt(A+14))<<16|(255&t.charCodeAt(A+15))<<24,255&t.charCodeAt(A+8)|(255&t.charCodeAt(A+9))<<8|(255&t.charCodeAt(A+10))<<16|(255&t.charCodeAt(A+11))<<24],h=x64Multiply(h,d),h=x64Rotl(h,31),h=x64Multiply(h,i),o=x64Xor(o,h),o=x64Rotl(o,27),o=x64Add(o,c),o=x64Add(x64Multiply(o,[0,5]),[0,1390208809]),a=x64Multiply(a,i),a=x64Rotl(a,33),a=x64Multiply(a,d),c=x64Xor(c,a),c=x64Rotl(c,31),c=x64Add(c,o),c=x64Add(x64Multiply(c,[0,5]),[0,944331445]);switch(h=[0,0],a=[0,0],x){case 15:a=x64Xor(a,x64LeftShift([0,t.charCodeAt(A+14)],48));case 14:a=x64Xor(a,x64LeftShift([0,t.charCodeAt(A+13)],40));case 13:a=x64Xor(a,x64LeftShift([0,t.charCodeAt(A+12)],32));case 12:a=x64Xor(a,x64LeftShift([0,t.charCodeAt(A+11)],24));case 11:a=x64Xor(a,x64LeftShift([0,t.charCodeAt(A+10)],16));case 10:a=x64Xor(a,x64LeftShift([0,t.charCodeAt(A+9)],8));case 9:a=x64Xor(a,[0,t.charCodeAt(A+8)]),a=x64Multiply(a,i),a=x64Rotl(a,33),a=x64Multiply(a,d),c=x64Xor(c,a);case 8:h=x64Xor(h,x64LeftShift([0,t.charCodeAt(A+7)],56));case 7:h=x64Xor(h,x64LeftShift([0,t.charCodeAt(A+6)],48));case 6:h=x64Xor(h,x64LeftShift([0,t.charCodeAt(A+5)],40));case 5:h=x64Xor(h,x64LeftShift([0,t.charCodeAt(A+4)],32));case 4:h=x64Xor(h,x64LeftShift([0,t.charCodeAt(A+3)],24));case 3:h=x64Xor(h,x64LeftShift([0,t.charCodeAt(A+2)],16));case 2:h=x64Xor(h,x64LeftShift([0,t.charCodeAt(A+1)],8));case 1:h=x64Xor(h,[0,t.charCodeAt(A)]),h=x64Multiply(h,d),h=x64Rotl(h,31),h=x64Multiply(h,i),o=x64Xor(o,h)}return o=x64Xor(o,[0,t.length]),c=x64Xor(c,[0,t.length]),o=x64Add(o,c),c=x64Add(c,o),o=x64Fmix(o),c=x64Fmix(c),o=x64Add(o,c),c=x64Add(c,o),(\"00000000\"+(o[0]>>>0).toString(16)).slice(-8)+(\"00000000\"+(o[1]>>>0).toString(16)).slice(-8)+(\"00000000\"+(c[0]>>>0).toString(16)).slice(-8)+(\"00000000\"+(c[1]>>>0).toString(16)).slice(-8)};");
            
            start_bda_list_generator();
        }
        public static string[] langs = "af-ZA,am-ET,ar-AE,ar-BH,ar-DZ,ar-EG,ar-IQ,ar-JO,ar-KW,ar-LB,ar-LY,ar-MA,ar-OM,ar-QA,ar-SA,ar-SY,ar-TN,ar-YE,as-IN,ba-RU,be-BY,bg-BG,bn-BD,bn-IN,bo-CN,br-FR,ca-ES,co-FR,cs-CZ,cy-GB,da-DK,de-AT,de-CH,de-DE,de-LI,de-LU,dv-MV,el-GR,en-029,en-AU,en-BZ,en-CA,en-GB,en-IE,en-IN,en-JM,en-MY,en-NZ,en-PH,en-SG,en-TT,en-US,en-ZA,en-ZW,es-AR,es-BO,es-CL,es-CO,es-CR,es-DO,es-EC,es-ES,es-GT,es-HN,es-MX,es-NI,es-PA,es-PE,es-PR,es-PY,es-SV,es-US,es-UY,es-VE,et-EE,eu-ES,fa-IR,fi-FI,fo-FO,fr-BE,fr-CA,fr-CH,fr-FR,fr-LU,fr-MC,fy-NL,ga-IE,gd-GB,gl-ES,gu-IN,he-IL,hi-IN,hr-BA,hu-HU,hy-AM,id-ID,ig-NG,ii-CN,is-IS,it-CH,it-IT,ja-JP,ka-GE,kk-KZ,kl-GL,km-KH,kn-IN,ko-KR,ky-KG,lb-LU,lo-LA,lt-LT,lv-LV,mi-NZ,mk-MK,ml-IN,mn-MN,mr-IN,ms-BN,ms-MY,mt-MT,nb-NO,ne-NP,nl-BE,nl-NL,nn-NO,oc-FR,or-IN,pa-IN,pl-PL,ps-AF,pt-BR,pt-PT,rm-CH,ro-RO,ru-RU,rw-RW,sa-IN,se-FI,se-NO,se-SE,si-LK,sk-SK,sl-SI,sq-AL,sv-FI,sv-SE,sw-KE,ta-IN,te-IN,th-TH,tk-TM,tn-ZA,tr-TR,tt-RU,ug-CN,uk-UA,ur-PK,vi-VN,wo-SN,xh-ZA,yo-NG,zh-CN,zh-HK,zh-MO,zh-SG,zh-TW,zu-ZA".Split(",".ToCharArray());
        public static string[] models = "SM-N950N,SM-G960F,SM-G892A,SM-G930VC,SM-G935S,SM-G920V,SM-G928X,Nexus 6P,G8231,E6653,HTC One X10,HTC One M9,SM-M315F,SM-M115M".Split(",".ToCharArray());
        public static string[] gen_lang() // returns short_code, acceptLang
        {
            Random rnd = new Random();

            string lang = langs[rnd.Next(0, langs.Length - 1)];
            string locales = "en-US,";
            
            var q = rnd.Next(7, 9);
            
            q = q - rnd.Next(1, 2);
            for (int i=0; i < rnd.Next(1, 3); i++)
            {
                var locale = langs[rnd.Next(0, langs.Length - 1)];
                if (rnd.Next(1, 2) == 3)
                    locale = locale.Split("-".ToCharArray())[0];

                locales = locales + locale + ";q=0." + q + ",";
                q = q - rnd.Next(1, 2);
            }
            
            //return new[] {lang, locales.Substring(0, locales.Length-1)};
            return new[] {lang, "en-US,en;q=0.9"};
        }

        public static string alphabet = "qwertyuiopasdfghjklzxcvbnm".ToUpper();
        public static string get_userbrowser(string os_type)
        {
            return getSpecificAgent(os_type);
            
            
            // below is the old version of userbrowser generation,
            // you can try using it but it is pretty bad
            
            var rnd = new Random();

            var chrome_version = rnd.Next(63, 78);
            var chrome_ver_inc = rnd.Next(1283, 4930);
            var chrome_ver_inc2 = rnd.Next(32, 383);

            //var model = models[rnd.Next(0, models.Length - 1)];
            var model = "SM-" + alphabet[rnd.Next(0, alphabet.Length - 1)] + rnd.Next(40, 99) * 10 + alphabet[rnd.Next(0, alphabet.Length - 1)];
            

            return
                $"Mozilla/5.0 (Linux; Android 10; {model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Mobile Safari/537.36";
            //return $"Android 5.1.1; {model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.9 Safari/537.36";
            return
                $"Mozilla/5.0 (Linux; Android 9.0; {model}) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1";
            return
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36";
            //return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/82.0"; 
        }
        public static BlockingCollection<string> bda_list_mobile = new BlockingCollection<string>();
        public static BlockingCollection<string> bda_list_windows = new BlockingCollection<string>();
        public static string get_bda_from_list(string os_type)
        {
            return (os_type == "Android" ? bda_list_mobile.Take() : bda_list_windows.Take());
        }

        public static void start_bda_list_generator()
        {
            // starts bda generator in new thread to not hog main
            new Thread(() =>
            {
                while (true)
                {
                    if (bda_list_mobile.Count < 2000)
                    {
                        bda_list_mobile.Add(get_bda("Android"));
                        Thread.Sleep(5);
                    }
                    if (bda_list_windows.Count < 2000)
                    {
                        bda_list_windows.Add(get_bda("Windows"));
                        Thread.Sleep(5);
                    }
                    Thread.Sleep(5);
                }
            }).Start();
        }
        public static string get_bda(string os_type)
        {
            var rnd = new Random();
            JArray bda = new JArray();

            JObject api_type = new JObject();
            api_type.Add(new JProperty("key", "api_type"));
            api_type.Add(new JProperty("value", "js"));
            
            JObject p = new JObject();
            p.Add(new JProperty("key", "p"));
            p.Add(new JProperty("value", 1));

            object[] fp = BdaGen.fp();
            
            JObject f = new JObject();
            f.Add(new JProperty("key", "f"));
            f.Add(new JProperty("value", fp[0]));
            
            JObject n = new JObject();
            n.Add(new JProperty("key", "n"));
            n.Add(new JProperty("value", "B64TIME"));
            
            JObject wh = new JObject();
            wh.Add(new JProperty("key", "wh"));
            
            // chrome
            // wh.Add(new JProperty("value", BdaGen.fp()[0] + "|" + "5d76839801bc5904a4f12f1731a7b6d1"));
            
            // firefox
            // wh.Add(new JProperty("value", BdaGen.fp()[0] + "|" + "5d76839801bc5904a4f12f1731a7b6d1"));
            
            // chrome dev (android)
            wh.Add(new JProperty("value", $"{BdaGen.fp()[0]}|{(os_type == "Android" ? "5d76839801bc5904a4f12f1731a7b6d1" : "72627afbfd19a741c7da1732218301ac")}"));


            string fonts =
                "Arial,Arial Black,Arial Narrow,Calibri,Cambria,Cambria Math,Comic Sans MS,Consolas,Courier,Courier New,Georgia,Helvetica,Impact,Lucida Console,Lucida Sans Unicode,Microsoft Sans Serif,MS Gothic,MS PGothic,MS Sans Serif,MS Serif,Palatino Linotype,Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Semibold,Segoe UI Symbol,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings";
            
            string mobileFonts =
                "Arial,Courier,Courier New,Georgia,Helvetica,Monaco,Palatino,Tahoma,Times,Times New Roman,Verdana";
            
            string plugins = "Chrome PDF Plugin,Chrome PDF Viewer,Native Client";
            string mobilePlugins = "";

            JArray fe_data = new JArray();
            fe_data.Add("DNT:unknown");
            fe_data.Add("L:en-US");
            fe_data.Add("D:24");
            fe_data.Add(os_type == "Android" ? "PR:1.2000000476837158" : "PR:1");
            fe_data.Add(os_type == "Android" ? "S:1067,600" : "S:1920,1080");
            fe_data.Add(os_type == "Android" ? "AS:1067,600" : "AS:1920,1040");
            fe_data.Add("TO:-60");
            fe_data.Add("SS:true");
            fe_data.Add("LS:true");
            fe_data.Add($"IDB:{(os_type == "Android" ? "false" : "true")}");
            fe_data.Add("B:false");
            fe_data.Add($"ODB:{(os_type == "Android" ? "false" : "true")}");
            fe_data.Add("CPUC:unknown");
            fe_data.Add(os_type == "Android" ? "PK:Linux armv7l" : "PK:Win32");

            // todo change this
            fe_data.Add("CFP:" + fp[1]);
            
            fe_data.Add("FR:false");
            fe_data.Add("FOS:false");
            fe_data.Add("FB:false");
            fe_data.Add($"JSF:{(os_type == "Android" ? mobileFonts : fonts)}");
            fe_data.Add(os_type == "Android" ? ("P:" + mobilePlugins) : ("P:" + plugins));
            fe_data.Add(os_type == "Android" ? "T:5,true,true" : "T:0,false,false");
            //fe_data.Add("H:" + rnd.Next(2, 7));
            fe_data.Add("H:4");
            fe_data.Add("SWF:false");
            
            JObject fe = new JObject();
            fe.Add(new JProperty("key", "fe"));
            fe.Add(new JProperty("value", fe_data));

            string pure_fe = String.Empty;
            foreach (var fvalue in fe_data)
            {
                pure_fe = pure_fe + fvalue + ", ";
            }

            pure_fe = pure_fe.Substring(0, pure_fe.Length - 2);
            var hash = engine.CallGlobalFunction<string>("x64hash128", pure_fe, 38);

            JObject ife = new JObject();
            ife.Add(new JProperty("key", "ife_hash"));
            ife.Add(new JProperty("value", hash));
            
            JObject cs = new JObject();
            cs.Add(new JProperty("value", 1));
            cs.Add(new JProperty("key", "cs"));
            
            JObject jsbd_data = new JObject();
            jsbd_data.Add(new JProperty("HL", rnd.Next(2, 14)));
            jsbd_data.Add(new JProperty("NCE", true));
            jsbd_data.Add(new JProperty("DT", "Roblox"));
            jsbd_data.Add(new JProperty("NWD", "undefined"));

            if (os_type == "Android")
            {
                jsbd_data.Add(new JProperty("DMTO", 1));
                jsbd_data.Add(new JProperty("DOTO", 1));
            }else{
                jsbd_data.Add(new JProperty("DA", null));
                jsbd_data.Add(new JProperty("DR", null));
                jsbd_data.Add(new JProperty("DMT", rnd.Next(28, 38)));
                jsbd_data.Add(new JProperty("DO", null));
                jsbd_data.Add(new JProperty("DOT", rnd.Next(31, 45)));
            }

            
            JObject jsbd = new JObject();
            jsbd.Add(new JProperty("key", "jsbd"));
            jsbd.Add(new JProperty("value", jsbd_data.ToString(Formatting.None)));
            
            bda.Add(api_type);
            bda.Add(p);
            bda.Add(f);
            bda.Add(n);
            bda.Add(wh);
            bda.Add(fe);
            bda.Add(ife);
            bda.Add(cs);
            bda.Add(jsbd);

            return bda.ToString(Formatting.None);
        }
    }
}