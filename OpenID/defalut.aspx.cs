using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.IO;
using System.Configuration;

namespace OpenID
{
    public partial class defalut : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

            string openid = Request["openid"];
            if (string.IsNullOrEmpty(openid) == false)
            {

                //-----------------------------------------------------------
                // 直接要求でアソシエーションを確立する.
                //-----------------------------------------------------------
                string openidURL = ConfigurationManager.AppSettings["OPENID_ENDPOINT"];
                string assoc_ns = "http://specs.openid.net/auth/2.0";
                string assoc_mode = "associate";
                string assoc_assoc_type = "HMAC-SHA256";
                string assoc_session_type = "no-encryption";

                openidURL += "?openid.ns=" + HttpUtility.UrlEncode(assoc_ns);
                openidURL += "&openid.mode=" + assoc_mode;
                openidURL += "&openid.assoc_type=" + assoc_assoc_type;
                openidURL += "&openid.session_type=" + assoc_session_type;

                System.Net.WebClient wc = new System.Net.WebClient();
                Stream st = wc.OpenRead(openidURL);
                wc.Dispose();

                StreamReader sr = new StreamReader(st);
                string resData = sr.ReadToEnd();
                sr.Close();
                st.Close();


                //-----------------------------------------------------------
                // アソシエーションレスポンスのサンプル.
                //-----------------------------------------------------------
                // ns:http://specs.openid.net/auth/2.0
                // assoc_handle:....
                // session_type:no-encryption
                // assoc_type:HMAC-SHA256
                // expires_in:14400
                // mac_key:....


                //-----------------------------------------------------------
                // アソシエーションハンドルと共有鍵をセッションに保存.
                //-----------------------------------------------------------
                string[] stArrayData = resData.Split('\n');
                foreach (string stData in stArrayData){
                    string[] keyValueData = stData.Split(':');
                    Session[keyValueData[0]] = keyValueData[1];
                }


                //-----------------------------------------------------------
                // 間接要求で認証リダイレクトを行う.
                //-----------------------------------------------------------
                openidURL = ConfigurationManager.AppSettings["OPENID_ENDPOINT"];
                string claimed_id = "http://specs.openid.net/auth/2.0/identifier_select";
                string identity = "http://specs.openid.net/auth/2.0/identifier_select";
                string mode = "checkid_setup";
                string ns = "http://specs.openid.net/auth/2.0";
                string realm = ConfigurationManager.AppSettings["SELF_DOMAIN"];
                string return_to = ConfigurationManager.AppSettings["CALLBACK_URL"];
                string assoc_handle = Session["assoc_handle"].ToString();

                // URL作成.
                openidURL += "?openid.claimed_id=" + claimed_id;
                openidURL += "&openid.identity=" + HttpUtility.UrlEncode(identity);
                openidURL += "&openid.mode=" + mode;
                openidURL += "&openid.ns=" + HttpUtility.UrlEncode(ns);
                openidURL += "&openid.realm=" + HttpUtility.UrlEncode(realm);
                openidURL += "&openid.return_to=" + HttpUtility.UrlEncode(return_to);
                openidURL += "&openid.assoc_handle=" + assoc_handle;
                

                Response.Redirect(openidURL);

            }
        }
    }
}