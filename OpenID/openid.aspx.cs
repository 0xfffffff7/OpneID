using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Cryptography;
using System.Configuration;

namespace OpenID
{
    public partial class openid : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

            // レスポンスのサンプル
            // openid.ns=http://specs.openid.net/auth/2.0
            // openid.mode=id_res
            // openid.return_to=https://要求時に指定した自身のコールバックURL
            // openid.claimed_id=https://me.yahoo.com/a/..........
            // openid.identity=https://me.yahoo.com/a/.......
            // openid.assoc_handle=.........
            // openid.realm=https://自身のドメイン
            // openid.response_nonce=.........
            // openid.signed=assoc_handle,claimed_id,identity,mode,ns,op_endpoint,response_nonce,return_to,signed,pape.auth_level.nist
            // openid.op_endpoint=https://open.login.yahooapis.com/openid/op/auth
            // openid.pape.auth_level.nist=0
            // openid.sig=.........


            // レスポンス表示
            foreach (string key in Request.QueryString.Keys)
            {
                LABEL1.Text += string.Format("{0}={1}<br><br>", key, Request.QueryString[key]);
            }


            // アサーションの検証.
            //
            // 1. openid.return_toが現在の要求の URL と一致する
            // 2. ディスカバリによって得られた情報がアサーションの情報と一致する
            //  　主張識別子 openid.claimed_id 
            //　  OPローカル識別子 openid.identity 
            //　  OPエンドポイントURL openid.op_endpoint 
            //　  プロトコルバージョン openid.ns 
            // 3. openid.response_nonce について、当該 OP から、これまでに同じ値のアサーションを受け入れたことがない
            // 4. アサーションの署名が有効で、署名が必要な全てのフィールドに署名がされている
            
            // ここでは1と4だけ検証する.

            // コールバックURL検証
            if (Request.QueryString["openid.return_to"].ToString() != ConfigurationManager.AppSettings["CALLBACK_URL"]){
                LABEL1.Text += "<br/><br/>Verify Failed!!<br/><br/><br/><br/><br/><br/>";
                return;
            }

            // シグネチャ検証検証
            // openid.signedに書かれている順番でキーバリュー形式に変換する。
            string keyValue = string.Empty;
            string signed = Request.QueryString["openid.signed"];

            string[] stArrayData = signed.Split(',');
            foreach (string stData in stArrayData)
            {
                keyValue += stData + ":" + Request.QueryString["openid." + stData] + "\n";
            }

            LABEL1.Text += "<hr>";
            LABEL1.Text += "<br/><br/>Verify signature parameter=" + keyValue;

            LABEL1.Text += "<hr>";

            // 共有鍵を使用してHMACを計算する。
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(keyValue);
            string macKey = Session["mac_key"].ToString();
            HMACSHA256 signer = new HMACSHA256(Convert.FromBase64String(macKey));
            byte[] result = signer.ComputeHash(bytes);

            LABEL1.Text += "<br/><br/>openid.sig=" + Request.QueryString["openid.sig"].ToString();
            LABEL1.Text += "<br/>Compute signature=";
            string computeSignature = System.Convert.ToBase64String(result);
            LABEL1.Text += computeSignature;

            if (Request.QueryString["openid.sig"].ToString() == computeSignature)
            {
                LABEL1.Text += "<br/><br/>Verify Success!!<br/><br/><br/><br/><br/><br/>";
            }
            else
            {
                LABEL1.Text += "<br/><br/>Verify Failed!!<br/><br/><br/><br/><br/><br/>";
            }
            

        }

    }
}