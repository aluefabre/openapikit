package weibo4j;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.log4j.Logger;

import weibo4j.http.AccessToken;
import weibo4j.http.BASE64Encoder;
import weibo4j.model.PostParameter;
import weibo4j.model.WeiboException;
import weibo4j.org.json.JSONException;
import weibo4j.org.json.JSONObject;
import weibo4j.util.WeiboConfig;

public class Oauth {
	// ----------------------------针对站内应用处理SignedRequest获取accesstoken----------------------------------------
	public String access_token;
	public String user_id;

	public String getToken() {
		return access_token;
	}

	/*
	 * 解析站内应用post的SignedRequest split为part1和part2两部分
	 */

	@SuppressWarnings("restriction")
	public String parseSignedRequest(String signed_request) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException {
		String[] t = signed_request.split("\\.", 2);
		// 为了和 url encode/decode 不冲突，base64url 编码方式会将
		// '+'，'/'转换成'-'，'_'，并且去掉结尾的'='。 因此解码之前需要还原到默认的base64编码，结尾的'='可以用以下算法还原
		int padding = (4 - t[0].length() % 4);
		for (int i = 0; i < padding; i++)
			t[0] += "=";
		String part1 = t[0].replace("-", "+").replace("_", "/");

		SecretKey key = new SecretKeySpec(WeiboConfig.getValue("client_SERCRET").getBytes(), "hmacSHA256");
		Mac m;
		m = Mac.getInstance("hmacSHA256");
		m.init(key);
		m.update(t[1].getBytes());
		String part1Expect = BASE64Encoder.encode(m.doFinal());

		sun.misc.BASE64Decoder decode = new sun.misc.BASE64Decoder();
		String s = new String(decode.decodeBuffer(t[1]));
		if (part1.equals(part1Expect)) {
			return ts(s);
		} else {
			return null;
		}
	}

	/*
	 * 处理解析后的json解析
	 */
	public String ts(String json) {
		try {
			JSONObject jsonObject = new JSONObject(json);
			access_token = jsonObject.getString("oauth_token");
			user_id = jsonObject.getString("user_id");
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return access_token;

	}

	/*----------------------------Oauth接口--------------------------------------*/

	public AccessToken getAccessTokenByCode(String code) throws WeiboException {
		return new AccessToken(Weibo.client.post(WeiboConfig.getValue("accessTokenURL"), new PostParameter[] {
				new PostParameter("client_id", WeiboConfig.getValue("client_ID")),
				new PostParameter("client_secret", WeiboConfig.getValue("client_SERCRET")),
				new PostParameter("grant_type", "authorization_code"), new PostParameter("code", code),
				new PostParameter("redirect_uri", WeiboConfig.getValue("redirect_URI")) }, false));
	}

	static Logger log = Logger.getLogger(Oauth.class.getName());

	public AccessToken refreshToken(String userName, String passwd) throws WeiboException {
		try {
			String url = WeiboConfig.getValue("authorizeURL");
			PostMethod postMethod = new PostMethod(url);
			postMethod.addParameter("client_id", WeiboConfig.getValue("client_ID"));
			postMethod.addParameter("redirect_uri", WeiboConfig.getValue("redirect_URI"));
			postMethod.addParameter("userId", userName);
			postMethod.addParameter("passwd", passwd);
			postMethod.addParameter("isLoginSina", "0");
			postMethod.addParameter("action", "submit");
			postMethod.addParameter("response_type", "code");// code
			HttpMethodParams param = postMethod.getParams();
			param.setContentCharset("UTF-8");
			List<Header> headers = new ArrayList<Header>();
			headers.add(new Header(
					"Referer",
					"https://api.weibo.com/oauth2/authorize?client_id=your_client_id&redirect_uri=your_redirect_url&from=sina&response_type=code"));// 伪造referer
			headers.add(new Header("Host", "api.weibo.com"));
			headers.add(new Header("User-Agent", "Mozilla/5.0 (Windows NT 6.1; rv:11.0) Gecko/20100101 Firefox/11.0"));
			HttpClient client = new HttpClient();
			client.getHostConfiguration().getParams().setParameter("http.default-headers", headers);
			client.executeMethod(postMethod);
			int status = postMethod.getStatusCode();
			if (status != 302) {
				log.error("refresh token failed");
				if(status==200){
					String response = postMethod.getResponseBodyAsString();
					log.error(response);
				}
				return null;
			}
			Header location = postMethod.getResponseHeader("Location");
			if (location != null) {
				String retUrl = location.getValue();
				int begin = retUrl.indexOf("code=");
				if (begin != -1) {
					int end = retUrl.indexOf("&", begin);
					if (end == -1)
						end = retUrl.length();
					String code = retUrl.substring(begin + 5, end);
					if (code != null) {
						AccessToken token = getAccessTokenByCode(code);
						return token;
					}
				}
			}
		} catch (FileNotFoundException e) {
			log.error("error" + e);
		} catch (IOException e) {
			log.error("error" + e);
		}
		log.error("refresh token failed");
		return null;
	}

	public String authorize(String response_type) throws WeiboException {
		return WeiboConfig.getValue("authorizeURL").trim() + "?client_id=" + WeiboConfig.getValue("client_ID").trim()
				+ "&redirect_uri=" + WeiboConfig.getValue("redirect_URI").trim() + "&response_type=" + response_type;
	}
}
