package weibo4j.examples.user;

import weibo4j.Users;
import weibo4j.Weibo;
import weibo4j.examples.oauth2.Log;
import weibo4j.model.User;
import weibo4j.model.WeiboException;

public class ShowUser {

	public static void main(String[] args) {
		args = new String[]{"2.00lY18yCS6tsaC96cec5caca9aALLD", "2725359715"};
		String access_token = args[0];
		Weibo weibo = new Weibo();
		weibo.setToken(access_token);
		String uid =  args[1];
		Users um = new Users();
		try {
			User user = um.showUserById(uid);
			Log.logInfo(user.toString());
		} catch (WeiboException e) {
			e.printStackTrace();
		}
	}

}
