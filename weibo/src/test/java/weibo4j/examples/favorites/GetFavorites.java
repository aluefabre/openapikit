package weibo4j.examples.favorites;

import java.util.List;

import weibo4j.Favorite;
import weibo4j.Weibo;
import weibo4j.examples.oauth2.Log;
import weibo4j.model.Favorites;
import weibo4j.model.WeiboException;

public class GetFavorites {

	public static void main(String[] args) {
		String access_token = "2.00RQs9XCjP8_PC27953e0bc62cwKCE";
		Weibo weibo = new Weibo();
		weibo.setToken(access_token);
		Favorite fm = new Favorite();
		try {
			List<Favorites> favors = fm.getFavorites();
			for(Favorites s : favors){
				Log.logInfo(s.toString());
			}
		} catch (WeiboException e) {
			e.printStackTrace();
		}
	}

}
