package weibo4j.examples.comment;

import weibo4j.Comments;
import weibo4j.Weibo;
import weibo4j.examples.oauth2.Log;
import weibo4j.model.Comment;
import weibo4j.model.CommentWapper;
import weibo4j.model.WeiboException;

public class GetCommentTimeline {

	public static void main(String[] args) {


		args = new String[]{"2.00irBQzBS6tsaC3168595db9i4VILD","1821309750"};
		
		String access_token = args[0];
		Weibo weibo = new Weibo();
		weibo.setToken(access_token);
		Comments cm = new Comments();
		try {
			CommentWapper comment = cm.getCommentTimeline();
			for(Comment c : comment.getComments()){
				Log.logInfo(c.toString());
			}
			System.out.println(comment.getTotalNumber());
			System.out.println(comment.getNextCursor());
			System.out.println(comment.getNextCursor());
			System.out.println(comment.getHasvisible());
		} catch (WeiboException e) {
			e.printStackTrace();
		}
	}

}
