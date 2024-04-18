// level: NONE
import java.net.*;


public class HttpCookieSecureTrue {
    public static void main(String[] args) {
        HttpCookie cookie = new HttpCookie("cookieName", "cookieValue");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
    }
}
