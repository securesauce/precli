// level: WARNING
// start_line: 13
// end_line: 13
// start_column: 25
// end_column: 30
import java.net.*;


public class HttpCookieSecureFalse {
    public static void main(String[] args) {
        HttpCookie cookie = new HttpCookie("cookieName", "cookieValue");
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
    }
}
