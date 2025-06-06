public class Bad {
    public void run(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (IOException e) {
            // ignore
        }
    }
}
