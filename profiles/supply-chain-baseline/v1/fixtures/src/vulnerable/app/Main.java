import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

// Deliberately insecure fixture: command and SQL injection for the SAST check.
public class Main {
    public static void run(String userInput) throws IOException {
        Runtime.getRuntime().exec("sh -c " + userInput);
    }

    public static void find(Connection c, String user) throws SQLException {
        Statement s = c.createStatement();
        s.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }
}
