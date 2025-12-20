import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.regex.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

public class Intrusense {

    private static final int MAX_FAILED = 5;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(30);
    private static final double STYLO_THRESHOLD = 0.65;

    public static class Database {
        private static final String DB_URL = System.getenv().getOrDefault("DB_URL",
                "jdbc:mysql://localhost:3306/auth_demo?useSSL=false&serverTimezone=UTC");
        private static final String DB_USER = System.getenv().getOrDefault("DB_USER", "root");
        private static final String DB_PASS = System.getenv().getOrDefault("DB_PASS", "Mysql#1");

        public static void init() {
            Connection conn = null;
            Statement stmt = null;
            try {
                conn = getConnection();
                System.out.println("Connected to DB: " + DB_URL);
                stmt = conn.createStatement();
                stmt.execute("CREATE TABLE IF NOT EXISTS security_events (" +
                        "id INT AUTO_INCREMENT PRIMARY KEY," +
                        "event_type VARCHAR(50) NOT NULL," +
                        "username VARCHAR(100)," +
                        "ip VARCHAR(45)," +
                        "details TEXT," +
                        "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                        ")");
            } catch (SQLException ex) {
                System.err.println("Database init failed: " + ex.getMessage());
            } finally {
                closeQuietly(stmt);
                closeQuietly(conn);
            }
        }

        public static Connection getConnection() throws SQLException {
            return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        }

        private static void closeQuietly(AutoCloseable r) {
            if (r == null) return;
            try { r.close(); } catch (Exception ignored) {}
        }
    }

    public static class Util {
        private static final Pattern SQL_PATTERN = Pattern.compile("(?i)\\b(select|union|insert|update|delete|drop|alter|truncate|--|;|/\\*)\\b");

        public static boolean detectSqlInjection(String s) {
            if (s == null) return false;
            return SQL_PATTERN.matcher(s).find();
        }

        public static class Profile {
            public final double avgWordLen;
            public final double uniqueWordRatio;
            public final double avgSentenceLen;

            public Profile(double avgWordLen, double uniqueWordRatio, double avgSentenceLen) {
                this.avgWordLen = avgWordLen;
                this.uniqueWordRatio = uniqueWordRatio;
                this.avgSentenceLen = avgSentenceLen;
            }
        }

        public static Profile computeStylometry(String text) {
            if (text == null) text = "";

            String[] sentences = text.split("[\\.!?]+");

            java.util.List<String> words = new ArrayList<String>();
            for (String raw : text.split("\\s+")) {
                String w = raw.replaceAll("[^\\p{L}\\p{N}']", "");
                if (w.length() > 0) words.add(w);
            }

            double avgWordLen = 0.0;
            if (words.size() > 0) {
                int totalLen = 0;
                for (String w : words) totalLen += w.length();
                avgWordLen = (double) totalLen / words.size();
            }

            double uniqueWordRatio = 0.0;
            if (words.size() > 0) {
                Set<String> uniq = new HashSet<String>();
                for (String w : words) uniq.add(w);
                uniqueWordRatio = (double) uniq.size() / words.size();
            }

            double avgSentenceLen = 0.0;
            int sentenceCount = 0;
            int totalSentWords = 0;
            for (String s : sentences) {
                String trim = s.trim();
                if (trim.length() == 0) continue;
                String[] ws = trim.split("\\s+");
                totalSentWords += ws.length;
                sentenceCount++;
            }
            if (sentenceCount > 0) {
                avgSentenceLen = (double) totalSentWords / sentenceCount;
            }

            return new Profile(avgWordLen, uniqueWordRatio, avgSentenceLen);
        }

        public static double similarity(Profile a, Profile b) {
            double[] fa = new double[] { a.avgWordLen / 8.0, a.uniqueWordRatio, a.avgSentenceLen / 20.0 };
            double[] fb = new double[] { b.avgWordLen / 8.0, b.uniqueWordRatio, b.avgSentenceLen / 20.0 };

            double dot = 0.0;
            double na = 0.0;
            double nb = 0.0;
            for (int i = 0; i < fa.length; i++) {
                dot += fa[i] * fb[i];
                na += fa[i] * fa[i];
                nb += fb[i] * fb[i];
            }
            if (na == 0.0 || nb == 0.0) return 0.0;
            return dot / (Math.sqrt(na) * Math.sqrt(nb));
        }
    }

    public static class PasswordUtil {
        private static final SecureRandom RANDOM = new SecureRandom();
        private static final int SALT_BYTES = 16;
        private static final int HASH_BYTES = 32;
        private static final int ITERATIONS = 10000;
        private static final String ALGO = "PBKDF2WithHmacSHA256";

        public static String hashPassword(String password) throws Exception {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);

            byte[] hash = pbkdf2(password.toCharArray(), salt, ITERATIONS, HASH_BYTES);

            String saltB64 = Base64.getEncoder().encodeToString(salt);
            String hashB64 = Base64.getEncoder().encodeToString(hash);
            return ITERATIONS + ":" + saltB64 + ":" + hashB64;
        }

        public static boolean verifyPassword(String password, String stored) throws Exception {
            if (stored == null) return false;
            String[] parts = stored.split(":");
            if (parts.length != 3) return false;
            int it = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] hash = Base64.getDecoder().decode(parts[2]);

            byte[] test = pbkdf2(password.toCharArray(), salt, it, hash.length);
            return slowEquals(hash, test);
        }

        private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes) throws Exception {
            KeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGO);
            return skf.generateSecret(spec).getEncoded();
        }

        private static boolean slowEquals(byte[] a, byte[] b) {
            if (a == null || b == null) return false;
            int diff = a.length ^ b.length;
            int len = Math.min(a.length, b.length);
            for (int i = 0; i < len; i++) {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }

    public static class UserService {

        public boolean enroll(String username, String password, String sampleText, String fingerprintPin) throws Exception {
            if (username == null || username.trim().isEmpty()) throw new IllegalArgumentException("username required");
            if (password == null) throw new IllegalArgumentException("password required");

            if (Util.detectSqlInjection(username) || Util.detectSqlInjection(password) || Util.detectSqlInjection(sampleText)) {
                throw new IllegalArgumentException("Input looks malicious (SQL detected).");
            }

            String hashed = PasswordUtil.hashPassword(password);

            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet keys = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement(
                        "INSERT INTO users (username, password_hash, fingerprint_pin) VALUES (?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS);
                ps.setString(1, username);
                ps.setString(2, hashed);
                if (fingerprintPin == null || fingerprintPin.trim().isEmpty()) {
                    ps.setNull(3, Types.VARCHAR);
                } else {
                    ps.setString(3, fingerprintPin);
                }
                ps.executeUpdate();
                keys = ps.getGeneratedKeys();
                if (keys.next()) {
                    int userId = keys.getInt(1);

                    Util.Profile profile = Util.computeStylometry(sampleText == null ? "" : sampleText);
                    PreparedStatement ps2 = null;
                    try {
                        ps2 = conn.prepareStatement(
                                "INSERT INTO stylometry (user_id, avg_word_len, uniq_word_ratio, avg_sent_len) VALUES (?, ?, ?, ?)");
                        ps2.setInt(1, userId);
                        ps2.setDouble(2, profile.avgWordLen);
                        ps2.setDouble(3, profile.uniqueWordRatio);
                        ps2.setDouble(4, profile.avgSentenceLen);
                        ps2.executeUpdate();
                    } finally {
                        if (ps2 != null) try { ps2.close(); } catch (Exception ignored) {}
                    }

                    logAttempt(userId, username, true, "local", "enroll");
                    return true;
                } else {
                    return false;
                }
            } finally {
                if (keys != null) try { keys.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
        }

        public Map<String,Object> attemptLogin(String username, String password, String sampleText, String ip, String fingerprintPinProvided) throws Exception {
            Map<String,Object> result = new HashMap<String,Object>();

            if (Util.detectSqlInjection(username) || Util.detectSqlInjection(password) || Util.detectSqlInjection(sampleText)) {
                logSecurityEvent("SQL_INJECTION_ATTEMPT", username, ip,
                        "Username: " + username + ", Password: " + password + ", Sample: " + sampleText);
                logAttempt(null, username, false, ip, "sql_injection_detected");
                result.put("ok", false);
                result.put("reason", "malicious_input");
                return result;
            }

            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement("SELECT id, password_hash, failed_count, locked_until, fingerprint_pin FROM users WHERE username = ?");
                ps.setString(1, username);
                rs = ps.executeQuery();
                if (!rs.next()) {
                    logAttempt(null, username, false, ip, "unknown_user");
                    result.put("ok", false);
                    result.put("reason", "invalid_credentials");
                    return result;
                }

                int userId = rs.getInt("id");
                String storedHash = rs.getString("password_hash");
                int failedCount = rs.getInt("failed_count");
                Timestamp lockedUntil = rs.getTimestamp("locked_until");
                String storedPin = rs.getString("fingerprint_pin");

                boolean fingerprintOk = false;
                if (fingerprintPinProvided != null && storedPin != null && !storedPin.trim().isEmpty()) {
                    fingerprintOk = storedPin.equals(fingerprintPinProvided);
                }

                if (lockedUntil != null && lockedUntil.toInstant().isAfter(Instant.now()) && !fingerprintOk) {
                    logAttempt(userId, username, false, ip, "account_locked");
                    result.put("ok", false);
                    result.put("reason", "locked");
                    result.put("lockedUntil", lockedUntil.toString());
                    return result;
                }

                boolean passwordOk = PasswordUtil.verifyPassword(password, storedHash);

                if (!passwordOk && !fingerprintOk) {
                    failedCount++;
                    PreparedStatement upr = null;
                    try {
                        upr = conn.prepareStatement("UPDATE users SET failed_count = ? WHERE id = ?");
                        upr.setInt(1, failedCount);
                        upr.setInt(2, userId);
                        upr.executeUpdate();
                    } finally {
                        if (upr != null) try { upr.close(); } catch (Exception ignored) {}
                    }

                    detectBruteForceAttack(ip);
                    detectPasswordSpraying(ip);

                    if (failedCount >= MAX_FAILED) {
                        Instant until = Instant.now().plus(LOCK_DURATION);
                        PreparedStatement lockp = null;
                        try {
                            lockp = conn.prepareStatement("UPDATE users SET locked_until = ? WHERE id = ?");
                            lockp.setTimestamp(1, Timestamp.from(until));
                            lockp.setInt(2, userId);
                            lockp.executeUpdate();
                        } finally {
                            if (lockp != null) try { lockp.close(); } catch (Exception ignored) {}
                        }
                        logSecurityEvent("ACCOUNT_LOCKED", username, ip,
                                "Account locked after " + MAX_FAILED + " failed attempts");
                        logAttempt(userId, username, false, ip, "locked_after_failed");
                        result.put("ok", false);
                        result.put("reason", "locked");
                        result.put("lockedUntil", Timestamp.from(until).toString());
                        return result;
                    } else {
                        logAttempt(userId, username, false, ip, "bad_password");
                        result.put("ok", false);
                        result.put("reason", "invalid_credentials");
                        result.put("failedCount", failedCount);
                        return result;
                    }
                }

                PreparedStatement reset = null;
                try {
                    reset = conn.prepareStatement("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = ?");
                    reset.setInt(1, userId);
                    reset.executeUpdate();
                } finally {
                    if (reset != null) try { reset.close(); } catch (Exception ignored) {}
                }

                boolean stylometryOk = true;
                String stylometryFlag = "none";
                if (sampleText != null && sampleText.trim().length() > 0) {
                    Util.Profile profile = Util.computeStylometry(sampleText);
                    PreparedStatement sp = null;
                    ResultSet r2 = null;
                    try {
                        sp = conn.prepareStatement("SELECT avg_word_len, uniq_word_ratio, avg_sent_len FROM stylometry WHERE user_id = ?");
                        sp.setInt(1, userId);
                        r2 = sp.executeQuery();
                        if (r2.next()) {
                            Util.Profile stored = new Util.Profile(r2.getDouble("avg_word_len"),
                                                                    r2.getDouble("uniq_word_ratio"),
                                                                    r2.getDouble("avg_sent_len"));
                            double sim = Util.similarity(profile, stored);
                            stylometryOk = sim >= STYLO_THRESHOLD;
                            stylometryFlag = String.format("similarity=%.3f", sim);
                            if (!stylometryOk) {
                                logSecurityEvent("STYLOMETRY_MISMATCH", username, ip,
                                        "Stylometry similarity: " + sim + " (threshold: " + STYLO_THRESHOLD + ")");
                            }
                        } else {
                            stylometryFlag = "no_profile";
                        }
                    } finally {
                        if (r2 != null) try { r2.close(); } catch (Exception ignored) {}
                        if (sp != null) try { sp.close(); } catch (Exception ignored) {}
                    }
                }

                detectSuspiciousPatterns(username, ip);
                detectAccountTakeover(username, ip);

                logAttempt(userId, username, true, ip, stylometryFlag);
                result.put("ok", true);
                result.put("stylometry_ok", stylometryOk);
                result.put("message", "login_success");
                return result;

            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
        }

        private void logAttempt(Integer userId, String usernameAttempted, boolean success, String ip, String reason) {
            Connection conn = null;
            PreparedStatement ps = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement(
                        "INSERT INTO login_logs (user_id, username_attempted, success, ip, reason) VALUES (?, ?, ?, ?, ?)");
                if (userId == null) ps.setNull(1, Types.INTEGER); else ps.setInt(1, userId);
                ps.setString(2, usernameAttempted);
                ps.setBoolean(3, success);
                ps.setString(4, ip);
                ps.setString(5, reason);
                ps.executeUpdate();
            } catch (SQLException e) {
                System.err.println("Failed to insert log: " + e.getMessage());
            } finally {
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
        }

        public void logSecurityEvent(String eventType, String username, String ip, String details) {
            Connection conn = null;
            PreparedStatement ps = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement(
                        "INSERT INTO security_events (event_type, username, ip, details) VALUES (?, ?, ?, ?)");
                ps.setString(1, eventType);
                ps.setString(2, username);
                ps.setString(3, ip);
                ps.setString(4, details);
                ps.executeUpdate();
            } catch (SQLException e) {
                System.err.println("Failed to log security event: " + e.getMessage());
            } finally {
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
        }

        public java.util.List<java.util.Map<String, Object>> getSecurityEvents(int limit) throws SQLException {
            java.util.List<java.util.Map<String,Object>> out = new ArrayList<java.util.Map<String,Object>>();
            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement(
                        "SELECT id, event_type, username, ip, details, timestamp FROM security_events ORDER BY timestamp DESC LIMIT ?");
                ps.setInt(1, limit);
                rs = ps.executeQuery();
                while (rs.next()) {
                    Map<String,Object> m = new HashMap<String,Object>();
                    m.put("id", rs.getInt("id"));
                    m.put("event_type", rs.getString("event_type"));
                    m.put("username", rs.getString("username"));
                    m.put("ip", rs.getString("ip"));
                    m.put("details", rs.getString("details"));
                    m.put("timestamp", rs.getTimestamp("timestamp").toString());
                    out.add(m);
                }
            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
            return out;
        }

        public Map<String,Integer> getSecurityStats() throws SQLException {
            Map<String,Integer> stats = new HashMap<String,Integer>();
            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();

                ps = conn.prepareStatement(
                        "SELECT COUNT(*) as count FROM security_events WHERE event_type = 'SQL_INJECTION_ATTEMPT' AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                rs = ps.executeQuery();
                if (rs.next()) stats.put("sql_injection", rs.getInt("count"));
                rs.close(); ps.close();

                ps = conn.prepareStatement(
                        "SELECT COUNT(*) as count FROM security_events WHERE event_type = 'BRUTE_FORCE_ATTACK' AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                rs = ps.executeQuery();
                if (rs.next()) stats.put("brute_force", rs.getInt("count"));
                rs.close(); ps.close();

                ps = conn.prepareStatement(
                        "SELECT COUNT(*) as count FROM security_events WHERE event_type IN ('MULTIPLE_IP_LOGIN', 'UNUSUAL_TIME_LOGIN', 'SUSPICIOUS_LOCATION_CHANGE') AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                rs = ps.executeQuery();
                if (rs.next()) stats.put("suspicious", rs.getInt("count"));
                rs.close(); ps.close();

                ps = conn.prepareStatement(
                        "SELECT COUNT(*) as count FROM security_events WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
                rs = ps.executeQuery();
                if (rs.next()) stats.put("total", rs.getInt("count"));
            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
            return stats;
        }

        public void detectBruteForceAttack(String ip) {
            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement(
                        "SELECT COUNT(*) as attempts FROM login_logs WHERE ip = ? AND success = false AND ts > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
                ps.setString(1, ip);
                rs = ps.executeQuery();
                if (rs.next() && rs.getInt("attempts") >= 10) {
                    logSecurityEvent("BRUTE_FORCE_ATTACK", null, ip,
                            "Multiple failed login attempts detected from this IP in the last 15 minutes");
                }
            } catch (SQLException e) {
                System.err.println("Failed to detect brute force attack: " + e.getMessage());
            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
        }

        public void detectSuspiciousPatterns(String username, String ip) {
            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();

                ps = conn.prepareStatement(
                        "SELECT COUNT(DISTINCT ip) as ip_count FROM login_logs WHERE username_attempted = ? AND ts > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
                ps.setString(1, username);
                rs = ps.executeQuery();
                if (rs.next() && rs.getInt("ip_count") >= 3) {
                    logSecurityEvent("MULTIPLE_IP_LOGIN", username, ip,
                            "Login attempts from multiple IPs detected in the last hour");
                }
                rs.close(); ps.close();

                ps = conn.prepareStatement(
                        "SELECT COUNT(*) as attempts FROM login_logs WHERE username_attempted = ? AND success = true AND HOUR(ts) BETWEEN 2 AND 5 AND ts > DATE_SUB(NOW(), INTERVAL 7 DAY)");
                ps.setString(1, username);
                rs = ps.executeQuery();
                if (rs.next() && rs.getInt("attempts") > 0) {
                    logSecurityEvent("UNUSUAL_TIME_LOGIN", username, ip,
                            "Login attempts at unusual hours (2 AM - 5 AM) detected");
                }
            } catch (SQLException e) {
                System.err.println("Failed to detect suspicious patterns: " + e.getMessage());
            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
        }

        public void detectAccountTakeover(String username, String ip) {
            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement(
                        "SELECT ip FROM login_logs WHERE username_attempted = ? AND success = true ORDER BY ts DESC LIMIT 2");
                ps.setString(1, username);
                rs = ps.executeQuery();

                String lastIp = null;
                if (rs.next()) {
                    lastIp = rs.getString("ip");
                }
                if (lastIp != null && !lastIp.equals(ip)) {
                    logSecurityEvent("SUSPICIOUS_LOCATION_CHANGE", username, ip,
                            "Login from a new IP address detected. Previous IP: " + lastIp);
                }
            } catch (SQLException e) {
                System.err.println("Failed to detect account takeover: " + e.getMessage());
            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
        }

        public void detectPasswordSpraying(String ip) {
            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement(
                        "SELECT COUNT(DISTINCT username_attempted) as user_count FROM login_logs WHERE ip = ? AND success = false AND ts > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
                ps.setString(1, ip);
                rs = ps.executeQuery();
                if (rs.next() && rs.getInt("user_count") >= 5) {
                    logSecurityEvent("PASSWORD_SPRAYING", null, ip,
                            "Attempts to login to multiple accounts from the same IP detected");
                }
            } catch (SQLException e) {
                System.err.println("Failed to detect password spraying: " + e.getMessage());
            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
        }

        public java.util.List<java.util.Map<String,Object>> getRecentLogs(int limit) throws SQLException {
            java.util.List<java.util.Map<String,Object>> out = new ArrayList<java.util.Map<String,Object>>();
            Connection conn = null;
            PreparedStatement ps = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();
                ps = conn.prepareStatement("SELECT id, user_id, username_attempted, success, ip, reason, ts FROM login_logs ORDER BY ts DESC LIMIT ?");
                ps.setInt(1, limit);
                rs = ps.executeQuery();
                while (rs.next()) {
                    Map<String,Object> m = new HashMap<String,Object>();
                    m.put("id", rs.getInt("id"));
                    Object uid = rs.getObject("user_id");
                    m.put("user_id", uid);
                    m.put("username_attempted", rs.getString("username_attempted"));
                    m.put("success", rs.getBoolean("success"));
                    m.put("ip", rs.getString("ip"));
                    m.put("reason", rs.getString("reason"));
                    m.put("ts", rs.getTimestamp("ts").toString());
                    out.add(m);
                }
            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (ps != null) try { ps.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
            return out;
        }

        public java.util.List<java.util.Map<String,Object>> listUsers() throws SQLException {
            java.util.List<java.util.Map<String,Object>> out = new ArrayList<java.util.Map<String,Object>>();
            Connection conn = null;
            Statement st = null;
            ResultSet rs = null;
            try {
                conn = Database.getConnection();
                st = conn.createStatement();
                rs = st.executeQuery("SELECT id, username, failed_count, locked_until, fingerprint_pin FROM users ORDER BY id");
                while (rs.next()) {
                    Map<String,Object> m = new HashMap<String,Object>();
                    m.put("id", rs.getInt("id"));
                    m.put("username", rs.getString("username"));
                    m.put("failed_count", rs.getInt("failed_count"));
                    m.put("locked_until", rs.getTimestamp("locked_until"));
                    m.put("fingerprint_pin", rs.getString("fingerprint_pin"));
                    out.add(m);
                }
            } finally {
                if (rs != null) try { rs.close(); } catch (Exception ignored) {}
                if (st != null) try { st.close(); } catch (Exception ignored) {}
                if (conn != null) try { conn.close(); } catch (Exception ignored) {}
            }
            return out;
        }
    }

    private final UserService userService = new UserService();

    public static void main(String[] args) {
        boolean adminMode = (args != null && args.length > 0 && "admin".equalsIgnoreCase(args[0]));

        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (Exception ignored) {}

        Database.init();

        Intrusense app = new Intrusense();
        if (adminMode) {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() { app.createAndShowAdminOnly(); }
            });
        } else {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() { app.createAndShowGui(); }
            });
        }
    }

    private void createAndShowAdminOnly() {
        JFrame frame = new JFrame("Intrusense - Admin Dashboard");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(900, 600);
        frame.setLocationRelativeTo(null);
        frame.getContentPane().add(createAdminPanel());
        frame.setVisible(true);
    }

    private void createAndShowGui() {
        JFrame frame = new JFrame("Intrusense (Simplified)");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(900, 620);
        frame.setLocationRelativeTo(null);

        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(new EmptyBorder(10,10,10,10));
        JLabel title = new JLabel("Intrusense - Stylometry + Fingerprint (simulated)");
        title.setFont(new Font("SansSerif", Font.BOLD, 16));
        header.add(title, BorderLayout.WEST);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Welcome", createWelcomePanel());
        tabs.addTab("Enroll", createEnrollPanel());
        tabs.addTab("Login", createLoginPanel());
        tabs.addTab("Security Events", createSecurityEventsPanel());
        tabs.addTab("Security Dashboard", createSecurityDashboard());
        tabs.addTab("Admin Logs", createAdminPanel());

        frame.getContentPane().setLayout(new BorderLayout());
        frame.getContentPane().add(header, BorderLayout.NORTH);
        frame.getContentPane().add(tabs, BorderLayout.CENTER);
        frame.setVisible(true);
    }

    private JPanel createWelcomePanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(12,12,12,12));
        JTextArea text = new JTextArea();
        text.setEditable(false);
        text.setText("Welcome to the Intrusense desktop app (simplified).\n\n"
                + " - Use 'Enroll' to add users (optionally register a fingerprint PIN).\n"
                + " - Use 'Login' to authenticate; fingerprint PIN can bypass locks.\n"
                + " - 'Security Events' shows detected incidents.\n"
                + " - 'Security Dashboard' shows basic counts.\n"
                + " - 'Admin Logs' shows recent login logs and user list.\n");
        p.add(new JScrollPane(text), BorderLayout.CENTER);
        return p;
    }

    private JPanel createEnrollPanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(12,12,12,12));
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6,6,6,6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        form.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1;
        final JTextField userField = new JTextField(30);
        form.add(userField, gbc);

        gbc.gridx = 0; gbc.gridy++;
        form.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        final JPasswordField passField = new JPasswordField(30);
        form.add(passField, gbc);

        gbc.gridx = 0; gbc.gridy++;
        form.add(new JLabel("Sample text (stylometry):"), gbc);
        gbc.gridx = 1;
        final JTextArea sampleArea = new JTextArea(6, 40);
        form.add(new JScrollPane(sampleArea), gbc);

        gbc.gridx = 0; gbc.gridy++;
        gbc.gridwidth = 2;
        final JCheckBox fpRegister = new JCheckBox("Register fingerprint (simulate via PIN)");
        form.add(fpRegister, gbc);

        gbc.gridy++;
        final JButton enrollBtn = new JButton("Enroll");
        form.add(enrollBtn, gbc);

        enrollBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                final String username = userField.getText().trim();
                final String password = new String(passField.getPassword());
                final String sample = sampleArea.getText();
                final String[] fpPinHolder = new String[1];

                if (fpRegister.isSelected()) {
                    String pin = JOptionPane.showInputDialog(null, "Set a numeric fingerprint PIN to simulate fingerprint (4-6 digits):", "Register Fingerprint PIN", JOptionPane.PLAIN_MESSAGE);
                    if (pin == null) return;
                    if (!pin.matches("\\d{4,6}")) {
                        JOptionPane.showMessageDialog(null, "PIN must be 4 to 6 digits", "Invalid PIN", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    fpPinHolder[0] = pin;
                }

                enrollBtn.setEnabled(false);
                SwingWorker<Boolean,Void> worker = new SwingWorker<Boolean,Void>() {
                    Exception ex = null;
                    protected Boolean doInBackground() {
                        try {
                            return userService.enroll(username, password, sample, fpPinHolder[0]);
                        } catch (Exception err) {
                            ex = err;
                            return false;
                        }
                    }
                    protected void done() {
                        enrollBtn.setEnabled(true);
                        try {
                            if (ex != null) {
                                JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Enroll failed", JOptionPane.ERROR_MESSAGE);
                                return;
                            }
                            boolean ok = get();
                            if (ok) {
                                JOptionPane.showMessageDialog(null, "User enrolled successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
                                userField.setText("");
                                passField.setText("");
                                sampleArea.setText("");
                                fpRegister.setSelected(false);
                            } else {
                                JOptionPane.showMessageDialog(null, "Failed to enroll user.", "Error", JOptionPane.ERROR_MESSAGE);
                            }
                        } catch (Exception ex2) {
                            JOptionPane.showMessageDialog(null, "Unexpected error: " + ex2.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                };
                worker.execute();
            }
        });

        p.add(form, BorderLayout.CENTER);
        return p;
    }

    private JPanel createLoginPanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(12,12,12,12));
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6,6,6,6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        form.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1;
        final JTextField userField = new JTextField(30);
        form.add(userField, gbc);

        gbc.gridx = 0; gbc.gridy++;
        form.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        final JPasswordField passField = new JPasswordField(30);
        form.add(passField, gbc);

        gbc.gridx = 0; gbc.gridy++;
        form.add(new JLabel("Sample text (optional):"), gbc);
        gbc.gridx = 1;
        final JTextArea sampleArea = new JTextArea(6, 40);
        form.add(new JScrollPane(sampleArea), gbc);

        gbc.gridx = 0; gbc.gridy++;
        gbc.gridwidth = 2;
        final JCheckBox useFingerprint = new JCheckBox("Use fingerprint (simulated) to bypass lock/wait");
        form.add(useFingerprint, gbc);

        gbc.gridy++;
        final JButton loginBtn = new JButton("Login");
        form.add(loginBtn, gbc);

        loginBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                final String username = userField.getText().trim();
                final String password = new String(passField.getPassword());
                final String sample = sampleArea.getText();
                final String[] fpProvided = new String[1];

                if (useFingerprint.isSelected()) {
                    String pin = JOptionPane.showInputDialog(null, "Enter your fingerprint PIN to scan (simulated):", "Fingerprint Scan", JOptionPane.PLAIN_MESSAGE);
                    if (pin == null) return;
                    fpProvided[0] = pin;
                }

                loginBtn.setEnabled(false);
                SwingWorker<Map<String,Object>,Void> worker = new SwingWorker<Map<String,Object>,Void>() {
                    Exception ex = null;
                    protected Map<String,Object> doInBackground() {
                        try {
                            return userService.attemptLogin(username, password, sample, "local", fpProvided[0]);
                        } catch (Exception err) {
                            ex = err;
                            return null;
                        }
                    }
                    protected void done() {
                        loginBtn.setEnabled(true);
                        try {
                            if (ex != null) {
                                JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Login failed", JOptionPane.ERROR_MESSAGE);
                                return;
                            }
                            Map<String,Object> result = get();
                            Boolean ok = (Boolean) result.get("ok");
                            if (Boolean.TRUE.equals(ok)) {
                                boolean stylok = Boolean.TRUE.equals(result.get("stylometry_ok"));
                                String msg = "Login successful.\nStylometry match: " + stylok;
                                JOptionPane.showMessageDialog(null, msg, "Success", JOptionPane.INFORMATION_MESSAGE);
                                userField.setText("");
                                passField.setText("");
                                sampleArea.setText("");
                            } else {
                                String reason = String.valueOf(result.getOrDefault("reason", "unknown"));
                                if ("locked".equals(reason)) {
                                    String lockedUntil = String.valueOf(result.getOrDefault("lockedUntil", ""));
                                    JOptionPane.showMessageDialog(null, "Account locked until: " + lockedUntil + "\nYou can use fingerprint (if registered) to bypass.", "Locked", JOptionPane.WARNING_MESSAGE);
                                } else {
                                    JOptionPane.showMessageDialog(null, "Login failed: " + reason, "Failed", JOptionPane.ERROR_MESSAGE);
                                }
                            }
                        } catch (Exception ex2) {
                            JOptionPane.showMessageDialog(null, "Error: " + ex2.getMessage(), "Login failed", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                };
                worker.execute();
            }
        });

        p.add(form, BorderLayout.CENTER);
        return p;
    }

    private JPanel createSecurityEventsPanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(12,12,12,12));

        final JTextArea eventsArea = new JTextArea();
        eventsArea.setEditable(false);
        eventsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        final JButton loadEvents = new JButton("Load Security Events");
        top.add(loadEvents);

        loadEvents.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                loadEvents.setEnabled(false);
                eventsArea.setText("Loading security events...");
                SwingWorker<java.util.List<java.util.Map<String,Object>>,Void> worker = new SwingWorker<java.util.List<java.util.Map<String,Object>>,Void>() {
                    Exception ex = null;
                    protected java.util.List<java.util.Map<String,Object>> doInBackground() {
                        try {
                            return userService.getSecurityEvents(100);
                        } catch (Exception err) {
                            ex = err;
                            return null;
                        }
                    }
                    protected void done() {
                        loadEvents.setEnabled(true);
                        if (ex != null) {
                            eventsArea.setText("Error: " + ex.getMessage());
                            return;
                        }
                        try {
                            java.util.List<java.util.Map<String,Object>> ev = get();
                            StringBuilder sb = new StringBuilder();
                            if (ev == null || ev.size() == 0) {
                                sb.append("No security events detected.\n");
                            } else {
                                sb.append("=== SECURITY EVENTS ===\n\n");
                                for (Map<String,Object> event : ev) {
                                    sb.append(String.format("[%s] Type: %s\nUser: %s\nIP: %s\nDetails: %s\n\n",
                                            event.get("timestamp"), event.get("event_type"),
                                            event.get("username"), event.get("ip"), event.get("details")));
                                }
                            }
                            eventsArea.setText(sb.toString());
                        } catch (Exception e1) {
                            eventsArea.setText("Error processing events: " + e1.getMessage());
                        }
                    }
                };
                worker.execute();
            }
        });

        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(eventsArea), BorderLayout.CENTER);
        return p;
    }

    private JPanel createSecurityDashboard() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(12,12,12,12));

        JPanel statsPanel = new JPanel(new GridLayout(2, 2, 10, 10));
        final JLabel sqlInjectionLabel = new JLabel("SQL Injection Attempts: 0");
        final JLabel bruteForceLabel = new JLabel("Brute Force Attacks: 0");
        final JLabel suspiciousActivityLabel = new JLabel("Suspicious Activities: 0");
        final JLabel totalEventsLabel = new JLabel("Total Security Events: 0");

        statsPanel.add(sqlInjectionLabel);
        statsPanel.add(bruteForceLabel);
        statsPanel.add(suspiciousActivityLabel);
        statsPanel.add(totalEventsLabel);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        final JButton refreshStats = new JButton("Refresh Statistics");
        top.add(refreshStats);

        refreshStats.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                refreshStats.setEnabled(false);
                SwingWorker<Map<String,Integer>,Void> worker = new SwingWorker<Map<String,Integer>,Void>() {
                    protected Map<String,Integer> doInBackground() {
                        try {
                            return userService.getSecurityStats();
                        } catch (Exception ex) {
                            System.err.println("Failed to get security statistics: " + ex.getMessage());
                            return new HashMap<String,Integer>();
                        }
                    }
                    protected void done() {
                        refreshStats.setEnabled(true);
                        try {
                            Map<String,Integer> stats = get();
                            sqlInjectionLabel.setText("SQL Injection Attempts: " + stats.getOrDefault("sql_injection", 0));
                            bruteForceLabel.setText("Brute Force Attacks: " + stats.getOrDefault("brute_force", 0));
                            suspiciousActivityLabel.setText("Suspicious Activities: " + stats.getOrDefault("suspicious", 0));
                            totalEventsLabel.setText("Total Security Events: " + stats.getOrDefault("total", 0));
                        } catch (Exception ex) {
                            System.err.println("Error updating stats: " + ex.getMessage());
                        }
                    }
                };
                worker.execute();
            }
        });

        p.add(top, BorderLayout.NORTH);
        p.add(statsPanel, BorderLayout.CENTER);
        return p;
    }

    private JPanel createAdminPanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(12,12,12,12));

        final JTextArea logsArea = new JTextArea();
        logsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logsArea.setEditable(false);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        final JButton loadLogs = new JButton("Load recent logs");
        final JButton loadUsers = new JButton("Load users");
        top.add(loadLogs);
        top.add(loadUsers);

        loadLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                loadLogs.setEnabled(false);
                logsArea.setText("Loading logs...");
                SwingWorker<java.util.List<java.util.Map<String,Object>>,Void> worker = new SwingWorker<java.util.List<java.util.Map<String,Object>>,Void>() {
                    Exception ex = null;
                    protected java.util.List<java.util.Map<String,Object>> doInBackground() {
                        try {
                            return userService.getRecentLogs(500);
                        } catch (Exception err) {
                            ex = err;
                            return null;
                        }
                    }
                    protected void done() {
                        loadLogs.setEnabled(true);
                        if (ex != null) {
                            logsArea.setText("Error: " + ex.getMessage());
                            return;
                        }
                        try {
                            java.util.List<java.util.Map<String,Object>> logs = get();
                            StringBuilder sb = new StringBuilder();
                            if (logs == null || logs.size() == 0) sb.append("No logs.\n");
                            else {
                                for (Map<String,Object> r : logs) {
                                    sb.append(String.format("[%s] user_id=%s attempted='%s' success=%s reason=%s ip=%s\n",
                                            r.get("ts"), r.get("user_id"), r.get("username_attempted"), r.get("success"), r.get("reason"), r.get("ip")));
                                }
                            }
                            logsArea.setText(sb.toString());
                        } catch (Exception ex) {
                            logsArea.setText("Error: " + ex.getMessage());
                        }
                    }
                };
                worker.execute();
            }
        });

        loadUsers.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                loadUsers.setEnabled(false);
                logsArea.setText("Loading users...");
                SwingWorker<java.util.List<java.util.Map<String,Object>>,Void> worker = new SwingWorker<java.util.List<java.util.Map<String,Object>>,Void>() {
                    Exception ex = null;
                    protected java.util.List<java.util.Map<String,Object>> doInBackground() {
                        try {
                            return userService.listUsers();
                        } catch (Exception err) {
                            ex = err;
                            return null;
                        }
                    }
                    protected void done() {
                        loadUsers.setEnabled(true);
                        if (ex != null) {
                            logsArea.setText("Error: " + ex.getMessage());
                            return;
                        }
                        try {
                            java.util.List<java.util.Map<String,Object>> users = get();
                            StringBuilder sb = new StringBuilder();
                            if (users == null || users.size() == 0) sb.append("No users.\n");
                            else {
                                for (Map<String,Object> u : users) {
                                    Object locked = u.get("locked_until");
                                    sb.append(String.format("id=%s username=%s failed=%s locked_until=%s fingerprint=%s\n",
                                            u.get("id"), u.get("username"), u.get("failed_count"),
                                            locked == null ? "null" : locked.toString(),
                                            u.get("fingerprint_pin") == null ? "no" : "yes"));
                                }
                            }
                            logsArea.setText(sb.toString());
                        } catch (Exception ex) {
                            logsArea.setText("Error: " + ex.getMessage());
                        }
                    }
                };
                worker.execute();
            }
        });

        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(logsArea), BorderLayout.CENTER);
        return p;
    }
}