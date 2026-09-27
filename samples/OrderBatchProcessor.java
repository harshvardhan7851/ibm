package com.enterprise.legacy;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

// Legacy Batch Processor written for Java 7/8
public class OrderBatchProcessor {
    private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); // BUG: Not thread-safe!

    public void processOrders(List<String> orderIds) {
        for (final String orderId : orderIds) {
            // ANTI-PATTERN: Unbounded thread spawning
            new Thread(new Runnable() {
                public void run() {
                    try {
                        Connection conn = DriverManager.getConnection("jdbc:legacy:db");
                        Statement stmt = conn.createStatement();
                        String dateStr = dateFormat.format(new Date());

                        stmt.executeUpdate("UPDATE orders SET processed_at = '" + dateStr + "' WHERE id = " + orderId);

                        // LEAK: Missing conn.close() / stmt.close() in finally block
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }
}
