package org.example;

import javax.net.ssl.SSLSocket;
import java.io.*;

public class SessionHandler extends Thread {
    private final SSLSocket socket;

    public SessionHandler(SSLSocket socket) {
        this.socket = socket;
    }

    public void run() {
        try (DataInputStream input = new DataInputStream(socket.getInputStream());
             DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {
            int numberOfFiles = input.readInt();

            for (int i = 0; i < numberOfFiles; i++) {
                String fileName = input.readUTF();
                long filesize = input.readLong();
                File file = new File("receivedfiles/" + fileName);

                try (FileOutputStream fos = new FileOutputStream(file)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;

                    while (filesize > 0 && (bytesRead = input.read(buffer,0, (int) Math.min(buffer.length, filesize))) != -1) {
                        fos.write(buffer,0,bytesRead);
                        filesize -= bytesRead;
                    }
                }

                output.writeUTF("File " + fileName + " received successfully.");
                System.out.println("File " + fileName + " received.");
            }
            String terminationMessage = input.readUTF();
            if (terminationMessage.equals("END_TRANSFER")) {
                System.out.println("Shutdown signal received. Server is shutting down...");
                socket.close();
                ConnectionManager.stopServer();
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
