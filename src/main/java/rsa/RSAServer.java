package rsa;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;

/**
 * RSAServer
 * Usage:
 *   java rsa.RSAServer <port> <receiverPrivKey> <senderPubKey> <outputFile>
 */
public class RSAServer {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Usage: java rsa.RSAServer "
                + "<port> <receiverPrivKey> <senderPubKey> <outputFile>");
            return;
        }
        int port           = Integer.parseInt(args[0]);
        String recvKey     = args[1];
        String senderKey   = args[2];
        String outFile     = args[3];

        // load receiver’s private key (n_r, d_r)
        BufferedReader br = new BufferedReader(new FileReader(recvKey));
        BigInteger n_r = new BigInteger(br.readLine());
        BigInteger d_r = new BigInteger(br.readLine());
        br.close();

        // load sender’s public key (n_s, e_s)
        br = new BufferedReader(new FileReader(senderKey));
        BigInteger n_s = new BigInteger(br.readLine());
        BigInteger e_s = new BigInteger(br.readLine());
        br.close();

        System.out.println("Server listening on port " + port + " ...");
        try (ServerSocket server = new ServerSocket(port);
             Socket client = server.accept();
             BufferedReader in = new BufferedReader(
                                   new java.io.InputStreamReader(client.getInputStream()))) {

            // read the two ciphertext lines
            BigInteger c1 = new BigInteger(in.readLine());
            BigInteger c2 = new BigInteger(in.readLine());
            System.out.println("Received ciphertext from client");

            // decrypt
            BigInteger mInt   = c1.modPow(d_r, n_r);
            BigInteger sigInt = c2.modPow(d_r, n_r);

            // recover plaintext
            byte[] plain = mInt.toByteArray();
            if (plain[0] == 0) {
                byte[] tmp = new byte[plain.length - 1];
                System.arraycopy(plain, 1, tmp, 0, tmp.length);
                plain = tmp;
            }

            // verify signature
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            BigInteger hashInt = new BigInteger(1, md.digest(plain));
            boolean ok = hashInt.equals(sigInt.modPow(e_s, n_s));
            System.out.println("Signature valid? " + ok);

            // write output file
            try (PrintWriter fout = new PrintWriter(outFile)) {
                fout.write(new String(plain));
            }
            System.out.println("Wrote decrypted plaintext to " + outFile);
        }
    }
}
