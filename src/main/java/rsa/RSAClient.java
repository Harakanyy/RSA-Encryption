package rsa;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.MessageDigest;

/**
 * RSAClient
 * Usage:
 *   java rsa.RSAClient <host> <port> <inputFile> <senderPrivKey> <receiverPubKey>
 */
public class RSAClient {
    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            System.out.println("Usage: java rsa.RSAClient "
                + "<host> <port> <inputFile> <senderPrivKey> <receiverPubKey>");
            return;
        }
        String host        = args[0];
        int port           = Integer.parseInt(args[1]);
        String inFile      = args[2];
        String senderKey   = args[3];
        String receiverKey = args[4];

        // load sender’s private key (n_s, d_s)
        BufferedReader br = new BufferedReader(new FileReader(senderKey));
        BigInteger n_s = new BigInteger(br.readLine());
        BigInteger d_s = new BigInteger(br.readLine());
        br.close();

        // load receiver’s public key (n_r, e_r)
        br = new BufferedReader(new FileReader(receiverKey));
        BigInteger n_r = new BigInteger(br.readLine());
        BigInteger e_r = new BigInteger(br.readLine());
        br.close();

        // read plaintext
        byte[] plain = Files.readAllBytes(Paths.get(inFile));

        // 1) sign: SHA-256(plain)^d_s mod n_s
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        BigInteger hashInt = new BigInteger(1, md.digest(plain));
        BigInteger sigInt  = hashInt.modPow(d_s, n_s);

        // 2) encrypt both blocks under receiver’s key
        BigInteger mInt = new BigInteger(1, plain);
        BigInteger c1   = mInt.modPow(e_r, n_r);
        BigInteger c2   = sigInt.modPow(e_r, n_r);

        // 3) open socket and send
        try (Socket sock = new Socket(host, port);
             PrintWriter out = new PrintWriter(sock.getOutputStream(), true)) {
            out.println(c1.toString());
            out.println(c2.toString());
            System.out.println("Sent ciphertext to " + host + ":" + port);
        }
    }
}
