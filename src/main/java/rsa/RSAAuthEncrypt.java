package rsa;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.security.MessageDigest;

public class RSAAuthEncrypt {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Usage: java rsa.RSAAuthEncrypt "
                + "<inputFile> <senderPrivKey> <receiverPubKey> <outputFile>");
            return;
        }
        String inFile      = args[0];
        String senderKey   = args[1];
        String receiverKey = args[2];
        String outFile     = args[3];

        // -- load sender’s private key (n_s, d_s)
        BufferedReader br = new BufferedReader(new FileReader(senderKey));
        BigInteger n_s = new BigInteger(br.readLine());
        BigInteger d_s = new BigInteger(br.readLine());
        br.close();

        // -- load receiver’s public key (n_r, e_r)
        br = new BufferedReader(new FileReader(receiverKey));
        BigInteger n_r = new BigInteger(br.readLine());
        BigInteger e_r = new BigInteger(br.readLine());
        br.close();

        // -- read plaintext
        byte[] plain = Files.readAllBytes(Paths.get(inFile));

        // 1) sign: hash = SHA256(plain), sig = hash^d_s mod n_s
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        BigInteger hashInt = new BigInteger(1, md.digest(plain));
        BigInteger sigInt  = hashInt.modPow(d_s, n_s);

        // 2) encrypt both as separate blocks
        BigInteger mInt  = new BigInteger(1, plain);
        BigInteger c1    = mInt.modPow(e_r, n_r);
        BigInteger c2    = sigInt.modPow(e_r, n_r);

        // 3) write two lines: ciphertext-of-message, ciphertext-of-signature
        try (PrintWriter out = new PrintWriter(outFile)) {
            out.println(c1.toString());
            out.println(c2.toString());
        }
        System.out.println("Authenticated & encrypted → " + outFile);
    }
}
