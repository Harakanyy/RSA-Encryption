package rsa;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.List;

public class RSAAuthDecrypt {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Usage: java rsa.RSAAuthDecrypt "
                + "<cipherFile> <receiverPrivKey> <senderPubKey> <outputFile>");
            return;
        }
        String cFile     = args[0];
        String recvKey   = args[1];
        String senderKey = args[2];
        String outFile   = args[3];

        // -- load receiver’s private key (n_r, d_r)
        BufferedReader br = new BufferedReader(new FileReader(recvKey));
        BigInteger n_r = new BigInteger(br.readLine());
        BigInteger d_r = new BigInteger(br.readLine());
        br.close();

        // -- load sender’s public key (n_s, e_s)
        br = new BufferedReader(new FileReader(senderKey));
        BigInteger n_s = new BigInteger(br.readLine());
        BigInteger e_s = new BigInteger(br.readLine());
        br.close();

        // -- read the two ciphertext lines
        List<String> lines = Files.readAllLines(Paths.get(cFile));
        BigInteger c1 = new BigInteger(lines.get(0));
        BigInteger c2 = new BigInteger(lines.get(1));

        // 1) decrypt them
        BigInteger mInt   = c1.modPow(d_r, n_r);
        BigInteger sigInt = c2.modPow(d_r, n_r);

        // 2) recover plaintext bytes
        byte[] plain = mInt.toByteArray();
        if (plain[0] == 0) {
            byte[] tmp = new byte[plain.length - 1];
            System.arraycopy(plain, 1, tmp, 0, tmp.length);
            plain = tmp;
        }

        // 3) verify signature
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        BigInteger hashInt     = new BigInteger(1, md.digest(plain));
        boolean ok = hashInt.equals(sigInt.modPow(e_s, n_s));
        System.out.println("Signature valid? " + ok);

        // 4) write recovered plaintext
        try (PrintWriter out = new PrintWriter(outFile)) {
            out.write(new String(plain));
        }
        System.out.println("Decrypted → " + outFile);
    }
}
