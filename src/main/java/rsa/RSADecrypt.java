package rsa;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.List;

/**
 * RSADecrypt
 * Usage: java rsa.RSADecrypt <cipherFile> <privateKeyFile> <outputFile>
 */
public class RSADecrypt {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: java rsa.RSADecrypt <cipherFile> <privateKeyFile> <outputFile>");
            return;
        }

        String cipherFile   = args[0];
        String privKeyFile  = args[1];
        String outputFile   = args[2];

        // 1. Load private key (n, d)
        BufferedReader keyReader = new BufferedReader(new FileReader(privKeyFile));
        BigInteger n = new BigInteger(keyReader.readLine());
        BigInteger d = new BigInteger(keyReader.readLine());
        keyReader.close();

        // 2. Read the ciphertext decimal string
        List<String> lines = Files.readAllLines(Paths.get(cipherFile));
        BigInteger c = new BigInteger(lines.get(0));

        // 3. Decrypt: m = c^d mod n
        BigInteger m = c.modPow(d, n);

        // 4. Recover original bytes
        byte[] plaintext = m.toByteArray();
        // (BigInteger may add a leading zero byte — strip if present)
        if (plaintext[0] == 0) {
            byte[] tmp = new byte[plaintext.length - 1];
            System.arraycopy(plaintext, 1, tmp, 0, tmp.length);
            plaintext = tmp;
        }

        // 5. Write out plaintext
        try (PrintWriter out = new PrintWriter(outputFile)) {
            out.write(new String(plaintext));
        }

        System.out.println("Decrypted → " + outputFile);
    }
}
