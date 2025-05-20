package rsa;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;

/**
 * RSAEncrypt
 * Usage: java rsa.RSAEncrypt <inputFile> <publicKeyFile> <outputFile>
 */
public class RSAEncrypt {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: java rsa.RSAEncrypt <inputFile> <publicKeyFile> <outputFile>");
            return;
        }

        String inputFile   = args[0];
        String pubKeyFile  = args[1];
        String outputFile  = args[2];

        // 1. Load public key (n, e)
        BufferedReader keyReader = new BufferedReader(new FileReader(pubKeyFile));
        BigInteger n = new BigInteger(keyReader.readLine());
        BigInteger e = new BigInteger(keyReader.readLine());
        keyReader.close();

        // 2. Read plaintext bytes
        byte[] plaintext = Files.readAllBytes(Paths.get(inputFile));

        // 3. Convert to BigInteger (positive)
        BigInteger m = new BigInteger(1, plaintext);

        // 4. Encrypt: c = m^e mod n
        BigInteger c = m.modPow(e, n);

        // 5. Write ciphertext as decimal string
        try (PrintWriter out = new PrintWriter(outputFile)) {
            out.println(c.toString());
        }

        System.out.println("Encrypted → " + outputFile);
    }
}
