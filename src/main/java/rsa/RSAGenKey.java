package rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.io.File;
import java.io.PrintWriter;

/**
 * RSAGenKey
 * Generates an RSA keypair and writes:
 *  - keys/public.key   (n, e)
 *  - keys/private.key  (n, d)
 *
 * Usage:
 *   java rsa.RSAGenKey [keySize]
 *   (default keySize = 2048 bits)
 */
public class RSAGenKey {
    public static void main(String[] args) throws Exception {
        int keySize = 2048;
        if (args.length > 0) {
            keySize = Integer.parseInt(args[0]);
        }

        SecureRandom rnd = new SecureRandom();
        // generate two primes p and q
        BigInteger p = BigInteger.probablePrime(keySize/2, rnd);
        BigInteger q = BigInteger.probablePrime(keySize/2, rnd);
        BigInteger n = p.multiply(q);

        // φ(n) = (p-1)*(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE)
                           .multiply(q.subtract(BigInteger.ONE));

        // common public exponent
        BigInteger e = BigInteger.valueOf(65537);
        if (!phi.gcd(e).equals(BigInteger.ONE)) {
            throw new RuntimeException("e and phi(n) not coprime");
        }

        // private exponent d = e⁻¹ mod φ(n)
        BigInteger d = e.modInverse(phi);

        // ensure keys directory exists
        File keyDir = new File("keys");
        if (!keyDir.exists()) keyDir.mkdir();

        // write public.key (n, e)
        try (PrintWriter pubOut = new PrintWriter(new File(keyDir, "public.key"))) {
            pubOut.println(n.toString());
            pubOut.println(e.toString());
        }

        // write private.key (n, d)
        try (PrintWriter privOut = new PrintWriter(new File(keyDir, "private.key"))) {
            privOut.println(n.toString());
            privOut.println(d.toString());
        }

        System.out.printf("Keys generated (%d bits)%n", keySize);
        System.out.println("  -> keys/public.key");
        System.out.println("  -> keys/private.key");
    }
}
