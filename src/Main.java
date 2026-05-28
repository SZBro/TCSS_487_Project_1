import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class Main 
{
    public static void main(String[] args) throws Exception
    {
        if(args.length < 2) 
        {
            printUsage();
            return;
        }

        String  cmd = args[0];

        switch(cmd)
        {
            case "hash":
                doHash(args);
                break;
            case "mac":
                doMAC(args);
                break;
            case "mac-text":
                doMACText(args);
                break;
            case "encrypt":
                doEncrypt(args);
                break;
            case "decrypt":
                doDecrypt(args);
                break;
            case "keygen":
                doKeyGen(args);
                break;
            case "ecencrypt":
                doECEncrypt(args);
                break;
            case "ecdecrypt":
                doECDecrypt(args);
                break;
            case "sign":
                doSign(args);
                break;
            case "verify":
                doVerify(args);
                break;
            default:
                System.out.println("Unknown Command: " + cmd);
                printUsage();
        }
    }

static void printUsage() 
{
        System.out.println("Usage:");
        System.out.println("  java Main hash <file>");
        System.out.println("    Computes SHA3-224, SHA3-256, SHA3-384, SHA3-512 of a file");
        System.out.println();
        System.out.println("  java Main mac <file> <passphrase> <length>");
        System.out.println("    Computes SHAKE-128 and SHAKE-256 MAC of a file");
        System.out.println();
        System.out.println("  java Main mac-text <text> <passphrase> <length>");
        System.out.println("    Computes SHAKE-128 and SHAKE-256 MAC of text input");
        System.out.println();
        System.out.println("  java Main encrypt <file> <passphrase> <outfile>");
        System.out.println("    Encrypts a file symmetrically under a passphrase");
        System.out.println();
        System.out.println("  java Main decrypt <file> <passphrase> <outfile>");
        System.out.println("    Decrypts a file symmetrically under a passphrase");
        System.out.println();
        System.out.println("  java Main keygen <passphrase> <outfile>");
        System.out.println("    Generates an elliptic key pair from a passphrase");
        System.out.println();
        System.out.println("  java Main ecencrypt <pubkeyfile> <datafile> <outfile>");
        System.out.println("    Encrypts a file with ECIES under a public key");
        System.out.println();
        System.out.println("  java Main ecdecrypt <passphrase> <infile> <outfile>");
        System.out.println("    Decrypts an ECIES encrypted file under a passphrase");
        System.out.println();
        System.out.println("  java Main sign <passphrase> <datafile> <sigfile>");
        System.out.println("    Signs a file with Schnorr under a passphrase");
        System.out.println();
        System.out.println("  java Main verify <pubkeyfile> <datafile> <sigfile>");
        System.out.println("    Verifies a Schnorr signature under a public key");
}

    static String toHex(byte[] bytes) 
    {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes)
        {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void doHash(String[] args) throws Exception
    {
        if(args.length < 2) 
        {
            System.out.println("Usage: hash <file>");
            return;
        }

        byte[] dataBytes = Files.readAllBytes(Paths.get(args[1]));

        // required
        System.out.println("SHA3-256: " + toHex(SHA3SHAKE.SHA3(256, dataBytes, null)));
        System.out.println("SHA3-512: " + toHex(SHA3SHAKE.SHA3(512, dataBytes, null)));

        // bonus
        System.out.println("SHA3-224: " + toHex(SHA3SHAKE.SHA3(224, dataBytes, null)));
        System.out.println("SHA3-384: " + toHex(SHA3SHAKE.SHA3(384, dataBytes, null)));
    }

    private static void doMAC(String[] args) throws Exception
    {
        if(args.length < 4)
        {
            System.out.println("Usage: mac <file> <passphrase> <length>");
        }

        byte[] dataBytes = Files.readAllBytes(Paths.get(args[1]));
        byte[] pass = args[2].getBytes();
        int length = Integer.parseInt(args[3]);
        
        SHA3SHAKE shake128 = new SHA3SHAKE();
        shake128.init(128);
        shake128.absorb(pass);
        shake128.absorb(dataBytes);
        System.out.println("SHAKE-128 MAC: " + toHex(shake128.squeeze(length)));

        SHA3SHAKE shake256 = new SHA3SHAKE();
        shake256.init(256);
        shake256.absorb(pass);
        shake256.absorb(dataBytes);
        System.out.println("SHAKE-256 MAC: " + toHex(shake256.squeeze(length)));
    }

    private static void doMACText(String[] args) throws Exception
    {
        if(args.length < 4) 
        {
            System.out.println("Usage: mac-text <text> <passphrase> <length>");
            return;
        }

        byte[] dataBytes = args[1].getBytes();
        byte[] pass = args[2].getBytes();
        int length = Integer.parseInt(args[3]);

        SHA3SHAKE sponge = new SHA3SHAKE();
        
        sponge.init(128);
        sponge.absorb(pass);
        sponge.absorb(dataBytes);
        System.out.println("SHAKE-128 MAC: " + toHex(sponge.squeeze(length)));

        sponge.init(256);
        sponge.absorb(pass);
        sponge.absorb(dataBytes);
        System.out.println("SHAKE-256 MAC: " + toHex(sponge.squeeze(length)));
    }

    private static void doEncrypt(String[] args) throws Exception
    {
        if(args.length < 4)
        {
            System.out.println("Usage: encrypt <file> <passphrase> <outfile>");
            return;
        }

        byte[] dataBytes = Files.readAllBytes(Paths.get(args[1]));
        byte[] pass = args[2].getBytes();
        String outFile = args[3];

        byte[] key = SHA3SHAKE.SHAKE(128, pass, 128, null);
        byte[] nonce = new byte[16];
        new java.security.SecureRandom().nextBytes(nonce);

        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(nonce);
        sponge.absorb(key);
        byte[] stream = sponge.squeeze(dataBytes.length);

        byte[] ciphertext = new byte[dataBytes.length];
        for(int i = 0; i < dataBytes.length; i++)
        {
            ciphertext[i] = (byte) (dataBytes[i] ^ stream[i]);
        }

        // bonus
        SHA3SHAKE mac = new SHA3SHAKE();
        mac.init(256);
        mac.pad = 0x06;
        mac.absorb(key);
        mac.absorb(ciphertext);
        byte[] mtag = mac.digest();

        // output
        byte[] output = new byte[nonce.length + ciphertext.length + mtag.length];
        System.arraycopy(nonce, 0, output, 0, nonce.length);
        System.arraycopy(ciphertext, 0, output, nonce.length, ciphertext.length);
        System.arraycopy(mtag, 0, output, nonce.length + ciphertext.length, mtag.length);

        Files.write(Paths.get(outFile), output);

        System.out.println("Encrypted to: " + outFile);
    }

    private static void doDecrypt(String[] args) throws Exception
    {
        if(args.length < 4)
        {
            System.out.println("Usage: decrypt <file> <passphrase> <outfile>");
            return;
        }

        byte[] fileData = Files.readAllBytes(Paths.get(args[1]));
        byte[] pass = args[2].getBytes();
        String outFile = args[3];

        byte[] nonce = new byte[16];
        System.arraycopy(fileData, 0, nonce, 0, 16);

        byte[] ciphertext = new byte[fileData.length - 16 - 32];
        System.arraycopy(fileData, 16, ciphertext, 0, ciphertext.length);

        byte[] mtag = new byte[32];
        System.arraycopy(fileData, 16 + ciphertext.length, mtag, 0, 32);

        byte[] key = SHA3SHAKE.SHAKE(128, pass, 128, null);

        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(nonce);
        sponge.absorb(key);
        byte[] stream = sponge.squeeze(ciphertext.length);

        byte[] plaintext = new byte[ciphertext.length];
        for(int i = 0; i < ciphertext.length; i++)
        {
            plaintext[i] = (byte) (ciphertext[i] ^ stream[i]);
        }

        //bonus
        SHA3SHAKE mac = new SHA3SHAKE();
        mac.init(256);
        mac.pad = 0x06;
        mac.absorb(key);
        mac.absorb(ciphertext);
        byte[] expected = mac.digest();

        if(java.util.Arrays.equals(expected, mtag))
        {
            System.out.println("MAC verified successfully!");
        }
        else
        {
            System.out.println("MAC verification FAILED!");
        }

        Files.write(Paths.get(outFile), plaintext);
        System.out.println("Decrypted to: " + outFile);
    }

    private static void doKeyGen(String[] args) throws Exception 
    {
        if(args.length < 3)
        {
            System.out.println("Usage: keygen <passphrase> <outfile>");
            return;
        }

        // setting up edwards
        Edwards E = new Edwards();
        Edwards.Point G = E.gen();

        // computing private key
        byte[] pass = args[1].getBytes(); 
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(pass);
        byte[] squeezed = sponge.squeeze(48);
        BigInteger s = new BigInteger(1, squeezed).mod(E.R);

        // computing public key
        Edwards.Point V = G.mul(s); // V <- s * G
        if (V.getX().testBit(0)) // test LSB
        {
            s = E.R.subtract(s); // Change S to r-s
            V = V.negate(); // V = -V
        }

        // file part
        String publicKey = V.getX().testBit(0) + "\n" + V.getY().toString();
        Files.write(Paths.get(args[2]), publicKey.getBytes());
        System.out.println("Public Key written to: " + args[2]);
    }

    private static void doECEncrypt(String[] args) throws Exception 
    {
        if(args.length < 4)
        {
            System.out.println("Usage: ecencrypt <pubkeyfile> <datafile> <outfile>");
            return;
        }

        // getting public key from file.
        String[] lines = new String(Files.readAllBytes(Paths.get(args[1]))).split("\n");
        Boolean lsb = Boolean.parseBoolean(lines[0]);
        BigInteger y = new BigInteger(lines[1].trim());
        Edwards E = new Edwards();
        Edwards.Point G = E.gen();
        Edwards.Point V = E.getPoint(y, lsb);

        // Random 384-bit
        int rbytes = (Edwards.R.bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(new SecureRandom().generateSeed(rbytes << 1)).mod(Edwards.R);

        // Computing W and Z
        Edwards.Point W = V.mul(k);
        Edwards.Point Z = G.mul(k);

        // normalize Z so x is always even
        if(Z.getX().testBit(0)) 
        {
            k = Edwards.R.subtract(k);
            Z = Z.negate();
            W = V.mul(k);  // recompute W with new k
        }

        //  squeezing ka and ke
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(256);
        sponge.absorb(W.getY().toByteArray());
        byte[] ka = sponge.squeeze(32);
        byte[] ke = sponge.squeeze(32);

        // setting up data
        byte[] data = Files.readAllBytes(Paths.get(args[2]));
        SHA3SHAKE cipher = new SHA3SHAKE();
        cipher.init(128);
        cipher.absorb(ke);
        byte[] stream = cipher.squeeze(data.length);

        // XORing data
        byte[] c = new byte[data.length];
        for (int i = 0; i < data.length; i++)
        {
            // XORing every byte from data with stream.
            c[i] = (byte)(data[i] ^ stream[i]); 
        }

        // Computing the MAC tag "t"
        SHA3SHAKE mac = new SHA3SHAKE();
        mac.init(256);
        mac.pad = 0x06; // SHA-3 specs
        mac.absorb(ka);
        mac.absorb(c);
        byte[] t = mac.digest();

        // Writing data to file.
        byte[] ZInfo = (Z.getY().toString() + "\n").getBytes();

        // Format: [Z Length (4 bytes)][Z Bytes][c length (4 bytes)][c bytes][t (32 bytes)]
        // reasoning easy to read and need to know the lengths of Z and C for clear distinction of data.
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

        // byte buffer allows us to make a set byte length to keep the format.
        byte[] ZLength = java.nio.ByteBuffer.allocate(4).putInt(ZInfo.length).array();
        out.write(ZLength);
        out.write(ZInfo);

        // Same thing with C
        byte[] CLength = java.nio.ByteBuffer.allocate(4).putInt(c.length).array();
        out.write(CLength);
        out.write(c);

        // add the tag
        out.write(t);

        // System.out.println("W in encrypt: " + W);
        // System.out.println("ka: " + toHex(ka));
        // System.out.println("ke: " + toHex(ke));

        Files.write(Paths.get(args[3]), out.toByteArray());
        System.out.println("Encrypted to: " + args[3]);
    }

    private static void doECDecrypt(String[] args) throws Exception 
    {
        if(args.length < 4)
        {
            System.out.println("Usage: ecdecrypt <passphrase> <infile> <outfile>");
            return;
        }

        // setting up edwards
        Edwards E = new Edwards();
        Edwards.Point G = E.gen();

        // computing private key
        byte[] pass = args[1].getBytes(); 
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(pass);
        byte[] squeezed = sponge.squeeze(48);
        BigInteger s = new BigInteger(1, squeezed).mod(Edwards.R);

        // Reading the Data
        // Format: [Z Length (4 bytes)][Z Bytes][c length (4 bytes)][c bytes][t (32 bytes)]
        byte[] data = Files.readAllBytes(Paths.get(args[2]));
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(data);

        int ZLength = buffer.getInt();
        byte[] ZBytes = new byte[ZLength];
        buffer.get(ZBytes);

        int CLength = buffer.getInt();
        byte[] CBytes =  new byte[CLength];
        buffer.get(CBytes);

        byte[] t = new byte[32];
        buffer.get(t);

        // Reconstructing data
        String[] ZLines = new String(ZBytes).split("\n");
        boolean Zlsb = Boolean.parseBoolean(ZLines[0]);
        BigInteger ZY = new BigInteger(new String(ZBytes).trim());
        Edwards.Point Z = E.getPoint(ZY, false);
        if(G.mul(s).getX().testBit(0)) 
        {
            s = Edwards.R.subtract(s);
        }

        // Computing W
        Edwards.Point W = Z.mul(s);

        // Getting ka and ke
        SHA3SHAKE kSponge = new SHA3SHAKE();
        kSponge.init(256);
        kSponge.absorb(W.getY().toByteArray());
        byte[] ka = kSponge.squeeze(32);
        byte[] ke = kSponge.squeeze(32);

        // Compute tags
        SHA3SHAKE tSponge = new SHA3SHAKE();
        tSponge.init(256);
        tSponge.pad = 0x06;
        tSponge.absorb(ka);
        tSponge.absorb(CBytes);
        byte[] tPrime = tSponge.digest();

        // System.out.println("Z reconstructed: " + Z);
        // System.out.println("Z is zero: " + Z.isZero());
        // System.out.println("ZY: " + ZY);
        // System.out.println("Zlsb: " + Zlsb);
        // Edwards.Point Ztest = E.getPoint(ZY, Zlsb);
        // System.out.println("Ztest is zero: " + Ztest.isZero());
        // System.out.println("Ztest.mul(R).isZero(): " + Ztest.mul(Edwards.R).isZero());

        // Compare tags 
        if(!java.util.Arrays.equals(tPrime, t))
        {
            System.out.println("Decryption error - MAC verification failed!");
            return;
        }

        // decrypt and write to file
        SHA3SHAKE cipher =  new SHA3SHAKE();
        cipher.init(128);
        cipher.absorb(ke);
        byte[] stream = cipher.squeeze(CBytes.length);

        byte[] plaintext = new byte[CBytes.length];
        for (int i = 0; i < CBytes.length; i++)
        {
            plaintext[i] = (byte)(CBytes[i] ^ stream[i]);
        }

        Files.write(Paths.get(args[3]), plaintext);
        System.out.println("Decrypted to: " + args[3]);
    }

    private static void doSign(String[] args) throws Exception 
    {
        if(args.length < 4)
        {
            System.out.println("Usage: sign <passphrase> <datafile> <sigfile>");
            return;
        }

        // setting up edwards
        Edwards E = new Edwards();
        Edwards.Point G = E.gen();

        // computing private key
        byte[] pass = args[1].getBytes(); 
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(pass);
        byte[] squeezed = sponge.squeeze(48);
        BigInteger s = new BigInteger(1, squeezed).mod(Edwards.R);

        // lsb check
        if(G.mul(s).getX().testBit(0))
        {
            s = Edwards.R.subtract(s);
        }

        // read data
        byte[] message = Files.readAllBytes(Paths.get(args[2]));

        // random k
        int rbytes = (Edwards.R.bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(new SecureRandom().generateSeed(rbytes << 1)).mod(Edwards.R);

        // compute U
        Edwards.Point U = G.mul(k);

        // compute H
        SHA3SHAKE HShake = new SHA3SHAKE();
        HShake.init(256);
        HShake.pad = 0x06;
        HShake.absorb(U.getY().toByteArray());
        HShake.absorb(message);
        byte[] HDigest = HShake.digest();
        BigInteger H = new BigInteger(1, HDigest).mod(Edwards.R);

        // Compute Z
        BigInteger Z = k.subtract(H.multiply(s)).mod(Edwards.R);

        // Write (H, Z) to file
        String writeData = H.toString() + "\n" + Z.toString();
        Files.write(Paths.get(args[3]), writeData.getBytes());
        System.out.println("Signature written to: " + args[3]);
    }

    private static void doVerify(String[] args) throws Exception 
    {
        if(args.length < 4)
        {
            System.out.println("Usage: verify <pubkeyfile> <datafile> <sigfile>");
            return;
        }

        // Edwards
        Edwards E = new Edwards();
        Edwards.Point G = E.gen();

        // Read the data
        String[] sigdata = new String(Files.readAllBytes(Paths.get(args[3]))).split("\n");
        BigInteger H = new BigInteger(sigdata[0].trim());
        BigInteger Z = new BigInteger(sigdata[1].trim());

        String[] pubdata = new String(Files.readAllBytes(Paths.get(args[1]))).split("\n");
        boolean lsb = Boolean.parseBoolean(pubdata[0]);
        BigInteger y = new BigInteger(pubdata[1].trim());
        Edwards.Point V = E.getPoint(y, lsb);

        byte[] message = Files.readAllBytes(Paths.get(args[2]));

        // compute U prime
        Edwards.Point UPrime = G.mul(Z).add(V.mul(H));

        // compute H prime
        SHA3SHAKE HShake = new SHA3SHAKE();
        HShake.init(256);
        HShake.pad = 0x06;
        HShake.absorb(UPrime.getY().toByteArray());
        HShake.absorb(message);
        byte[] HDigest = HShake.digest();
        BigInteger HPrime = new BigInteger(1, HDigest).mod(Edwards.R);

        if(HPrime.equals(H))
        {
            System.out.println("Signature verified successfully!");
        }
        else 
        {
            System.out.println("Signature verification FAILED!");
        }
    }
}