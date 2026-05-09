import java.nio.file.Files;
import java.nio.file.Paths;

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
}