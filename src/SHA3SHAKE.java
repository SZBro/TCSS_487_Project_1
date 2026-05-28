public class SHA3SHAKE {
    public SHA3SHAKE() {}

    /** Keccak-f rotation offset constants */
    private static final int[] RHO = 
    {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /** keccak-f lane permutation indices constant */
    private static final int[] PI =
    {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    /** keccak-f round constants */
    private static final long[] RC = 
    {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /* This is the sponge's state  */
    private long[] A = new long[25];

    /** Rate in bytes number of bytes XOR */
    private int rate;

    /** Number of bytes abosrbed*/
    private int absorbed;

    /** Output lenght in bytes */
    private int digestLen;

    /** Padding byte */
    byte pad;


    /**
    * Initialize the SHA-3/SHAKE sponge.
    * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
    * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec level = suffix)
    */
    public void init(int suffix) 
    { 
        A = new long[25];
        absorbed = 0;
        rate = (1600 -2 * suffix) / 8;
        pad = 0x1F; 
        digestLen = suffix / 8;
     }

    /**
    * Update the SHAKE sponge with a byte-oriented data chunk.
    *
    * @param data byte-oriented data buffer
    * @param pos initial index to hash from
    * @param len byte count on the buffer
    */
    public void absorb(byte[] data, int pos, int len) 
    {
        for(int i = 0; i < len; i++)
        {
            int lane = absorbed / 8;
            // 0xFF prevents sign extension
            A[lane] ^= (long) (data[pos + i] & 0xFF) << ((absorbed % 8) * 8);
            absorbed++;

            if(absorbed == rate) 
            {
                keccak();
                absorbed = 0;
            }
        }
    }

    /**
    * Update the SHAKE sponge with a byte-oriented data chunk.
    *
    * @param data byte-oriented data buffer
    * @param len byte count on the buffer (starting at index 0)
    */
    public void absorb(byte[] data, int len) 
    {
        absorb(data, 0, len);
    }

    /**
    * Update the SHAKE sponge with a byte-oriented data chunk.
    *
    * @param data byte-oriented data buffer
    */
    public void absorb(byte[] data) 
    {
        absorb(data, 0, data.length);
    }

    /**
    * Squeeze a chunk of hashed bytes from the sponge.
    * Call this method as many times as needed to extract the total desired number of bytes.
    *
    * @param out hash value buffer
    * @param len desired number of squeezed bytes
    * @return the val buffer containing the desired hash value
    */
    public byte[] squeeze(byte[] out, int len) 
    { 
        int lane = absorbed / 8;
        A[lane] ^= (long)(pad & 0xFF) << ((absorbed % 8) * 8);
        A[(rate - 1) / 8] ^= 0x80L << (((rate - 1) % 8) * 8);
        keccak();
        absorbed = 0;

        // squeezing 
        int squeezed = 0;
        while(squeezed < len)
        {
            // check how many we have read 
            if(absorbed == rate)
            {
                //permute and reset if limit reached
                if(squeezed > 0) keccak();
                absorbed = 0;
            }
            // reading reverse of absorb
            out[squeezed] = (byte) (A[absorbed / 8] >>> ((absorbed % 8) * 8));
            absorbed++;
            squeezed++;
        }
        return out;
    }
    
    /**
    * Squeeze a chunk of hashed bytes from the sponge.
    * Call this method as many times as needed to extract the total desired number of bytes.
    *
    * @param len desired number of squeezed bytes
    * @return newly allocated buffer containing the desired hash value
    */
    public byte[] squeeze(int len) 
    { 
        return squeeze(new byte[len], len);
    }
    
    /**
    * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
    *
    * @param out hash value buffer
    * @return the val buffer containing the desired hash value
    */
    public byte[] digest(byte[] out) 
    {
        return squeeze(out, digestLen);
    }
    
    /**
    * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
    *
    * @return the desired hash value on a newly allocated byte array
    */
    public byte[] digest() 
    {
        return squeeze(new byte[digestLen], digestLen);
    }
    
    /**
    * Compute the streamlined SHA-3-<224,256,384,512> on input X.
    *
    * @param suffix desired output length in bits (one of 224, 256, 384, 512)
    * @param X data to be hashed
    * @param out hash value buffer (if null, this method allocates it with the required size)
    * @return the out buffer containing the desired hash value.
    */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) 
    { 
        if(out == null) out = new byte[suffix / 8];
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.pad = 0x06;
        sponge.absorb(X);
    
        return sponge.digest(out);
    }
    
    /**
    * Compute the streamlined SHAKE-<128,256> on input X with output bitlength L.
    *
    * @param suffix desired security level (either 128 or 256)
    * @param X data to be hashed
    * @param L desired output length in bits (must be a multiple of 8)
    * @param out hash value buffer (if null, this method allocates it with the required size)
    * @return the out buffer containing the desired hash value.
    */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) 
    {
        if(out == null) out = new byte[L / 8];
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.pad = 0x1F;
        sponge.absorb(X);

        return sponge.squeeze(out, L / 8);
    }

    private void keccak() 
     {
        for(int round = 0; round < 24; round++)
        {
            // Theta -  XOR each lane together
            long[] sheetParity = new long[5];
            long[] Diffusion = new long[5];
            
            // Computing Sheet Parity
            for(int i = 0; i < 5; i++)
            {
                for(int j = 0; j < 25; j += 5)
                {
                    sheetParity[i] ^= A[i + j];
                }
            }

            //Computing Diffusion 
            for(int i = 0; i < 5; i++)
            {
                Diffusion[i] = sheetParity[(i + 4) %  5] ^
                Long.rotateLeft(sheetParity[(i + 1) % 5], 1);
            }

            // Do the XORing
            for(int j = 0; j < 25; j += 5)
            {
                for(int i = 0; i < 5; i++)
                {
                    A[i + j] ^= Diffusion[i];
                }
            }

            // RHO / PI - Rotating Lanes (can be done at the same time)
            long t = A[1];
            for(int i = 0; i < 24; i++)
            {
                int j = PI[i];
                long displaced = A[j];
                A[j] = Long.rotateLeft(t, RHO[i]);
                t = displaced;
            }

            // CHI - non linear mixing 
            for(int j = 0; j < 25; j += 5)
            {
                for(int i = 0; i < 5; i++)
                {
                    sheetParity[i] = A[j + i];
                }
                for(int i = 0; i < 5; i++)
                {
                    A[j + i] = sheetParity[i] ^
                    (~sheetParity[(i + 1) % 5]
                    & sheetParity[(i + 2) % 5]);
                }
            }

            // IOTA
            A[0] ^= RC[round];
        }
     }
}
