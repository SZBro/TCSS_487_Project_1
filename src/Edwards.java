import java.math.BigInteger;

/**
* Arithmetic on Edwards elliptic curves.
*/
public class Edwards {
    
    /**
     * This is the p that is used for doing all given mod arithmitic, in the specs.
     */
    static final BigInteger P = BigInteger.TWO.pow(256).subtract(BigInteger.valueOf(189)); 

    /**
     * This is the d required in the specs.  (curve constant)
     */
    static final BigInteger D = BigInteger.valueOf(15343);

    /**
     * This is the r that in the specs.
     */
    static final BigInteger R = BigInteger.TWO.pow(256).subtract(
        new BigInteger("87175310462106073678594642380840586067"));

    /**
    * Create an instance of the default curve NUMS-256.
    */
    public Edwards() 
    { /* ... */ }

    /**
    * Determine if a given affine coordinate pair P = (x, y)
    * defines a point on the curve.
    *
    * @param x x-coordinate of presumed point on the curve
    * @param y y-coordinate of presumed point on the curve
    * @return whether P is really a point on the curve
    */
    public boolean isPoint(BigInteger x, BigInteger y) 
    {
        // Following the edwards equation to check if the point is on the curve or not.
        // x^2 + y^2 = 1 + (dx^2 * y^2) moding every 
        BigInteger x2 = x.pow(2).mod(P);
        BigInteger y2 = y.pow( 2).mod(P);

        BigInteger left = x2.add(y2).mod(P);
        BigInteger right = BigInteger.ONE.add(D.multiply(x2).mod(P).multiply(y2).mod(P)).mod(P);

        return (left.equals(right));
    }

    /**
    * Find a generator G on the curve with the smallest possible
    * y-coordinate in absolute value.
    *
    * @return G.
    */
    public Point gen() 
    {
        
    }

    /**
    * Create a point from its y-coordinate and
    * the least significant bit (LSB) of its x-coordinate.
    *
    * @param y the y-coordinate of the desired point
    * @param x_lsb the LSB of its x-coordinate
    * @return point (x, y) if it exists and has order r,
    * otherwise the neutral element O = (0, 1)
    */
    public Point getPoint(BigInteger y, boolean x_lsb) 
    {
        
    }

    /**
    * Display a human-readable representation of this curve.
    *
    * @return a string of form "E: x^2 + y^2 = 1 + d*x^2*y^2 mod p"
    * where E is a suitable curve name (e.g. NUMS ed-256-mers*),
    * d is the actual curve equation coefficient defining this curve,
    * and p is the order of the underlying finite field F_p.
    */
    public String toString() 
    {
        
    }

    /**
    * Edwards curve point in affine coordinates.
    * NB: this is a nested class, enclosed within the Edwards class.
    */
    public class Point {

        BigInteger myX;
        
        BigInteger myY;

        /**
        * Create a copy of the neutral element on this curve.
        */
        public Point()
        {

        }


        /**
        * Create a point from its coordinates (assuming
        * these coordinates really define a point on the curve).
        *
        * @param x the x-coordinate of the desired point
        * @param y the y-coordinate of the desired point
        */
        private Point(BigInteger x, BigInteger y) 
        {
            myX = x;
            myY = y;
        }
        /**
        * Determine if this point is the neutral element O on the curve.
        *
        * @return true iff this point is O
        */
        public boolean isZero() 
        {
        
        }

        /**
        * Determine if a given point P stands for
        * the same point on the curve as this.
        *
        * @param P a point (presumably on the same curve as this)
        * @return true iff P stands for the same point as this
        */
        public boolean equals(Point P) 
        {
            
        }

        /**
        * Given a point P = (x, y) on the curve,
        * return its opposite -P = (-x, y).
        *
        * @return -P
        */
        public Point negate() 
        {
            return new Point(myX.negate().mod(P), myY);
        }

        /**
        * Add two given points on the curve, this and P.
        *
        * @param P a point on the curve
        * @return this + P
        */
        public Point add(Point theP) 
        {
            // using edwards formula 
            // x = (x1y2 + y1x2) / (1 + dx1x2y1y2) | y = (y1y2 - x1x2) / (1 - dx1x2y1y2) 
            // x
            BigInteger newXNum = myX.multiply(theP.getY()).mod(P).add(myY.multiply(theP.getX()).mod(P)).mod(P);
            BigInteger newXDen = BigInteger.ONE.add(
                                D.multiply(myX).mod(P).multiply(theP.getX()).mod(P)
                                .multiply(myY).mod(P).multiply(theP.getY()).mod(P)).mod(P);
            BigInteger newX =  newXNum.multiply(newXDen.modInverse(P)).mod(P);

            // y
            BigInteger newYNum = myY.multiply(theP.getY()).mod(P).subtract(myX.multiply(theP.getX()).mod(P)).mod(P);
            BigInteger newYDen = BigInteger.ONE.subtract(
                                D.multiply(myX).mod(P).multiply(theP.getX()).mod(P)
                                .multiply(myY).mod(P).multiply(theP.getY()).mod(P)).mod(P);
            BigInteger newY = newYNum.multiply(newYDen.modInverse(P)).mod(P);

            return new Point(newX, newY);
        }

        /**
        * Multiply a point P = (x, y) on the curve by a scalar m.
        *
        * @param m a scalar factor (an integer mod the curve order)
        * @return m*P
        */
        public Point mul(BigInteger m) 
        {
        
        }

        /**
        * Display a human-readable representation of this point.
        *
        * @return a string of form "(x, y)" where x and y are
        * the coordinates of this point
        */
        public String toString() 
        {
        
        }

        public BigInteger getX()
        {
            return myX;
        }

        public BigInteger getY()
        {
            return myY;
        }
    }
}