import java.math.BigInteger;

public class Test {
    public static void main(String[] args) {
        Edwards E = new Edwards();
        Edwards.Point G = E.gen();

        System.out.println("Curve: " + E);
        System.out.println("G = " + G);
        System.out.println();

        // Basic tests from Appendix C
        System.out.println("0*G = O: " + G.mul(BigInteger.ZERO).isZero());
        System.out.println("1*G = G: " + G.mul(BigInteger.ONE).equals(G));
        System.out.println("r*G = O: " + G.mul(E.R).isZero());
        System.out.println("4*G != O: " + !G.mul(BigInteger.valueOf(4)).isZero());

        // G + (-G) = O
        System.out.println("G + (-G) = O: " + G.add(G.negate()).isZero());

        // 2*G = G + G
        Edwards.Point twoG = G.mul(BigInteger.TWO);
        Edwards.Point GplusG = G.add(G);
        System.out.println("2*G = G+G: " + twoG.equals(GplusG));

        // 4*G = 2*(2*G)
        Edwards.Point fourG = G.mul(BigInteger.valueOf(4));
        Edwards.Point twotwoG = twoG.mul(BigInteger.TWO);
        System.out.println("4*G = 2*(2*G): " + fourG.equals(twotwoG));
    }
}