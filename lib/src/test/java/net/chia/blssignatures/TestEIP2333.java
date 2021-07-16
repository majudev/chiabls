package net.chia.blssignatures;

import net.majudev.chiabls.EIP2333;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class TestEIP2333 {
    @Test
    void testEIP2333() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        for(int i = 0; i < testCases.length; ++i){
            byte[] master = EIP2333.derive_master_SK(testCases[i].seed);
            byte[] child = EIP2333.derive_child_SK(master, testCases[i].child_index);
            assertEquals(master.length, 32);
            assertEquals(child.length, 32);
            assertArrayEquals(master, testCases[i].master_sk_hex);
            assertArrayEquals(child, testCases[i].child_sk_hex);
        }
    }

    private static class TestCase{
        byte[] seed;
        byte[] master_sk_hex;
        byte[] child_sk_hex;
        long child_index;
        TestCase(byte[] seed, byte[] master_sk_hex, byte[] child_sk_hex, long child_index){
            this.seed = seed;
            this.master_sk_hex = master_sk_hex;
            this.child_sk_hex = child_sk_hex;
            this.child_index = child_index;
        }
    }
    private static TestCase[] testCases = {
            new TestCase(
                    hexStringToByteArray("3141592653589793238462643383279502884197169399375105820974944592"),
                    hexStringToByteArray("4ff5e145590ed7b71e577bb04032396d1619ff41cb4e350053ed2dce8d1efd1c"),
                    hexStringToByteArray("5c62dcf9654481292aafa3348f1d1b0017bbfb44d6881d26d2b17836b38f204d"),
                    3141592653L
            ),
            new TestCase(
                    hexStringToByteArray("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00"),
                    hexStringToByteArray("1ebd704b86732c3f05f30563dee6189838e73998ebc9c209ccff422adee10c4b"),
                    hexStringToByteArray("1b98db8b24296038eae3f64c25d693a269ef1e4d7ae0f691c572a46cf3c0913c"),
                    4294967295L
            ),
            new TestCase(
                    hexStringToByteArray("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
                    hexStringToByteArray("614d21b10c0e4996ac0608e0e7452d5720d95d20fe03c59a3321000a42432e1a"),
                    hexStringToByteArray("08de7136e4afc56ae3ec03b20517d9c1232705a747f588fd17832f36ae337526"),
                    42
            ),
            new TestCase(
                    hexStringToByteArray("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
                    hexStringToByteArray("0befcabff4a664461cc8f190cdd51c05621eb2837c71a1362df5b465a674ecfb"),
                    hexStringToByteArray("1a1de3346883401f1e3b2281be5774080edb8e5ebe6f776b0f7af9fea942553a"),
                    0
            )
    };

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
