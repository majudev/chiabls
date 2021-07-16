package net.majudev.chiabls;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

class EIP2334Test {

    @Test
    void deriveMasterFromSeed() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Testing deriveMasterFromSeed");
        for(int i = 0; i < this.eip2334_tests.length; ++i) {
            byte[] out = EIP2334.deriveMasterFromSeed(this.eip2334_tests[i].seed, "");
            if(!Arrays.equals(out, this.eip2334_tests[i].master_SK)){
                System.out.println("Function returned:\t" + bytesToHex(out) + " (" + out.length + " bytes)");
                System.out.println("Expected:\t\t\t" + bytesToHex(this.eip2334_tests[i].master_SK) + " (" + this.eip2334_tests[i].master_SK.length + " bytes)");
                assert(false);
            }
        }
    }

    @Test
    void deriveMasterFromRawSeed() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Testing deriveMasterFromRawSeed");
        for(int i = 0; i < this.eip2334_tests.length; ++i) {
            byte[] out = EIP2334.deriveMasterFromRawSeed(this.eip2334_tests[i].extended_seed);
            if(!Arrays.equals(out, this.eip2334_tests[i].master_SK)){
                System.out.println("Function returned:\t" + bytesToHex(out) + " (" + out.length + " bytes)");
                System.out.println("Expected:\t\t\t" + bytesToHex(this.eip2334_tests[i].master_SK) + " (" + this.eip2334_tests[i].master_SK.length + " bytes)");
                assert(false);
            }
        }
    }

    @Test
    void deriveChildFromPath() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Testing derive_child_SK");
        for(int i = 0; i < this.eip2334_tests.length; ++i) {
            byte[] out = EIP2334.deriveChildFromPath(this.eip2334_tests[i].master_SK, this.eip2334_tests[i].path);
            if(!Arrays.equals(out, this.eip2334_tests[i].child_SK)){
                System.out.println("Function returned:\t" + bytesToHex(out) + " (" + out.length + " bytes)");
                System.out.println("Expected:\t\t\t" + bytesToHex(this.eip2334_tests[i].child_SK) + " (" + this.eip2334_tests[i].child_SK.length + " bytes)");
                assert(false);
            }
        }
    }

    private class EIP2334TestCase {
        String seed;
        byte[] extended_seed;
        byte[] master_SK;
        String path;
        byte[] child_SK;
        EIP2334TestCase(String seed, byte[] extended_seed, byte[] master_SK, String path, byte[] child_SK){
            this.seed = seed;
            this.extended_seed = extended_seed;
            this.master_SK = master_SK;
            this.path = path;
            this.child_SK = child_SK;
        }
    }
    EIP2334TestCase[] eip2334_tests = {
            new EIP2334TestCase(
                    "useless seek aspect wealth remain glass medal clinic audit spawn there ten female scissors service negative diesel auction income fragile charge cactus garden void",
                    hexStringToByteArray("6BE2CBF210D06C3F73C66435CD40D753BC1AC94723ABD5AE6922120B883F04C4BB22B077EDE48EE04307F52762EA9813483A2B8B56FF369055D98BE752F894C4"),
                    hexStringToByteArray("10c4ed9051f52976b6311f0b1bc095459256de9b8ec3f6bbd32e3294e35cd6f0"),
                    "m/12381/8444/2/0",
                    hexStringToByteArray("220e15bb2b34f667c90df40ab0b53ccf6a11af8f2ea98eb104a638bb558f5464")
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
