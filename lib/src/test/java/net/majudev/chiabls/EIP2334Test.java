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
                    hexStringToByteArray("4733c833b343103e12a8cb948ee6c2ce20f689bed4f2af3c7dcb8f529c9a5d98"),
                    "m/12381/8444/2/0",
                    hexStringToByteArray("17096eea617fb569347ab70264ef5163fb9cd3d580e34274acfb625b9a30178b")
            ),
            new EIP2334TestCase(
                    "panic shoot august search eye man banana wrap reopen shift gauge use fringe mix gadget void soccer cube bronze bleak waste solar august vital",
                    hexStringToByteArray("66995a2863bf8eb65f618da722bd51444fdf142700257c54807887a5f1dc2dc7f9bfabebe752fd9d431752ffc317ca08ceb398f015c12b53a1ec9a55d3ac22be"),
                    hexStringToByteArray("359c259b87930a7b7b8fffb51fc4e0cc3f29dff662e78e87c502a507794e8050"),
                    "m/12381/8444/2/0",
                    hexStringToByteArray("51183f54230cbd054ae51150b369b70c188e4152bfa9cf041982922b3e85b88b")
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
