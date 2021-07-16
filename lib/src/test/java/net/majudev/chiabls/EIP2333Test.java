package net.majudev.chiabls;


import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


class EIP2333Test {

    @Test
    void HKDF_Extract_SHA256() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Testing HKDF_Extract_SHA256...");
        for(int i = 0; i < this.RTC5869_tests.length; ++i) {
            byte[] out = EIP2333.RFC5869.HKDF_Extract_SHA256(this.RTC5869_tests[i].salt, this.RTC5869_tests[i].IKM);
            if(!Arrays.equals(out, this.RTC5869_tests[i].PRK)){
                System.out.println("Function returned:\t" + bytesToHex(out) + " (" + out.length + " bytes)");
                System.out.println("Expected:\t\t\t" + bytesToHex(this.RTC5869_tests[i].PRK) + " (" + this.RTC5869_tests[i].PRK.length + " bytes)");
                assert(false);
            }
        }
    }

    @Test
    void HKDF_Expand_SHA256() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Testing HKDF_Expand_SHA256...");
        for(int i = 0; i < this.RTC5869_tests.length; ++i) {
            byte[] out = EIP2333.RFC5869.HKDF_Expand_SHA256(this.RTC5869_tests[i].PRK, this.RTC5869_tests[i].info, this.RTC5869_tests[i].L);
            if(!Arrays.equals(out, this.RTC5869_tests[i].OKM)){
                System.out.println("Function returned:\t" + bytesToHex(out) + " (" + out.length + " bytes)");
                System.out.println("Expected:\t\t\t" + bytesToHex(this.RTC5869_tests[i].OKM) + " (" + this.RTC5869_tests[i].OKM.length + " bytes)");
                assert(false);
            }
        }
    }

    // Disabled because of Chia's wrong implementation of EIP2333
    /*@Test
    void derive_master_SK() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Testing derive_master_SK");
        for(int i = 0; i < this.eip2333_tests.length; ++i) {
            byte[] out = EIP2333.derive_master_SK(this.eip2333_tests[i].seed);
            if (!Arrays.equals(out, this.eip2333_tests[i].master_SK)) {
                System.out.println("Function returned:\t" + bytesToHex(out) + " (" + out.length + " bytes)");
                System.out.println("Expected:\t\t\t" + bytesToHex(this.eip2333_tests[i].master_SK) + " (" + this.eip2333_tests[i].master_SK.length + " bytes)");
                assert (false);
            }
        }
    }

    @Test
    void derive_child_SK() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        System.out.println("Testing derive_child_SK");
        for(int i = 0; i < this.eip2333_tests.length; ++i) {
            byte[] out = EIP2333.derive_child_SK(this.eip2333_tests[i].master_SK, this.eip2333_tests[i].child_index);
            if(!Arrays.equals(out, this.eip2333_tests[i].child_SK)){
                System.out.println("Function returned:\t" + bytesToHex(out) + " (" + out.length + " bytes)");
                System.out.println("Expected:\t\t\t" + bytesToHex(this.eip2333_tests[i].child_SK) + " (" + this.eip2333_tests[i].child_SK.length + " bytes)");
                assert(false);
            }
        }
    }*/

    private class RFC5869TestCase {
        byte[] IKM;
        byte[] salt;
        byte[] info;
        int L;
        byte[] PRK;
        byte[] OKM;
        RFC5869TestCase(byte[] IKM, byte[] salt, byte[] info, int L, byte[] PRK, byte[] OKM){
            this.IKM = IKM;
            this.salt = salt;
            this.info = info;
            this.L = L;
            this.PRK = PRK;
            this.OKM = OKM;
        }
    }
    RFC5869TestCase[] RTC5869_tests = {
            new RFC5869TestCase(
                    hexStringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                    hexStringToByteArray("000102030405060708090a0b0c"),
                    hexStringToByteArray("f0f1f2f3f4f5f6f7f8f9"),
                    42,
                    hexStringToByteArray("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
                    hexStringToByteArray("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
            ),
            new RFC5869TestCase(
                    hexStringToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
                    hexStringToByteArray("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
                    hexStringToByteArray("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                    82,
                    hexStringToByteArray("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
                    hexStringToByteArray("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
            ),
            new RFC5869TestCase(
                    hexStringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                    new byte[0],
                    new byte[0],
                    42,
                    hexStringToByteArray("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
                    hexStringToByteArray("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
            )
    };

    private class EIP2333TestCase {
        byte[] seed;
        byte[] master_SK;
        long child_index = 0;
        byte[] child_SK;
        EIP2333TestCase(byte[] seed, byte[] master_SK, long child_index, byte[] child_SK){
            this.seed = seed;
            this.master_SK = master_SK;
            this.child_index = child_index;
            this.child_SK = child_SK;
        }
    }

    EIP2333TestCase[] eip2333_tests = {
            new EIP2333TestCase(
                    hexStringToByteArray("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
                    hexStringToByteArray("0D7359D57963AB8FBBDE1852DCF553FEDBC31F464D80EE7D40AE683122B45070"),
                    0,
                    hexStringToByteArray("2D18BD6C14E6D15BF8B5085C9B74F3DAAE3B03CC2014770A599D8C1539E50F8E")
            ),
            new EIP2333TestCase(
                    hexStringToByteArray("3141592653589793238462643383279502884197169399375105820974944592"),
                    hexStringToByteArray("41C9E07822B092A93FD6797396338C3ADA4170CC81829FDFCE6B5D34BD5E7EC7"),
                    3141592653L,
                    hexStringToByteArray("384843FAD5F3D777EA39DE3E47A8F999AE91F89E42BFFA993D91D9782D152A0F")
            ),
            new EIP2333TestCase(
                    hexStringToByteArray("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00"),
                    hexStringToByteArray("3CFA341AB3910A7D00D933D8F7C4FE87C91798A0397421D6B19FD5B815132E80"),
                    4294967295L,
                    hexStringToByteArray("40E86285582F35B28821340F6A53B448588EFA575BC4D88C32EF8567B8D9479B")
            ),
            new EIP2333TestCase(
                    hexStringToByteArray("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
                    hexStringToByteArray("2A0E28FFA5FBBE2F8E7AAD4ED94F745D6BF755C51182E119BB1694FE61D3AFCA"),
                    42,
                    hexStringToByteArray("455C0DC9FCCB3395825D92A60D2672D69416BE1C2578A87A7A3D3CED11EBB88D")
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
