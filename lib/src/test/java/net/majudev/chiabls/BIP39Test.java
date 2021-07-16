package net.majudev.chiabls;

import org.junit.jupiter.api.Test;

import java.util.Arrays;


class BIP39Test {

    @Test
    void generateSeed() {
        for(int i = 0; i < 10; ++i) {
            String seed = BIP39.generateSeed();
            assert (BIP39.verifySeed(seed));
        }
    }

    @Test
    void verifySeed() {
        String[] vectors = {
                "phrase series ski bless ghost slam cry anchor rather crumble canvas team accident chair melody file dumb season fruit document notice minor angle mansion",
                "false elevator bike cabbage more injury crash bottom purse shell loop live donkey bubble crash pitch reflect garbage cradle hill violin punch cram narrow",
                "leader coyote top road region prosper lab casual oyster inmate virus paddle engine little gesture cabbage upgrade knife dice ecology emerge exotic antique scrub",
                "ranch trial enrich map brother trumpet parrot canvas decline voice metal toward wood wave leopard know razor horse absorb duck reject bridge key comic",
                "ranch trial enrich map brother trumpet parrot canvas decline voice metal toward wood wave leopard know razor horse absorb duck reject bridge key trezor",
                "seed turn human tobacco cost ocean desk motion permit leopard tag light verb slab cabin chat craft spread divorce category bronze rather barely limit"
        };
        boolean[] pass = {
                true,
                true,
                false,
                false,
                false,
                true,
        };
        for(int i = 0; i < vectors.length; ++i){
            boolean res = BIP39.verifySeed(vectors[i]);
            assert(res == pass[i]);
        }
    }

    @Test
    void derivePrivkey() {
        String[] seeds = {
                "seed turn human tobacco cost ocean desk motion permit leopard tag light verb slab cabin chat craft spread divorce category bronze rather barely limit",
                "copy super rice mind excess disorder dumb provide mandate note race refuse aisle frown sing busy lesson welcome crucial elite enrich escape sight adjust",
                "great castle fatigue now chapter nut camp height sorry sphere enrich picnic bubble burden supreme such tongue output dish idea palm fun seek regret",
                "great castle fatigue now chapter nut camp height sorry sphere enrich picnic bubble burden supreme such tongue output dish idea palm fun seek regret"
        };
        String[] passwords = {
                "",
                "TREZOR",
                "BLSCHIA",
                "UwU OwO"
        };
        byte[][] privkeys = {
                hexStringToByteArray("e4c281f859f4535bfbd00a8fd690905ad83adcd650c01aced926ad7662216e7e05a3b57ee7646c260b12bd10c4ed2c6b050a8fa3edea6adb8eb1230fe17e4f97"),
                hexStringToByteArray("feabee17afa8dae46f6447b5b2e84ce3e24c7b9f9bccde0de269c9ccb3cd8d4b709d87a7d5c903b9f8869105a6aa172dd3e95fc18eded612f92a7315d3a48689"),
                hexStringToByteArray("c101dfb7c36be9f4b22d736de0c64d6ac592868625ff7a1809b4476176a97052f603cedae990331fa3631666d24f29589bf2234ab6137911a3ec148eaa970a0b"),
                hexStringToByteArray("ac9364a7e9ccae5d58bac96df7107a53757abb608f168f1a968e16854b663f7bf6d9e74502610c52378eda04d5a64ff91483fbf563445de8bede1add8a569e15")
        };
        for(int i = 0; i < seeds.length; ++i){
            byte[] res = BIP39.derivePrivkey(seeds[i], passwords[i]);
            assert(Arrays.equals(res, privkeys[i]));
        }
    }

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
