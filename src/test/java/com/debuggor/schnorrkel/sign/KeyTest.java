package com.debuggor.schnorrkel.sign;

import com.debuggor.schnorrkel.utils.HexUtils;


/**
 * @Author:yong.huang
 * @Date:2020-07-29 23:03
 */
public class KeyTest {

    public static void main(String[] args) {
        byte[] seed = HexUtils.hexToBytes("882749e4a5738ba59e7e25b2cd66c41c9037c4950e3a0cd18846df9814a33d79");
        KeyPair keyPair = KeyPair.fromSecretSeed(seed);
        PrivateKey privateKey = keyPair.getPrivateKey();
        PublicKey publicKey = keyPair.getPublicKey();

        byte[] key = privateKey.getKey();
        byte[] nonce = privateKey.getNonce();
        byte[] pubkey = publicKey.toPublicKey();
        System.out.println("seed:" + HexUtils.bytesToHex(privateKey.getSeed()));
        System.out.println("key:" + HexUtils.bytesToHex(key));
        System.out.println("nonce:" + HexUtils.bytesToHex(nonce));
        System.out.println("pubkey:" + HexUtils.bytesToHex(pubkey));

        KeyPair pair = KeyPair.generateKeyPair();


        KeyPair keyPair1 = KeyPair.fromSecretSeed(HexUtils.hexToBytes("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"));

        PrivateKey privateKey1 = keyPair.getPrivateKey();
        byte[] privateKeyBytes = privateKey1.toPrivateKey();
        System.out.println("private key:" + HexUtils.bytesToHex(privateKeyBytes));

    }




}
