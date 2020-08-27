package com.debuggor.schnorrkel.sign;

import com.debuggor.schnorrkel.utils.HexUtils;


/**
 * @Author:yong.huang
 * @Date:2020-07-29 23:03
 */
public class KeyTest {

    public static void main(String[] args) {
        byte[] seed = HexUtils.hexToBytes("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae");
        KeyPair keyPair = KeyPair.fromSecretSeed(seed, ExpansionMode.Ed25519);
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


        KeyPair keyPair1 = KeyPair.fromSecretSeed(HexUtils.hexToBytes("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"), ExpansionMode.Ed25519);

        PrivateKey privateKey1 = keyPair.getPrivateKey();
        byte[] privateKeyBytes = privateKey1.toPrivateKey();
        System.out.println("private key:" + HexUtils.bytesToHex(privateKeyBytes));

        KeyPair keyPair2 = KeyPair.fromPrivateKey(HexUtils.hexToBytes("e08d5baee7dae0f0463994503b812677c9523bce7653f724a59d28cf35581f73cd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"));

        PublicKey publicKey2 = keyPair2.getPublicKey();
        byte[] publicKeyBytes2 = publicKey2.toPublicKey();
        System.out.println("public key:" + HexUtils.bytesToHex(publicKeyBytes2));

    }




}
