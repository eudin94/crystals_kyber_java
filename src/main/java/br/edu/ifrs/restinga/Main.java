package br.edu.ifrs.restinga;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import com.swiftcryptollc.crypto.interfaces.KyberPublicKey;
import com.swiftcryptollc.crypto.provider.*;
import com.swiftcryptollc.crypto.spec.KyberGenParameterSpec;
import com.swiftcryptollc.crypto.util.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.util.ServiceLoader;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.*;


public class Main {
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    public static void main(String[] args) throws Exception {

        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        String mensagem = """
                Se tu me amas, amame baixinho
                Nao o grites de cima dos telhados
                Deixa em paz os passarinhos
                Deixa em paz a mim
                Se me queres,
                enfim,
                tem de ser bem devagarinho, Amada,
                que a vida e breve, e o amor mais breve ainda...""";

        byte[] msgEmBytes = mensagem.getBytes();


        System.out.println("Alice gera um par de chaves e manda sua chave pública para Bob");
        final var aliceKeyPair = aliceGeneratesKeyPair();

        //System.out.println("Chave publica da alice:" +  Base64.getEncoder().encodeToString(aliceKeyPair.getPublic().getEncoded()));
        //System.out.println("Chave privada da alice:" +  Base64.getEncoder().encodeToString(aliceKeyPair.getPrivate().getEncoded()));

        System.out.println("-------------------------------------------------");
        System.out.println("Bob gera um par de chaves");
        final var bobKeyPair = bobGeneratesKeyPair();

        //System.out.println("Chave publica do Bob:" +  Base64.getEncoder().encodeToString(bobKeyPair.getPublic().getEncoded()));
        //System.out.println("Chave privada do Bob:" +  Base64.getEncoder().encodeToString(bobKeyPair.getPrivate().getEncoded()));

        System.out.println("----------------------------------------------------");
        System.out.println("Bob gera um acordo inicial de chaves a partir de sua chave privada");
        final var bobKeyAgreement = bobGeneratesKeyAgreement(bobKeyPair.getPrivate());


        System.out.println("Bob gera um KyberEncrypted, carregando a chave secreta e o texto cifrado a partir da chave pública de Alice, então envia para ela o texto cifrado");
        var kyberEncrypted = bobGeneratesKyberEncrypted(bobKeyAgreement, aliceKeyPair.getPublic());



        //System.out.println("Cifra Kiber: " + Base64.getEncoder().encodeToString(kyberEncrypted.getCipherText().getEncoded()));

        System.out.println("------------------------------------------------------");

        System.out.println("Alice cria seu próprio acordo de chaves e o inicializa com sua chave privada");
        final var aliceKeyAgreement = aliceGeneratesKeyAgreement(aliceKeyPair.getPrivate());

        System.out.println("Alice gera a mesma chave secreta a partir do texto cifrado assim gerando um KyberDecrypted");
        System.out.println("KyberDecrypted carrega a chave secreta(será a mesma que Bob gerou) e a variante");

        final var kyberDecrypted = aliceGeneratesKyberDecrypted(aliceKeyAgreement, kyberEncrypted.getCipherText());

        System.out.println("ENCRYPTED SECRET KEY = " + Base64.getEncoder().encodeToString(kyberEncrypted.getSecretKey().getEncoded()));
        System.out.println("DECRYPTED SECRET KEY = " + Base64.getEncoder().encodeToString(kyberDecrypted.getSecretKey().getEncoded()));


        // -------------------------------------------------------
        // utilizando a chave secreta do kyber para criptografar um dado com AES
        String salt = "D;%yL9TS:5PalS/d";

        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKeyFactory factoryBob = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec specBob = new PBEKeySpec(kyberEncrypted.getSecretKey().getEncoded().toString().toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmpBob = factoryBob.generateSecret(specBob);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tmpBob.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);

        byte[] cipherText = cipher.doFinal(mensagem.getBytes("UTF-8"));
        byte[] msgEncriptada = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, msgEncriptada, 0, iv.length);
        System.arraycopy(cipherText, 0, msgEncriptada, iv.length, cipherText.length);


        System.out.println("Msg encriptada= " + Base64.getEncoder().encodeToString(msgEncriptada));


        // -----------------------------------------------------------
        // decriptografando a mensagem

        SecretKeyFactory factoryAlice = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec specAlice = new PBEKeySpec(kyberEncrypted.getSecretKey().getEncoded().toString().toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmpAlice = factoryAlice.generateSecret(specAlice);
        SecretKeySpec secretKeySpecAlice = new SecretKeySpec(tmpAlice.getEncoded(), "AES");

        Cipher cifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);

        byte[] cifraText = new byte[msgEncriptada.length - 16];
        System.arraycopy(msgEncriptada, 16, cifraText, 0, cifraText.length);

        String msgDescriptada = new String(cifra.doFinal(cifraText), "UTF-8");

        System.out.println("\nMsg Limpa: \n" + msgDescriptada);


    }

    private static KeyPair aliceGeneratesKeyPair() throws NoSuchAlgorithmException {
        // "Kyber512", "Kyber768", "Kyber1024" são as opções para geração de chaves
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
       // var kyberKeygen = new Kyber1024KeyPairGenerator();
        //return kyberKeygen.generateKeyPair();
        return keyGen.generateKeyPair();
    }

    private static KeyPair bobGeneratesKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
        //var kyberKeygen = new Kyber1024KeyPairGenerator();

        return keyGen.generateKeyPair();
    }

    private static KeyAgreement bobGeneratesKeyAgreement(final PrivateKey bobPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("Kyber");
        bobKeyAgreement.init(bobPrivateKey);
        return bobKeyAgreement;
    }

    private static KyberEncrypted bobGeneratesKyberEncrypted(final KeyAgreement bobKeyAgreement, final PublicKey alicePublicKey) throws InvalidKeyException {
        return (KyberEncrypted) bobKeyAgreement.doPhase((KyberPublicKey) alicePublicKey, true);
    }

    private static KeyAgreement aliceGeneratesKeyAgreement(final PrivateKey alicePrivateKey) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("Kyber");
        aliceKeyAgreement.init(alicePrivateKey);
        return aliceKeyAgreement;
    }

    private static KyberDecrypted aliceGeneratesKyberDecrypted(final KeyAgreement aliceKeyAgreement, final KyberCipherText cipherText) throws InvalidKeyException {

        return (KyberDecrypted) aliceKeyAgreement.doPhase(cipherText, true);
    }





}