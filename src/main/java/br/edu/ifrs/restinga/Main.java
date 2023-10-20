package br.edu.ifrs.restinga;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import com.swiftcryptollc.crypto.interfaces.KyberPublicKey;
import com.swiftcryptollc.crypto.provider.*;
import com.swiftcryptollc.crypto.spec.KyberGenParameterSpec;
import com.swiftcryptollc.crypto.util.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.util.ServiceLoader;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.*;


public class Main {
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
        byte[] msgEncriptado = encrypt(msgEmBytes, bobKeyPair.getPublic().getEncoded(), msgEmBytes, KyberKeySize.KEY_1024.getParamsK());


        System.out.println("\n*********\nMensagem limpa: " + new String(msgEmBytes,  StandardCharsets.UTF_8));


        System.out.println( "\n*********\nMMensagem encriptada: " + Base64.getEncoder().encodeToString(msgEncriptado));


        byte[] msgDecriptado = decrypt(msgEncriptado, aliceKeyPair.getPrivate().getEncoded(), KyberKeySize.KEY_1024.getParamsK());


        System.out.println("\n*********\nMMensagem decriptada: " + Base64.getEncoder().encodeToString(msgDecriptado));




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