package br.edu.ifrs.restinga;

import com.swiftcryptollc.crypto.provider.KyberCipherText;
import com.swiftcryptollc.crypto.provider.KyberDecrypted;
import com.swiftcryptollc.crypto.provider.KyberEncrypted;
import com.swiftcryptollc.crypto.provider.KyberJCE;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        System.out.println("Alice gera um par de chaves e manda sua chave pública para Bob");
        final var aliceKeyPair = aliceGeneratesKeyPair();

        System.out.println("Bob gera um par de chaves");
        final var bobKeyPair = bobGeneratesKeyPair();

        System.out.println("Bob gera um acordo inicial de chaves a partir de sua chave privada");
        final var bobKeyAgreement = bobGeneratesKeyAgreement(bobKeyPair.getPrivate());

        System.out.println("Bob gera um KyberEncrypted, carregando a chave secreta e o texto cifrado a partir da chave pública de Alice, então envia para ela o texto cifrado");
        final var kyberEncrypted = bobGeneratesKyberEncrypted(bobKeyAgreement, aliceKeyPair.getPublic());

        System.out.println("Alice cria seu próprio acordo de chaves e o inicializa com sua chave privada");
        final var aliceKeyAgreement = aliceGeneratesKeyAgreement(aliceKeyPair.getPrivate());

        System.out.println("Alice gera a mesma chave secreta a partir do texto cifrado assim gerando um KyberDecrypted");
        System.out.println("KyberDecrypted carrega a chave secreta(será a mesma que Bob gerou) e a variante");
        final var kyberDecrypted = aliceGeneratesKyberDecrypted(aliceKeyAgreement, kyberEncrypted.getCipherText());

        System.out.println("ENCRYPTED SECRET KEY = " + Base64.getEncoder().encodeToString(kyberEncrypted.getSecretKey().getEncoded()));
        System.out.println("DECRYPTED SECRET KEY = " + Base64.getEncoder().encodeToString(kyberDecrypted.getSecretKey().getEncoded()));
    }

    private static KeyPair aliceGeneratesKeyPair() throws NoSuchAlgorithmException {
        // "Kyber512", "Kyber768", "Kyber1024" são as opções para geração de chaves
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
        return keyGen.generateKeyPair();
    }

    private static KeyPair bobGeneratesKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
        return keyGen.generateKeyPair();
    }

    private static KeyAgreement bobGeneratesKeyAgreement(final PrivateKey bobPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("Kyber");
        bobKeyAgreement.init(bobPrivateKey);
        return bobKeyAgreement;
    }

    private static KyberEncrypted bobGeneratesKyberEncrypted(final KeyAgreement bobKeyAgreement, final PublicKey alicePublicKey) throws InvalidKeyException {
        return (KyberEncrypted) bobKeyAgreement.doPhase(alicePublicKey, true);
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