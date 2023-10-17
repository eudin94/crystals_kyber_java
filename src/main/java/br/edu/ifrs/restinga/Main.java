package br.edu.ifrs.restinga;

import com.swiftcryptollc.crypto.provider.KyberCipherText;
import com.swiftcryptollc.crypto.provider.KyberDecrypted;
import com.swiftcryptollc.crypto.provider.KyberEncrypted;
import com.swiftcryptollc.crypto.provider.KyberJCE;

import javax.crypto.KeyAgreement;
import java.security.*;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        // Alice gera um par de chaves e manda sua chave pública para Bob
        final var aliceKeyPair = aliceGeneratesKeyPair();

        // Bob gera um par de chaves
        final var bobKeyPair = bobGeneratesKeyPair();

        // Bob gera um acordo inicial de chaves a partir de sua chave privada
        final var bobKeyAgreement = bobGeneratesKeyAgreement(bobKeyPair.getPrivate());

        // Bob gera um KyberEncrypted, carregando a chave secreta e o texto cifrado da chave pública de Alice, então envia para ela o texto cifrado
        final var kyberEncrypted = bobGeneratesKyberEncrypted(bobKeyAgreement, aliceKeyPair.getPublic());

        // Alice cria seu próprio acordo de chaves e o inicializa com sua chave privada
        final var aliceKeyAgreement = aliceGeneratesKeyAgreement(aliceKeyPair.getPrivate());

        // Alice gera a mesma chave secreta a partir do texto cifrado assim gerando um KyberDecrypted
        // KyberDecrypted carrega a chave secreta(será a mesma que Bob gerou) e a variante
        final var kyberDecrypted = aliceGeneratesKyberDecrypted(aliceKeyAgreement, kyberEncrypted.getCipherText());

        final var verification = kyberDecrypted.getSecretKey().equals(kyberEncrypted.getSecretKey());
        System.out.printf("Alice recebeu uma chave secreta igual a de Bob? [%s]%n", verification);
    }

    private static KeyPair aliceGeneratesKeyPair() throws NoSuchAlgorithmException {
        // "Kyber512", "Kyber768", "Kyber1024" são as opções para geração de chaves
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
        final var keyPair = keyGen.generateKeyPair();
        System.out.println("Alice enviou sua chave públicapara Bob!");
        return keyPair;
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
        KyberEncrypted kyberEncrypted = (KyberEncrypted) bobKeyAgreement.doPhase(alicePublicKey, true);
        System.out.println("Bob gerou o texto cifrado e enviou para a Alice");
        return kyberEncrypted;
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