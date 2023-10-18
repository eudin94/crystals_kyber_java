package br.edu.ifrs.restinga;

import com.swiftcryptollc.crypto.provider.*;
import com.swiftcryptollc.crypto.provider.kyber.Indcpa;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.decrypt;
import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.encrypt;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;



public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        String mensagem = """
                Se tu me amas, ama-me baixinho
                Não o grites de cima dos telhados
                Deixa em paz os passarinhos
                Deixa em paz a mim!
                Se me queres,
                enfim,
                tem de ser bem devagarinho, Amada,
                que a vida é breve, e o amor mais breve ainda...""";

        byte[] mensagemEmBytes = mensagem.getBytes();


        System.out.println("Alice gera um par de chaves e manda sua chave pública para Bob");
        final var aliceKeyPair = aliceGeneratesKeyPair();

        System.out.println("Chave publica da alice:" +  Base64.getEncoder().encodeToString(aliceKeyPair.getPublic().getEncoded()));
        System.out.println("Chave privada da alice:" +  Base64.getEncoder().encodeToString(aliceKeyPair.getPrivate().getEncoded()));

        System.out.println("-------------------------------------------------");
        System.out.println("Bob gera um par de chaves");
        final var bobKeyPair = bobGeneratesKeyPair();

        System.out.println("Chave publica do Bob:" +  Base64.getEncoder().encodeToString(bobKeyPair.getPublic().getEncoded()));
        System.out.println("Chave privada do Bob:" +  Base64.getEncoder().encodeToString(bobKeyPair.getPrivate().getEncoded()));

        System.out.println("----------------------------------------------------");
        System.out.println("Bob gera um acordo inicial de chaves a partir de sua chave privada");
        final var bobKeyAgreement = bobGeneratesKeyAgreement(bobKeyPair.getPrivate());


        System.out.println("Bob gera um KyberEncrypted, carregando a chave secreta e o texto cifrado a partir da chave pública de Alice, então envia para ela o texto cifrado");
        var kyberEncrypted = bobGeneratesKyberEncrypted(bobKeyAgreement, aliceKeyPair.getPublic());

        // setando a cifra no formato x.509, aceito pelo algoritmo
        byte[] coins = {4};
        // encripta a mensagem utilizando a chave publica do bob
        byte[] mensagemBytesEncriptado = encrypt(mensagemEmBytes, bobKeyPair.getPublic().getEncoded(), coins, KyberKeySize.KEY_1024.getParamsK());

        // transforma para a cifra do Kyber
        KyberCipherText msgNoKyber = new KyberCipherText(mensagemBytesEncriptado, new BigInteger("2") , new BigInteger("2"));

        // e adiciona a cifra do kyber no pacote de envio
        kyberEncrypted.setCipherText(msgNoKyber);

        System.out.println("Cifra Kiber: " + Base64.getEncoder().encodeToString(kyberEncrypted.getCipherText().getEncoded()));

        System.out.println("------------------------------------------------------");

        System.out.println("Alice cria seu próprio acordo de chaves e o inicializa com sua chave privada");
        final var aliceKeyAgreement = aliceGeneratesKeyAgreement(aliceKeyPair.getPrivate());

        System.out.println("Alice gera a mesma chave secreta a partir do texto cifrado assim gerando um KyberDecrypted");
        System.out.println("KyberDecrypted carrega a chave secreta(será a mesma que Bob gerou) e a variante");
        final var kyberDecrypted = aliceGeneratesKyberDecrypted(aliceKeyAgreement, kyberEncrypted.getCipherText());

        System.out.println("ENCRYPTED SECRET KEY = " + Base64.getEncoder().encodeToString(kyberEncrypted.getSecretKey().getEncoded()));
        System.out.println("DECRYPTED SECRET KEY = " + Base64.getEncoder().encodeToString(kyberDecrypted.getSecretKey().getEncoded()));

        System.out.println("VVVVVVVVVVVVVVVVVVVVVVVVV");

        // utilizando a chave criada, Alice decriptografa a mensagem recebida
        byte[] mensagemRecebida = decrypt(kyberEncrypted.getCipherText().getC(), kyberDecrypted.getSecretKey().getEncoded(), KyberKeySize.KEY_1024.getParamsK());
        System.out.println("Mensagem que alice recebe: " +  Base64.getEncoder().encodeToString(mensagemRecebida));

        // ----------------------------



        KyberPackedPKI kpPKI = new KyberPackedPKI();
        kpPKI = Indcpa.generateKyberKeys(4);


        System.out.println(mensagemBytesEncriptado.toString());

        byte[] mensagemBytesDecriptado = decrypt(mensagemBytesEncriptado, kpPKI.getPackedPrivateKey(), KyberKeySize.KEY_1024.getParamsK());

        String mensagemNova = mensagemBytesDecriptado.toString();
        System.out.println(Base64.getEncoder().encodeToString(mensagemBytesEncriptado));
        System.out.println();
        System.out.println(Base64.getEncoder().encodeToString(mensagemBytesDecriptado));



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