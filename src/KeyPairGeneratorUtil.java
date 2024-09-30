import java.io.*;
import java.security.*;
import java.util.Base64;

public class KeyPairGeneratorUtil {

    public static void generateKeyPair(String publicKeyPath, String privateKeyPath) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Save the public key
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(publicKeyPath))) {
            oos.writeObject(keyPair.getPublic());
        }

        // Save the private key
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(privateKeyPath))) {
            oos.writeObject(keyPair.getPrivate());
        }

        // Print the generated keys
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        System.out.println("Public Key (" + publicKeyPath + "): \n" + publicKeyBase64);
        System.out.println("Private Key (" + privateKeyPath + "): \n" + privateKeyBase64);
    }

    public static PublicKey loadPublicKey(String publicKeyPath) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(publicKeyPath))) {
            return (PublicKey) ois.readObject();
        }
    }

    public static PrivateKey loadPrivateKey(String privateKeyPath) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(privateKeyPath))) {
            return (PrivateKey) ois.readObject();
        }
    }

    public static void main(String[] args) throws Exception {
        // Generate and store the keys (only need to do this once)
        generateKeyPair("serverPublicKey", "serverPrivateKey");
        generateKeyPair("clientPublicKey", "clientPrivateKey");
        System.out.println("Keys generated and stored successfully.");
    }
}
