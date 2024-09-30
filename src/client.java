import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

public class client {
    // Providing RSA Signature
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    // Verify RSA Signature
    public static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }

    // AES Encryption for messages
    public static byte[] encryptAES(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    // RSA Encryption for AES key
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        // Load client's private and public keys
        PrivateKey clientPrivateKey = KeyPairGeneratorUtil.loadPrivateKey("clientPrivateKey");
        PublicKey serverPublicKey = KeyPairGeneratorUtil.loadPublicKey("serverPublicKey");

        // Print client's private key and server's public key
        System.out.println("Client Private Key: " + Base64.getEncoder().encodeToString(clientPrivateKey.getEncoded()));
        System.out.println("Server Public Key: " + Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));

        // Step 1: Send a challenge to the server
        String challenge = "Are you there?";
        byte[] signedChallenge = signMessage(challenge, clientPrivateKey);
        System.out.println("Signed Challenge: " + Base64.getEncoder().encodeToString(signedChallenge));

        // Connect to the server
        Socket socket = new Socket("localhost", 8080);
        OutputStream outputStream = socket.getOutputStream();
        PrintWriter writer = new PrintWriter(outputStream, true);

        // Send signed challenge to server
        writer.println(Base64.getEncoder().encodeToString(signedChallenge));

        // Wait for server's response
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String serverResponse = reader.readLine();
        byte[] serverResponseSignature = Base64.getDecoder().decode(reader.readLine());

        // Verify server's response
        boolean isServerResponseValid = verifySignature(serverResponse, serverResponseSignature, serverPublicKey);
        if (!isServerResponseValid) {
            System.out.println("Server response is invalid!");
            socket.close();
            return;
        }

        // Step 2: Generate AES key for symmetric encryption
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey aesKey = aesKeyGen.generateKey();
        System.out.println("Generated AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

        // Step 3: Prepare a message to send to server
        String message = "This is a secret message";

        // Sign the message using client's private RSA key
        byte[] signature = signMessage(message, clientPrivateKey);
        System.out.println("Message is signed, Signature: " + Base64.getEncoder().encodeToString(signature));

        // Step 4: Concatenate the message and the signature, then encrypt it using the AES key
        String messageWithSignature = message + "::SIGNATURE::" + Base64.getEncoder().encodeToString(signature);
        byte[] encryptedMessage = encryptAES(messageWithSignature.getBytes(), aesKey);
        System.out.println("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedMessage));

        // Step 5: Encrypt the AES key using server's public RSA key
        byte[] encryptedAESKey = encryptRSA(aesKey.getEncoded(), serverPublicKey);
        System.out.println("Encrypted AES Key: " + Base64.getEncoder().encodeToString(encryptedAESKey));

        // Step 6: Send encrypted AES key and message from client
        writer.println(Base64.getEncoder().encodeToString(encryptedAESKey));
        writer.println(Base64.getEncoder().encodeToString(encryptedMessage));
        System.out.println("Encrypted AES key and message sent.");

        // Step 7: Close connections
        writer.close();
        socket.close();
    }
}
