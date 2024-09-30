import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

public class server {
    // RSA Signature Verification
    public static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }

    // AES Decryption
    public static byte[] decryptAES(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    // RSA Decryption (for AES key)
    public static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // RSA Signature Generation
    private static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    public static void main(String[] args) throws Exception {
        // Step 1: Load server's private and public keys
        PrivateKey serverPrivateKey = KeyPairGeneratorUtil.loadPrivateKey("serverPrivateKey");
        PublicKey clientPublicKey = KeyPairGeneratorUtil.loadPublicKey("clientPublicKey");

        // Print server's private key and client's public key
        System.out.println("Server Private Key: " + Base64.getEncoder().encodeToString(serverPrivateKey.getEncoded()));
        System.out.println("Client Public Key: " + Base64.getEncoder().encodeToString(clientPublicKey.getEncoded()));

        // Step 2: Start server socket and listen for client connections
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Server is waiting for client connection...");

        Socket socket = serverSocket.accept();
        System.out.println("Client connected!");

        // Step 3: Read the signed challenge from the client
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String signedChallengeBase64 = reader.readLine();
        byte[] signedChallenge = Base64.getDecoder().decode(signedChallengeBase64);

        // Step 4: Verify the client's challenge
        String challenge = "Are you there?";
        boolean isChallengeValid = verifySignature(challenge, signedChallenge, clientPublicKey);
        System.out.println("Is the client's challenge valid? " + isChallengeValid);

        // Respond to the challenge
        String serverResponse = "I am here!";
        byte[] responseSignature = signMessage(serverResponse, serverPrivateKey);
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
        writer.println(serverResponse);
        writer.println(Base64.getEncoder().encodeToString(responseSignature));

        // Read encrypted AES key and message from client
        String encryptedAESKeyBase64 = reader.readLine();
        String encryptedMessageBase64 = reader.readLine();

        byte[] encryptedAESKey = Base64.getDecoder().decode(encryptedAESKeyBase64);
        byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageBase64);

        System.out.println("Received encrypted AES key: " + encryptedAESKeyBase64);
        System.out.println("Received encrypted message: " + encryptedMessageBase64);

        // Step 5: Decrypt the AES key using server's private RSA key
        byte[] aesKeyBytes = decryptRSA(encryptedAESKey, serverPrivateKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        System.out.println("Decrypted AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

        // Step 6: Decrypt the message using the decrypted AES key
        byte[] decryptedMessageBytes = decryptAES(encryptedMessage, aesKey);
        String decryptedMessageWithSignature = new String(decryptedMessageBytes);
        System.out.println("Decrypted message with signature: " + decryptedMessageWithSignature);

        // Step 7: Split the decrypted message into actual message and the signature
        String[] parts = decryptedMessageWithSignature.split("::SIGNATURE::");
        if (parts.length != 2) {
            System.out.println("Invalid message format, signature is missing or malformed.");
            socket.close();
            serverSocket.close();
            return;
        }

        String originalMessage = parts[0];
        byte[] receivedSignature = Base64.getDecoder().decode(parts[1]);

        // Step 8: Verify the signature using client's public key
        boolean isSignatureValid = verifySignature(originalMessage, receivedSignature, clientPublicKey);
        System.out.println("Is the signature valid? " + isSignatureValid);

        if (isSignatureValid) {
            System.out.println("Server confirms the authenticity of the message: " + originalMessage);
        } else {
            System.out.println("Message signature verification failed!");
        }

        // Step 10: Close connections
        writer.close();
        reader.close();
        socket.close();
        serverSocket.close();
    }
}
