package main;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class playground {
    
	
  public static final int keyLength = 128;
  public static final String charEnc = "UTF-8";
  public static final String transformationString = "AES/CFB/NoPadding";

  public static void main(String[] args) {
    System.out.println("Please enter a message for us to encrypt...");
    Scanner myObj = new Scanner(System.in);
    String message = myObj.nextLine();
    String cipherText;

    try {
      // Step 1
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(keyLength);
      SecretKey secretKey = keyGen.generateKey();

      // Step 2
      Cipher aesCipherForEncryption = Cipher.getInstance(transformationString);

      // Step 3
      byte[] iv = new byte[aesCipherForEncryption.getBlockSize()];
      SecureRandom prng = new SecureRandom();
      prng.nextBytes(iv);

      // Step 4
      aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

      // Step 5
      byte[] encrypted = aesCipherForEncryption.doFinal(message.getBytes(charEnc));
      ByteBuffer cipherData = ByteBuffer.allocate(iv.length + encrypted.length);
      cipherData.put(iv);
      cipherData.put(encrypted);
      cipherText = new String(Base64.getEncoder().encode(cipherData.array()), charEnc);
      System.out
        .println("Encrypted and encoded message is: " + new String(Base64.getEncoder().encode(encrypted), charEnc));
      System.out.println(cipherText);
      System.out.println("\nThe receiver will now initialize the cipher using the IV and decrypt the ciphertext");

      // Step 6
      Cipher aesCipherForDecryption = Cipher.getInstance(transformationString);

      // Step 7
      cipherData = ByteBuffer.wrap(Base64.getDecoder().decode(cipherText.getBytes(charEnc)));
      iv = new byte[aesCipherForDecryption.getBlockSize()];
      cipherData.get(iv);
      encrypted = new byte[cipherData.remaining()];
      cipherData.get(encrypted);
      aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

      // Step 8
      byte[] decrypted = aesCipherForDecryption.doFinal(encrypted);
      System.out.println("Decrypted text message is: " + new String(decrypted, charEnc));
    } catch(NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | UnsupportedEncodingException ex) {
      System.err.println(ex);
    }
  }

}