import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;


public class FileDecrypt {
	public void decryptMode(String[] args) {
		/*
		 * get values from arguments
		 */
		String publicKeyFileName=args[2];
		String privateKeyFileName=args[1];
		String messageFileName=args[4];
		String cipherFileName=args[3];
		
		KeyFactory rsaKeyFactory = null;
		try {
			rsaKeyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		byte initialisationVector[] = null; // for use with AES
		/*
		 * Byte arrays of various objects
		 */
		byte ciphertext[] = null, publickeyBytes[], cipheraesKey[] = null, 
		message[] = null, privatekeyBytes[], signatureData[] = null;
 
		/*
		 * Read the cipher file
		 */
		DataInputStream dis = null;
		try {
			dis = new DataInputStream(new FileInputStream(cipherFileName));
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		/*
		 * read it in the order as encrypted
		 */
		try {
			cipheraesKey = new byte[dis.readInt()];
			ciphertext = new byte[dis.readInt()];
			initialisationVector = new byte[dis.readInt()];
			signatureData = new byte[dis.readInt()];
			dis.read(cipheraesKey);
			dis.read(ciphertext);
			dis.read(initialisationVector);
			dis.read(signatureData);
			dis.close();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		//Read key files
		privatekeyBytes = getBytes(new File(privateKeyFileName));
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privatekeyBytes);
		PrivateKey privKey = null;
		try {
			privKey = rsaKeyFactory.generatePrivate(privateSpec);
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		publickeyBytes = getBytes(new File(publicKeyFileName));
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publickeyBytes);
		PublicKey pubKey = null;
		try {
			pubKey = rsaKeyFactory.generatePublic(publicSpec);
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		/*
		 * Create a signature object
		 */
		Signature sig = null;
		try {
			sig = Signature.getInstance("SHA512withRSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}//Verify signature
		try {
			sig.initVerify(pubKey);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			sig.update(ciphertext);
			sig.update(cipheraesKey);
			sig.update(initialisationVector);
		} catch (SignatureException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			if(!sig.verify(signatureData)) {
				System.err.println("Signature cannot be verfied.");
				return;
			}
		} catch (SignatureException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		/*	
		 * Create cipher object
		 */
		Cipher publicCipher = null, secretCipher = null;
		try {
			publicCipher = Cipher.getInstance("RSA"); 
			secretCipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
					 
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}

		//Decrypt aes key
		Key aeskey = null; // create a reference to AES key
		try {
			publicCipher.init(Cipher.UNWRAP_MODE, privKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			aeskey = publicCipher.unwrap(cipheraesKey, "AES", Cipher.SECRET_KEY);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//init cipher with iv
		try {
			secretCipher.init(Cipher.DECRYPT_MODE, aeskey, new IvParameterSpec(initialisationVector));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//decrypt the data
		try {
			message = secretCipher.doFinal(ciphertext);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//output the decrypted data into file			
		try {
			FileOutputStream fos = new FileOutputStream(messageFileName);
			DataOutputStream dos = new DataOutputStream(fos);
			dos.write(message);
			dos.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}			
	}
	private static byte[] getBytes(File plainFile) {
		InputStream fis = null;
		try {
			fis = new FileInputStream(plainFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		DataInputStream dis ;
		dis = new DataInputStream(fis);
		
		byte[] myBytes=new byte[(int) plainFile.length()];
		try {
			dis.readFully(myBytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			dis.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return myBytes;
	}
}
