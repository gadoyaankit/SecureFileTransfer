import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;


class FileEncrypt {
	 void encryptMode(String[] args){
		/*
		 * get values from arguments
		 */
		String publicKeyFileName=args[1];
		String privateKeyFileName=args[2];
		String messageFileName=args[3];
		String cipherFileName=args[4];
		/*	
		 * Create cipher object
		 */
		Cipher publicCipher = null, secretCipher = null;
		try {
			publicCipher = Cipher.getInstance("RSA");  //public cryptography
			/*
			 * using AES as secret key cryptography 
			 */
			secretCipher = Cipher.getInstance("AES/CBC/ISO10126Padding"); 
					 
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		/*
		 * Create a signature object
		 */
		Signature sig = null;
		try {
			/*
			 * using SHA
			 */
			sig = Signature.getInstance("SHA512withRSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		/*
		 * Make KeyFactory object
		 */
		KeyFactory rsaKeyFactory = null;
		try {
			rsaKeyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		
		byte initialisationVector[]; // for use with AES
		/*
		 * Byte arrays of various objects
		 */
		byte ciphertext[] = null, publickeyBytes[], cipheraesKey[] = null, 
		message[], privatekeyBytes[], signatureData[] = null;
		
		/*
		 * Generate AES key i.e. Secret Key
		 */
		Key aeskey; // create a reference to AES key
		KeyGenerator aeskeygen = null;
		try {
			aeskeygen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		aeskey = aeskeygen.generateKey();			
		
		/*
		 * Make the file object. Pass this file to a function so that it
		 * returns the contents of the file in the form of byte array
		 */
		File f=new File(messageFileName);
		
		message = getBytes(f);
		
		
		/*
		 * Encrypt the message with generated AES key.
		 * Store it in cipherText
		 */
		try {
			secretCipher.init(Cipher.ENCRYPT_MODE, aeskey);
		} catch (InvalidKeyException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		initialisationVector = secretCipher.getIV();
		try {
			ciphertext = secretCipher.doFinal(message);
		} catch (IllegalBlockSizeException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		} catch (BadPaddingException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
	        
		/*
		 * Read the RSA public key.
		 * Convert it into byte array.
		 * Keys have to be in x509 specification 
		 */
		publickeyBytes = getBytes(new File(publicKeyFileName));
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publickeyBytes);
		PublicKey pubKey = null;
		try {
			pubKey = rsaKeyFactory.generatePublic(pubSpec);
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		/*
		 * Read the RSA private key.
		 * Convert it into byte array.
		 * Keys have to be in PKCS8 specification 
		 */
		privatekeyBytes = getBytes(new File(privateKeyFileName));
		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privatekeyBytes);
		PrivateKey privKey = null;
		try {
			privKey = rsaKeyFactory.generatePrivate(privSpec);
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		/*
		 * Encrypt AES key using public cryptography
		 */
		try {
			publicCipher.init(Cipher.WRAP_MODE, pubKey);
		} catch (InvalidKeyException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		try {
			cipheraesKey = publicCipher.wrap(aeskey);
		} catch (InvalidKeyException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		} catch (IllegalBlockSizeException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		/*
		 * Sign the ciphertext + key + 
		 * Initialization vector using private key
		 */
		try {
			sig.initSign(privKey);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		try {
			sig.update(ciphertext);
			sig.update(cipheraesKey);
			sig.update(initialisationVector);
			signatureData = sig.sign();
		} catch (SignatureException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(cipherFileName);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		DataOutputStream dos = new DataOutputStream(fos);
		/*
		 * First write the length and then the data to the cipher file
		 * 1) write AESKeyLength
		 * 2) CipherText length
		 * 3) Initialization Vector
		 * 4) Signature Data
		 * 5) CipherAES key
		 * 6) CiphrerText
		 * 7) Initialization Vector
		 * 8) Signature Data
		 */
		try {
			dos.writeInt(cipheraesKey.length);
			dos.writeInt(ciphertext.length);
			dos.writeInt(initialisationVector.length);
			dos.writeInt(signatureData.length);
			dos.write(cipheraesKey);			
			dos.write(ciphertext);
			dos.write(initialisationVector);
			dos.write(signatureData);
			dos.close();
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
