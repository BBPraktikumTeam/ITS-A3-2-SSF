package ssf;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.*;

public class SSF {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		File prvFile = null;
		File pubFile = null;
		File inFile = null;
		File outFile = null;
		if (args.length == 4) {
			prvFile = new File(args[0]);
			pubFile = new File(args[1]);
			inFile = new File(args[2]);
			outFile = new File(args[3]);
			ssf(prvFile, pubFile, inFile, outFile);
		} else {
			System.out
					.println("Bitte Parameter in der Reihenfolge: <privater Schluessel des Senders> <oeffentlicher Schluessel des Empfaengers> <Queldatei> <Zieldatei> angeben.");
			System.exit(1);
		}
	}
	
	private static void ssf(File prvFile, File pubFile, File inFile, File outFile) {
		//Keys erzeugen
		RSAPrivateKey privateKey = (RSAPrivateKey) getKey(prvFile,
				"RSA", true);
		RSAPublicKey publicKey = (RSAPublicKey) getKey(pubFile, "RSA", false);
		SecretKey secretKey = createSecretAESKey();
		
		//Geheimen Schlüssel signieren und verschlüsseln
		byte[] secretKeySign = sign(secretKey.getEncoded(), privateKey);
		byte[] secretKeyEnc = encode(secretKey.getEncoded(), "RSA", publicKey);
		
		//Daten verschlüsseln
		byte[] data = getDataFromFile(inFile);
		byte[] encData = encode(data, "AES", secretKey);
		
		//Daten in Datei schreiben
		DataOutputStream out = null;
		try {
			out = new DataOutputStream(new FileOutputStream(outFile));
			//Länge des verschlüsselten geheimen Schlüssels (integer)
			out.writeInt(secretKeyEnc.length);
			//Verschlüsselter geheimer Schlüssel (Bytefolge)
			out.write(secretKeyEnc);
			//Länge der Signatur des geheimen Schlüssels (integer)
			out.writeInt(secretKeySign.length);
			// Signatur des geheimen Schlüssels (Bytefolge)
			out.write(secretKeySign);
			//Verschlüsselte Dateidaten (Bytefolge)
			out.write(encData);
			
			System.out.println("Fertig!");
		} catch (Exception e) {
			error(e);
		}
	}
	
	private static RSAKey getKey(File keyFile, String algo, boolean isPrivate) {
		String name = "";
		RSAKey key = null;
		try {
			FileInputStream fis = new FileInputStream(keyFile);
			// Namenslänge auslesen
			byte[] intLength = new byte[4];
			fis.read(intLength);
			ByteBuffer bb = ByteBuffer.wrap(intLength);
			int nameLength = bb.getInt();
			System.out.println(nameLength);
			// Namen auslesen
			byte[] nameBytes = new byte[nameLength];
			fis.read(nameBytes);
			name = new String(nameBytes);
			System.out.println(name);
			// Key Länge auslesen.
			fis.read(intLength);
			bb = ByteBuffer.wrap(intLength);
			int keyLength = bb.getInt();
			System.out.println(keyLength);
			// KeyAuslesen
			byte[] keyBytes = new byte[keyLength];
			fis.read(keyBytes);
			// PrivateKey Object erstellen
			KeyFactory keyFactory = KeyFactory.getInstance(algo);
			if (isPrivate) {
				KeySpec ks = new PKCS8EncodedKeySpec(keyBytes);
				key = (RSAPrivateKey) keyFactory.generatePrivate(ks);
				System.out.println(((RSAPrivateKey) key).getFormat());
			} else {
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
				key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
				System.out.println(((RSAPublicKey) key).getFormat());
			}
			String prvOrPub = "";
			if (isPrivate) {
				prvOrPub = "Private";
			} else {
				prvOrPub = "Public";
			}
			System.out.println(prvOrPub + "Key erfolgreich eingelesen: " + key);
		} catch (Exception e) {
			error(e);
		}
		return key;
	}
	
	private static SecretKey createSecretAESKey() {
		SecretKey skey = null;
		try {
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(128); // Schlüssellänge
			skey = kg.generateKey();
			System.out.println("Geheimen Schlüssel erzeugt: " + new String(skey.getEncoded()));
		} catch (Exception e) {
			error(e);
		}
		return skey;
	}
	
	private static byte[] sign(byte[] dataBytes, RSAPrivateKey key) {
		Signature rsa = null;
		byte[] signature = null;
		try {
			rsa = Signature.getInstance("SHA1withRSA");
			rsa.initSign(key);
			rsa.update(dataBytes);
			signature = rsa.sign();
			System.out.println("Geheimen Schlüssel signiert: " + new String(signature));
		} catch (Exception e) {
			error(e);
		}
		return signature;
	}
	
	private static byte[] getDataFromFile(File file) {
		byte[] buffer = null;
		try {
			DataInputStream in = new DataInputStream(new FileInputStream(file));
			int bytes = in.available();
			System.out.println("Bytes: "+ bytes);
			buffer = new byte[bytes];
			in.read(buffer);
			System.out.println("Daten aus Datei ausgelesen");
		} catch (Exception e) {
			error(e);
		}
		return buffer.clone();
	}
	
	private static byte[] encode(byte[] dataBytes, String algo, Key key) {
		byte[] encRest = null;
		Cipher cipher = null;
		try {
			//Cipher initialisieren
			cipher = Cipher.getInstance(algo);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			System.out.println(cipher.getOutputSize(21));
			
			// Daten verschlüsseln
			// (update wird bei großen Datenmengen mehrfach aufgerufen werden!)
			//byte[] encData = cipher.update(dataBytes);

			// mit doFinal abschließen (Rest inkl. Padding ..)
			encRest = cipher.doFinal(dataBytes);

			System.out.println(encRest.length);
			System.out.println("Daten verschlüsselt mit " + algo);
			//System.out.println("Verschlüsselte Daten: " + new String(encData) + " # " + new String(encRest));
		} catch (Exception e) {
			error(e);
		}
		return encRest;
	}

	private static void error(Exception e) {
		if (e instanceof IOException || e instanceof FileNotFoundException) {
			System.out.println("File not found");
		} else if (e instanceof NoSuchAlgorithmException) {
			System.out.println("Algorithm not found");
		} else if (e instanceof InvalidKeySpecException) {
			System.out.println("Invalid key");
		} else if (e instanceof NoSuchProviderException) {
			System.out.println("Provider not found");
		} else if (e instanceof SignatureException) {
			System.out.println("Fehler beim Signieren");
		} else if (e instanceof BadPaddingException || e instanceof IllegalBlockSizeException) {
			System.out.println("Fehler bei Verschlüsselung");
		} else if (e instanceof NoSuchPaddingException) {
			System.out.println("Padding not found");
		} else {
			System.out.println("Exception: " + e.getMessage());
		}	
		e.printStackTrace();
	}

}
