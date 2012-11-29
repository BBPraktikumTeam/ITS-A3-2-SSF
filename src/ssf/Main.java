package ssf;

public class Main {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		String prvFile = "";
		String pubFile = "";
		String inFile = "";
		String outFile = "";
		if (args.length == 4) {
			prvFile = args[0];
			pubFile = args[1];
			inFile = args[2];
			outFile = args[3];
		} else {
			System.out.println("Bitte Parameter in der Reihenfolge: <privater Schluessel des Senders> <oeffentlicher Schluessel des Empfaengers> <Queldatei> <Zieldatei> angeben.");
			System.exit(1);
		}
		
		byte[] privateKeyBytes = getKey(prvFile);
		byte[] publicKeyBytes = getKey(pubFile);
		byte[] secretKeyBytes = createSecretAESKey();
		byte[] secretKeySign = sign(secretKeyBytes, privateKeyBytes);
		byte[] secretKeyEnc = encodeRSA(secretKeyBytes, publicKeyBytes);
		byte[] dataEnc = encodeAES(inFile, secretKeyBytes);
		
		//TODO: write
		

	}

	private static byte[] encodeAES(String dataFile, byte[] keyBytes) {
		// TODO Auto-generated method stub
		return null;
	}

	private static byte[] encodeRSA(byte[] dataBytes, byte[] keyBytes) {
		// TODO Auto-generated method stub
		return null;
	}

	private static byte[] sign(byte[] dataBytes, byte[] keyBytes) {
		// TODO Auto-generated method stub
		return null;
	}

	private static byte[] createSecretAESKey() {
		// TODO Auto-generated method stub
		return null;
	}

	private static byte[] getKey(String keyFile) {
		// TODO Auto-generated method stub
		return null;
	}

}
