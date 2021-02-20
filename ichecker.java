import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ichecker {

	public static void main(String[] args) {

		try {

			// args[1] = ichecker
			Scanner scan = new Scanner(System.in);

			if (args[0].equals("createCert")){

				String priKey = args[2];					// path of private key file
				String pubKeyCertificate = args[4];			// path of certificate

				Certificate cert = new Certificate();		// keystore password = huceng
	        
		        Process process = Runtime.getRuntime().exec(cert.getCmdarray());

				int exitVal = process.waitFor();
				
				if (exitVal == 0) {
					System.out.println("Public/Private keys were created.");
				}
				
				cert.getSSCertificate(pubKeyCertificate);

				// get password from user to encrypt the private key file
				
				System.out.print("Enter a password: ");
				String password = scan.nextLine();

				Key privateKey = cert.getPrivateKey();
			
				String binPswd = getBinary(password);
				
				MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(binPswd.getBytes());
				byte[] digest = md.digest();
				
				// encrypt private key with AES
				
				SecretKey aeskey = new SecretKeySpec(digest, "AES");
				Cipher encrypt = Cipher.getInstance("AES");
				encrypt.init(Cipher.ENCRYPT_MODE, aeskey);
				
				byte[] byte_key = privateKey.getEncoded();
				String base64key = Base64.getEncoder().encodeToString(byte_key);
				String full_text = base64key + "This is the private key file";
				byte[] encrypted_text = encrypt.doFinal(full_text.getBytes());
				
				// write to file with meaningful text
				
				BufferedWriter bw = new BufferedWriter(new FileWriter(new File(priKey)));
				bw.write(new String(Base64.getEncoder().encodeToString(encrypted_text)));
				bw.close();
				
				System.out.println("Private key file was created.");

			}

			else if (args[0].equals("createReg")){

				// get password from user to decrypt the private key file

				System.out.print("Enter a password: ");
				String pswd = scan.nextLine();
				scan.close();
				
				String bin_pswd = getBinary(pswd);
				
				MessageDigest md2 = MessageDigest.getInstance("MD5");
				md2.update(bin_pswd.getBytes());
				byte[] msgdigest = md2.digest();
				
				SecretKey decaeskey = new SecretKeySpec(msgdigest, "AES");
				Cipher decrypt = Cipher.getInstance("AES");
				decrypt.init(Cipher.DECRYPT_MODE, decaeskey);

				// create the registry file
			
				String reg_file = args[2];
				String monitored_path = args[4];
				String log_file = args[6];
				String hash = args[8];
				String priKey = args[10];
				
				Registry registry = new Registry(reg_file, monitored_path, log_file, hash, priKey);
				registry.createReg(decrypt);

			}

			else {
				
				String reg_file = args[2];
				String monitored_path = args[4];
				String log_file = args[6];
				String hash = args[8];
				String pubKeyCertificate = args[10];

				Integrity integrity = new Integrity(reg_file, monitored_path, log_file, hash, pubKeyCertificate);
				integrity.check();
			}
			
			
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} 
	}
	
	public static String getBinary(String text) throws UnsupportedEncodingException {
		
		byte[] barr = text.getBytes("UTF-8");
		String result = "";
		for (byte b : barr){
			result += String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
		}
		result = padding(result);
		return result;
	}
	
	public static String padding(String text) {
		
		int len = text.length();
		String out;

		if (len < 128) {
			String text2 = String.format("%-128s", text).replace(' ', '*');
			char[] tempbin = text2.toCharArray();
		    int temp = 0;
		    for (int i = len; i < 128; i++){
		      if (temp % 2 == 0) tempbin[i] = '0';
		      else tempbin[i] = '1';
		      temp++;
		    }
		    out = String.valueOf(tempbin);
		}
		else out = text;
	    return out;
		
	}

}
