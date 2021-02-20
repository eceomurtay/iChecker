import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Registry {

	private String regFile;
	private String directory;
	private String logFile;
	private String hashFunc;
	private String priKey;
	
	public BufferedWriter bw_log;
	
	public Registry(String regFile, String directory, String logFile, String hashFunc, String priKey){
		
		this.regFile = regFile;
		this.directory = directory;
		this.logFile = logFile;
		this.hashFunc = hashFunc;
		this.priKey = priKey;
		
	}
	
	public void createReg(Cipher cipher) throws IOException {
		
		String reg_text = "";
		bw_log = new BufferedWriter(new FileWriter(new File(logFile), true));
		
		try {
			
			BufferedReader br = new BufferedReader(new FileReader(priKey));
			byte[] decoded = Base64.getDecoder().decode(br.readLine());
			br.close();
			
			String dec_text = new String(cipher.doFinal(decoded), "UTF-8");
			if (dec_text.contains("This is the private key file")){
				System.out.println("Password is correct.");
			}
			
			String decoded_prikey_wom = dec_text.replace("This is the private key file", "");
				
			BufferedWriter bw_reg = new BufferedWriter(new FileWriter(new File(regFile)));
			bw_log.write(getTimestamp() + "Registry file is created at " + regFile + "!");
			bw_log.newLine();
			
			File[] dir = new File(directory).listFiles();

			for (File f : dir){

				String content = new String(Files.readAllBytes(f.toPath()));
				String hashed = hashing(content, hashFunc);
				
				reg_text += (f.getPath() + " " + hashed);
				bw_reg.write(f.getPath() + " " + hashed);
				bw_reg.newLine();
				reg_text += "\n";
				
				bw_log.write(getTimestamp() + f.getPath() + " is added to registry.");
				bw_log.newLine();
			}

			bw_log.write(getTimestamp() + dir.length + " files are added to the registry and registry creation is finished!");
			bw_log.newLine();
			
			bw_reg.write(getSignature(reg_text, hashFunc, decoded_prikey_wom)); 		// signature creation
			
			bw_reg.close();
			
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) { 
			try {

				System.out.println("Wrong password attempt!");
				bw_log.write(getTimestamp() + "Wrong password attempt!");
				bw_log.newLine();
				// program terminated
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}

		try {
			bw_log.close();	
		} catch (IOException e) {
			e.printStackTrace();
		} 									
		
		
	}
	
	public String hashing(String text, String hashFunc){
		
		String result = null;
		if (hashFunc.equals("MD5")){
			try {
				MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(text.getBytes());
				byte[] msgdigest = md.digest();
				result = new String(Base64.getEncoder().encodeToString(msgdigest));
				
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
		else {
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(text.getBytes());
				byte[] msgdigest = md.digest();
				result = new String(Base64.getEncoder().encodeToString(msgdigest));
				
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
		return result;
	}
	
	public String getTimestamp(){
		return new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date()) + ": ";
	}
	
	public String getSignature(String reg_text, String hashFunc, String priv_key) {

		String signature = "";

		String hashed_reg = hashing(reg_text, hashFunc);
		
		try {
			
			String algorithm = "";
			if (hashFunc.equals("SHA-256")) algorithm = "SHA256withRSA";
			else algorithm = hashFunc + "withRSA";
			
			Signature sign = Signature.getInstance(algorithm);
			sign.initSign(getPrivateKey(priv_key));
			
			byte[] hashed_reg_byte = hashed_reg.getBytes();
			
			sign.update(hashed_reg_byte);
			
			byte [] signature_byte = sign.sign();
			signature = new String(Base64.getEncoder().encodeToString(signature_byte));

		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			e.printStackTrace();
		}
		
		return signature;
	}

	public PrivateKey getPrivateKey(String base64PrivateKey){
		
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
	}
	
}
