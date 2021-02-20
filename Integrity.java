import java.io.*;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

public class Integrity {

	private String regFile;
	private String path;
	private String logFile;
	private String hashFunc;
	private String pubKeyCert;
	
	public Integrity (String regFile, String path, String logFile, String hashFunc, String pubKeyCert){
		
		this.regFile = regFile;
		this.path = path;
		this.logFile = logFile;
		this.hashFunc = hashFunc;
		this.pubKeyCert = pubKeyCert;
		
	}
	
	public void check(){
		
		// check the registry file first
		try {
			
			BufferedReader br = new BufferedReader(new FileReader(regFile));
			BufferedWriter bw_log = new BufferedWriter(new FileWriter(new File(logFile), true));
			
			String line;
			String previous = null;
			String content = "";
			ArrayList<String> reg_file_content = new ArrayList<>();
			
			while ((line = br.readLine()) != null){

				if(previous != null){

					content += (previous + "\n");
					reg_file_content.add(previous);
				}
				
				previous = line;
			}
			
			String hashed = hashing(content, hashFunc);

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(new FileInputStream(pubKeyCert));
			PublicKey publicKey = certificate.getPublicKey();
			
			byte[] sign = Base64.getDecoder().decode(previous); 			// signature extracted from registry file
	        
			String algorithm = "";
			if (hashFunc.equals("SHA-256")) algorithm = "SHA256withRSA";
			else algorithm = hashFunc + "withRSA";
			
			Signature signature = Signature.getInstance(algorithm);
			
			// initializing the signature
			signature.initVerify(publicKey);
			signature.update(hashed.getBytes());
		    
		    // verifying the signature
		    boolean bool = signature.verify(sign);
		    
		    System.out.println("Signature verification is : " + (bool == true ? "successful" : "failed"));
		    
		    if (bool == false){ 
		    	
		    	bw_log.write(getTimestamp() + "Registry file verification failed!");
		    	bw_log.newLine();
		    	System.exit(0);				// terminate the program
		    }

		    else {
		    	
		    	boolean change = false;
		    	String created = "";
		    	String deleted = "";
		    	String altered = "";
		    	File[] dir = new File(path).listFiles();		// path of monitored file
		    	
		    	// create
		    	for (File f : dir){		
		    		boolean contain = false;

		    		for (String p : reg_file_content){

		    			if (p.contains(f.getPath())) {
		    				contain = true;
		    			}
		    		}
		    		if (!contain){

		    			change = true;
		    			created = f.getPath();
		    			bw_log.write(getTimestamp() + created + " is created");
			    		bw_log.newLine();
		    		}
		    	}

			    // altered
		    	for (String p : reg_file_content){
		    		for (File f : dir){
			    		if (p.split(" ")[0].equals(f.getPath())){

			    			String check_hash = hashing(new String(Files.readAllBytes(f.toPath())), hashFunc);

							if (!p.split(" ")[1].equals(check_hash)){

								change = true;
			    				altered = f.toPath().toString();
			    				bw_log.write(getTimestamp() + altered + " is altered");
			    				bw_log.newLine();
							}
			    		}
		    		}
		    	}

		    	// delete
		    	for (String p : reg_file_content){

		    		File file = new File(p.split(" ")[0]);

		    		if (!file.exists()){

		    			deleted = p.split(" ")[0];
			    		bw_log.write(getTimestamp() + deleted + " is deleted");
			    		bw_log.newLine();
		    		}
		    	}
		    	
		    	
		    	if (!change){
			    	bw_log.write(getTimestamp() + "The directory is checked and no change is detected!");
			    	bw_log.newLine();
		    	}
		    }
			
			br.close();
			bw_log.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
		
	}
	
	public String getTimestamp(){
		return new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date()) + ": ";
	}
	
	public String hashing(String text, String hash_func){
		
		String result = null;
		if (hash_func.equals("MD5")){

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
	
	
}
