import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class Certificate {

	private String[] cmdarray;

	public Certificate(){
		
		cmdarray = new String[16];
		
		cmdarray[0] = "keytool";
		cmdarray[1] = "-genkeypair";
		cmdarray[2] = "-keysize";
		cmdarray[3] = "2048";
		cmdarray[4] = "-keyalg";
		cmdarray[5] = "RSA";
		cmdarray[6] = "-alias";
		cmdarray[7] = "keys";
		cmdarray[8] = "-keystore";
		cmdarray[9] = "./keys.jks";
		cmdarray[10] = "-dname";
		cmdarray[11] = "CN=Group24, OU=CS, O=Hacettepe University, L=Ankara, S=Ankara, C=TR";
		cmdarray[12] = "-storepass";
		cmdarray[13] = "huceng";
		cmdarray[14] = "-keypass";
		cmdarray[15] = "huceng";
		
	}
	
	public String[] getCmdarray() {
		return cmdarray;
	}
	
	public Key getPrivateKey(){
		
		Key privkey = null;
		try {
			
			char[] pwd = "huceng".toCharArray();
			KeyStore keystore = KeyStore.getInstance("JKS");
			keystore.load(new FileInputStream("./keys.jks"), pwd);
			privkey = keystore.getKey("keys", pwd);
			
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			System.err.println("Error occured in :");
			e.printStackTrace();
		}

		return privkey;
	}
	
	public void getSSCertificate(String path) {				// self-signed certificate 
		
		try {
			
			String[] cmdarr = new String[11];
		
			cmdarr[0] = "keytool";
			cmdarr[1] = "-export";
			cmdarr[2] = "-keystore";
			cmdarr[3] = "keys.jks";
			cmdarr[4] = "-alias";
			cmdarr[5] = "keys";
			cmdarr[6] = "-rfc";
			cmdarr[7] = "-file";
			cmdarr[8] = path;
			cmdarr[9] = "-storepass";
			cmdarr[10] = "huceng";
		
			Process process = Runtime.getRuntime().exec(cmdarr);
			
			int exitVal = process.waitFor();
			
			if (exitVal == 0) {
				System.out.println("Certificate was created.");
			}
			
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
	}

}
