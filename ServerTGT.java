import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.*;
import java.util.logging.Level;
import java.util.logging.Logger;


public class ServerTGT {

private static String algorithm = "AES";
private static byte[] keyShareServidor=new byte[] 
{ 'P', 'M', 'k', 'z', 'z', 's', 'a', 'q', 'j', 'd', 'q', 'p', 'd', 'K', 'd', 'k' }; //Clave secreta compartida entre el server TGT y el Servidor

private static byte[] keyShareAS=new byte[] 
{ 'P', 'Q', 'd', 'a', 'v', 'q', 'e', 'S', 'j', 'k', 'l', 'm', 't', 'K', 'z', 'y' }; //Clave secreta compartida entre el server AS y el server TGT

 // Performs Encryption
        public static String encrypt(String plainText) throws Exception 
        {
                Key key = generateKey(0);
                Cipher chiper = Cipher.getInstance(algorithm);
                chiper.init(Cipher.ENCRYPT_MODE, key);
                byte[] encVal = chiper.doFinal(plainText.getBytes());
                String encryptedValue = new BASE64Encoder().encode(encVal);
                return encryptedValue;
        }

        // Performs decryption
        public static String decrypt(String encryptedText) throws Exception 
        {
                // generate key 
		try{
		        Key key = generateKey(1);
		        Cipher chiper = Cipher.getInstance(algorithm);
		        chiper.init(Cipher.DECRYPT_MODE, key);
		        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
		        byte[] decValue = chiper.doFinal(decordedValue);
		        String decryptedValue = new String(decValue);
		        return decryptedValue;
		}
		catch(Exception error){
			System.out.println("La clave secreta compartida no es correcta");
			return "Error";
		}
        }

//generateKey() is used to generate a secret key for AES algorithm
        private static Key generateKey(int tipo) throws Exception 
        {
		Key key;
		if(tipo==0)
                	key = new SecretKeySpec(keyShareServidor, algorithm);
		else
			key = new SecretKeySpec(keyShareAS, algorithm);
                return key;
        }

	public static void main(String argv[]) {
		ServerSocket servidor;
		Socket cliente;
		try {
			servidor = new ServerSocket(8000);
			do {
				cliente = servidor.accept();
				System.out.println("Se ha establecido una conexión con el cliente " + cliente.getRemoteSocketAddress());
				DataOutputStream salida = new DataOutputStream(cliente.getOutputStream());
				DataInputStream entrada = new DataInputStream(cliente.getInputStream());
				String recibido = entrada.readUTF();
				System.out.println("Validando Ticket");
				String desencriptado = ServerTGT.decrypt(recibido);
				if(desencriptado.equals("Error"))
					salida.writeUTF("Error en la validación del Ticket"); //Si el server no puede descifrar la peticion
				else{
					System.out.println("Ticket validado con éxito");
					String Token = "Token para el cliente 127.0.0.1";
					String tokenCifrado = ServerTGT.encrypt(Token);
					salida.writeUTF(tokenCifrado);
				}
				cliente.close();
			} while (true);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
