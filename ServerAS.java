// servidor
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.*;
import java.util.logging.Level;
import java.util.logging.Logger;


public class ServerAS {

private static String algorithm = "AES";
private static byte[] keyShareAS=new byte[] 
{ 'A', 'S', 'e', 'c', 'u', 'r', 'e', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' }; //Clave secreta compartida entre el server AS y el cliente

private static byte[] keyShareTGT=new byte[] 
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
		if(tipo==1)
                	key = new SecretKeySpec(keyShareAS, algorithm);
		else
			key = new SecretKeySpec(keyShareTGT, algorithm);
                return key;
        }



	public static void main(String argv[]) {
		ServerSocket servidor;
		Socket cliente;
		try {
			servidor = new ServerSocket(5000);
			do {
				cliente = servidor.accept();
				System.out.println("Se ha establecido una conexión con el cliente " + cliente.getRemoteSocketAddress());
				DataOutputStream salida = new DataOutputStream(cliente.getOutputStream());
				DataInputStream entrada = new DataInputStream(cliente.getInputStream());
				String recibido = entrada.readUTF();
				System.out.println("Validando autenticación del cliente");
				String desencriptado = ServerAS.decrypt(recibido);
				System.out.println(desencriptado);
				if(desencriptado.equals("Error"))
					salida.writeUTF("Error de autenticacion"); //Si el server no puede descifrar la peticion
				else{
					System.out.println("Cliente autenticado correctamente");
					String Ticket = "Ticket para el cliente 127.0.0.1";
					String ticketCifrado = ServerAS.encrypt(Ticket);
					salida.writeUTF(ticketCifrado);
				}
				cliente.close();
			} while (true);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
