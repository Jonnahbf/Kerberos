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

	//Metodo para cifrar
        public static String encrypt(String plainText) throws Exception {
                Key key = generateKey(0);
                Cipher chiper = Cipher.getInstance(algorithm);
                chiper.init(Cipher.ENCRYPT_MODE, key);
                byte[] encVal = chiper.doFinal(plainText.getBytes());
                String encryptedValue = new BASE64Encoder().encode(encVal);
                return encryptedValue;
        }

        //Metodo para descifrar
        public static String decrypt(String encryptedText) throws Exception {
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

	//Metodo para generar la clave secreta
        private static Key generateKey(int tipo) throws Exception {
		Key key;
		if(tipo==0) //Sie l tipo es 0 se usara la clave keyShareServidor
                	key = new SecretKeySpec(keyShareServidor, algorithm);
		else		//Sie l tipo es 1 se usara la clave keyShareAS
			key = new SecretKeySpec(keyShareAS, algorithm);
                return key;
        }

	public static void main(String argv[]) {
		ServerSocket servidor;
		Socket cliente;
		try {
			servidor = new ServerSocket(8000); //Aceptaremos conexions en el puerto 8000
			do {
				cliente = servidor.accept(); //Esperando conexiones de los clientes
				System.out.println("Se ha establecido una conexión con el cliente " + cliente.getRemoteSocketAddress());
				
				//Estalecemos los flujos de entrada y salida
				DataOutputStream salida = new DataOutputStream(cliente.getOutputStream());
				DataInputStream entrada = new DataInputStream(cliente.getInputStream());

				//Recibimos el ticket enviado por el cliente
				String recibido = entrada.readUTF();
				System.out.println("Validando Ticket");

				//Desciframos el ticket
				String desencriptado = ServerTGT.decrypt(recibido);

				if(desencriptado.equals("Error")) //Si ocurre error al descifrar
					salida.writeUTF("Error"); //Mandamos msj de error
				else{	//Si no
					System.out.println("Ticket validado con éxito");
					String Token = "Token para el cliente 127.0.0.1";
					String tokenCifrado = ServerTGT.encrypt(Token);
					salida.writeUTF(tokenCifrado); //Mandamos el token cifrado
				}
				cliente.close(); //Cerramos conexion
			} while (true);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
