// servidor
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.net.InetAddress;


public class ServerAS {

private static String algorithm = "AES";
private static byte[] keyShareAS=new byte[] 
{ 'A', 'S', 'e', 'c', 'u', 'r', 'e', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' }; //Clave secreta compartida entre el server AS y el cliente

private static byte[] keyShareTGT=new byte[] 
{ 'P', 'Q', 'd', 'a', 'v', 'q', 'e', 'S', 'j', 'k', 'l', 'm', 't', 'K', 'z', 'y' }; //Clave secreta compartida entre el server AS y el server TGT



	public static void DefinirCliente(int cliente){
		if(cliente == 0){ //Si cliente vale 0 cambiamos la clave porque es otro cliente
			keyShareAS = new byte[] 
			{ 'd', 'p', 'f', 'k', 'j', 'a', 'e', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' };
		}
	}

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
		        String decryptedValue = new BASE64Encoder().encode(decValue);
		        return decryptedValue;
		}
		catch(Exception error){
			System.out.println("La clave secreta compartida no es correcta");
			return "Error";
		}
        }

	//Metodo para generar la clave secreta
        private static Key generateKey(int tipo) throws Exception{
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
			servidor = new ServerSocket(5000); //Aceptaremos conexiones en el puerto 5000
			do {
				cliente = servidor.accept(); //Esperamos conexiones de los clientes
				System.out.println("Se ha establecido una conexión con el cliente " + cliente.getRemoteSocketAddress()); //Obtenemos la ip del cliente
				
				//Establecemos los flujos de entrada y salida
				DataOutputStream salida = new DataOutputStream(cliente.getOutputStream());
				DataInputStream entrada = new DataInputStream(cliente.getInputStream());

				//Convertimos la IP a String
				String ip=(((InetSocketAddress) cliente.getRemoteSocketAddress()).getAddress()).toString().replace("/","");
				
				if(ip.equals("127.0.0.1")){ //Si el cliente tiene la ip 127.0.0.1
					ServerAS.DefinirCliente(1);
				}
				else{
					ServerAS.DefinirCliente(0);
				}

				String recibido = entrada.readUTF(); //Obtenemos la solicitud enviada por el cliente
				System.out.println("Validando autenticación del cliente");
				String desencriptado = ServerAS.decrypt(recibido); //Desciframos los datos del cliente
				System.out.println(desencriptado); //Imprimimos la peticion descifrada
				if(desencriptado.equals("Error"))
					salida.writeUTF("Error"); //Si el server no puede descifrar la peticion
				else{ //Si todo salio bien
					System.out.println("Cliente autenticado correctamente");
					String Ticket = "Ticket para el cliente 127.0.0.1";
					String ticketCifrado = ServerAS.encrypt(Ticket); //Enviamos el ticket cifrado					salida.writeUTF(ticketCifrado);
				}
				cliente.close(); //Cerramos conexion
			} while (true);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
