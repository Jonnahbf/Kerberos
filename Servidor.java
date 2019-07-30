import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.*;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Servidor{

private static String algorithm = "AES";
private static byte[] keyShareServidor=new byte[] 
{ 'P', 'M', 'k', 'z', 'z', 's', 'a', 'q', 'j', 'd', 'q', 'p', 'd', 'K', 'd', 'k' }; //Clave secreta compartida entre el server TGT y el Servidor

		//Metodo para cifrar
        public static String encrypt(String plainText) throws Exception {
                Key key = generateKey();
                Cipher chiper = Cipher.getInstance(algorithm);
                chiper.init(Cipher.ENCRYPT_MODE, key);
                byte[] encVal = chiper.doFinal(plainText.getBytes());
                String encryptedValue = new BASE64Encoder().encode(encVal);
                return encryptedValue;
        }

       //Metodo para descifrar
        public static String decrypt(String encryptedText) throws Exception {
		    try{
		        Key key = generateKey();
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
        private static Key generateKey() throws Exception  {
            Key key = new SecretKeySpec(keyShareServidor, algorithm);
            return key;
        }



	public static void main(String argv[]) {
		ServerSocket servidor;
		Socket cliente;
		try {
			servidor = new ServerSocket(9000); //Esperaremos conexiones en el puerto 9000
			do {
				cliente = servidor.accept(); //Esperando conexiones de los clientes

				//Imprimimos la IP del cliente conectado
				System.out.println("Se ha establecido una conexión con el cliente " + cliente.getRemoteSocketAddress());

				//Establecemos los flujos de salida
				DataOutputStream salida = new DataOutputStream(cliente.getOutputStream());
				//Establecemos los flujos de salida
				DataInputStream entrada = new DataInputStream(cliente.getInputStream());

				//Recibimos el token enviado por el cliente
				String recibido = entrada.readUTF();
				System.out.println("Validando autenticación del cliente");

				//Desciframos el token
				String desencriptado = Servidor.decrypt(recibido);
				System.out.println(desencriptado);

				if(desencriptado.equals("Error")){ //Si ocurrio un error al descifrar el token
					salida.writeUTF("Error de autenticacion"); //Enviamos msj de error
					
				}
				else{
					System.out.println("La validacion del cliente ha sido exitosa");
					salida.writeUTF("Autenticación realizada con éxito"); //Enviamos msj de exito
				}
				cliente.close(); //Cerramos la conexion
			} while (true);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
