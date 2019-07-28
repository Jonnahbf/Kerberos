// cliente:
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.*;
import java.util.logging.Level;
import java.util.logging.Logger;
 

public class ClienteKerberos {

private static String algorithm = "AES";
private static byte[] keyShareAS=new byte[] 
{ 'A', 'S', 'e', 'c', 'u', 'r', 'e', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' }; //Clave compartida con el server AS

 // Performs Encryption
        public static String encrypt(String plainText) throws Exception 
        {
                Key key = generateKey(); //Invocamos al método generateKey()
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
                Key key = generateKey();
                Cipher chiper = Cipher.getInstance(algorithm);
                chiper.init(Cipher.DECRYPT_MODE, key);
                byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
                byte[] decValue = chiper.doFinal(decordedValue);
                String decryptedValue = new String(decValue);
                return decryptedValue;
        }

//generateKey() genera una clave secreta para el algoritmo AES
        private static Key generateKey() throws Exception 
        {
                Key key = new SecretKeySpec(keyShareAS, algorithm);
                return key;
        }


	public static void main(String argv[]) {
		InetAddress direccion;
		Socket socket;
		try {
			socket = new Socket(argv[0], 5000); //Se abre una conexión con el server AS

                        System.out.println("Estableciendo comunicación con el server AS");

                        DataOutputStream salida = new DataOutputStream(socket.getOutputStream());
			DataInputStream entrada = new DataInputStream(socket.getInputStream());

			String str = "Soy el cliente 127.0.0.1 y quiero un ticket para comunicarme con el servidor 192.168.8.102";
			String textoCifrado = ClienteKerberos.encrypt(str);

                        System.out.println("Enviando solicitud al server AS");

			salida.writeUTF(textoCifrado); //Enviamos la solicitud cifrada al server AS

			String recibido = entrada.readUTF(); //El cliente recibe lo que le envia el server AS
                        System.out.println("Recibiendo el Ticker del server AS");
			
			Socket socketTGT = new Socket(argv[0], 8000); //El cliente abre una conexión con el server TGT

                        System.out.println("Estableciendo comunicación con el server TGT");

                        DataOutputStream salidaTGT = new DataOutputStream(socketTGT.getOutputStream());
			DataInputStream entradaTGT = new DataInputStream(socketTGT.getInputStream());

                        System.out.println("Enviando Ticket al servidor TGT");
			salidaTGT.writeUTF(recibido); //Envia el ticket recibido del server AS

                        String token = entradaTGT.readUTF();
                        System.out.println("Recibiendo Token del servidor TGT");

                        Socket socketServidor = new Socket(argv[0], 9000);
                        System.out.println("Estableciendo comunicación con el servidor");

                        DataOutputStream salidaServidor = new DataOutputStream(socketServidor.getOutputStream());
			DataInputStream entradaServidor = new DataInputStream(socketServidor.getInputStream());

			salidaServidor.writeUTF(token);
                        System.out.println("Enviando el token al servidor");

                        String resultado = entradaServidor.readUTF();
                        System.out.println("Recibiendo respuesta del servidor");
                        System.out.println(resultado);

			socket.close();
                        socketServidor.close();
                        socketTGT.close();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}

	
