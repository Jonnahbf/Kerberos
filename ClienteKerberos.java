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

        //Metodo para cifrar
        public static String encrypt(String plainText) throws Exception 
        {
                Key key = generateKey(); //Invocamos al método generateKey()
                Cipher chiper = Cipher.getInstance(algorithm);
                chiper.init(Cipher.ENCRYPT_MODE, key);
                byte[] encVal = chiper.doFinal(plainText.getBytes());
                String encryptedValue = new BASE64Encoder().encode(encVal);
                return encryptedValue;
        }

        //Metodo para descifrar
        public static String decrypt(String encryptedText) throws Exception 
        {
                // generate key 
                Key key = generateKey();
                Cipher chiper = Cipher.getInstance(algorithm);
                chiper.init(Cipher.DECRYPT_MODE, key);
                byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
                byte[] decValue = chiper.doFinal(decordedValue);
                String decryptedValue = new BASE64Encoder().encode(decValue);
                return decryptedValue;
        }

        //Metodo para generar la clave secreta
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

                        //Establecemos los flujos de salida con el serverAS
                        DataOutputStream salida = new DataOutputStream(socket.getOutputStream());
                        //Establecemos los flujos de entrada con el serverAS
			DataInputStream entrada = new DataInputStream(socket.getInputStream());

                        //Definimos la peticion
			String str = "Soy el cliente 127.0.0.1 y quiero un ticket para comunicarme con el servidor 192.168.8.102";

                        //Ciframos la peticion
			String textoCifrado = ClienteKerberos.encrypt(str);

                        System.out.println("Enviando solicitud al server AS");

			salida.writeUTF(textoCifrado); //Enviamos la solicitud cifrada al server AS

			String recibido = entrada.readUTF(); //El cliente recibe lo que le envia el server AS

                        //Si el serverAS no puede descifrar la peticion
                        if(recibido.equals("Error")){
                                System.out.println("Error de autenticacion con el serverAS"); //Imprimimos un msj de error
                                socket.close(); //Terminamos la aplicacion
                        }
                        else{
                                System.out.println("Recibiendo el Ticker del server AS");
                                //Establecemos una conexion con el serverTGT
                                Socket socketTGT = new Socket(argv[0], 8000); //El cliente abre una conexión con el server TGT

                                System.out.println("Estableciendo comunicación con el server TGT");

                                //Cerramos la conexion con el serverAS
                                socket.close();

                                //Establecemos los flujos de salida para el serverTGT
                                DataOutputStream salidaTGT = new DataOutputStream(socketTGT.getOutputStream());
                                //Establecemos los flujos de entrada para el serverTGT
                                DataInputStream entradaTGT = new DataInputStream(socketTGT.getInputStream());

                                System.out.println("Enviando Ticket al servidor TGT");
                                salidaTGT.writeUTF(recibido); //Envia el ticket recibido del server AS

                                //Recibimos la respuesta del serverTGT
                                String token = entradaTGT.readUTF();

                                if(token.equals("Error")){ //Si el serverTGT no pudo descfrar el ticket
                                        System.out.println("Error de autenticacion con el serverTGT");
                                }
                                else{
                                        System.out.println("Recibiendo Token del servidor TGT");

                                        //Establecemos conexion con el servidor que nos queremos comunicar
                                        Socket socketServidor = new Socket(argv[0], 9000);
                                        System.out.println("Estableciendo comunicación con el servidor");
                                        //Cerramos conexion con el serverTGT
                                        socketTGT.close();

                                        //Establecemos los flujos de salida para el servidor
                                        DataOutputStream salidaServidor = new DataOutputStream(socketServidor.getOutputStream());
                                        //Establecemos los flujos de entrada para el servidor
                                        DataInputStream entradaServidor = new DataInputStream(socketServidor.getInputStream());


                                        //Enviamos el token al servidor
                                        salidaServidor.writeUTF(token);
                                        System.out.println("Enviando el token al servidor");

                                        //Recibimos respuesta del servidor
                                        String resultado = entradaServidor.readUTF();
                                        System.out.println("Recibiendo respuesta del servidor");

                                        //Imprimimos la respuesta enviada por el servidor
                                        System.out.println(resultado);

                                        //Cerramos conexion
                                        socketServidor.close();
                                }
                        }

		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}

	
