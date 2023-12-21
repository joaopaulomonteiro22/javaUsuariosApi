package br.com.cotiinformatica.helpers;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA1CryptoHelper {

	/*
	 * Método para criptografar um valor usando o algoritmo SHA1
	 */
	public static String encrypt(String value) {

		try {
			// Obtém a instância do algoritmo SHA-1
			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

			// Converte a string para um array de bytes
			byte[] byteArray = value.getBytes();

			// Atualiza a mensagem no algoritmo com os bytes da string
			sha1.update(byteArray);

			// Gera a hash SHA-1
			byte[] digest = sha1.digest();

			// Converte a hash para uma representação hexadecimal
			StringBuilder hexString = new StringBuilder();
			for (byte b : digest) {
				hexString.append(String.format("%02x", b));
			}

			return hexString.toString();

		} catch (NoSuchAlgorithmException e) {
			// Tratar exceção caso o algoritmo não seja suportado
			e.printStackTrace();
			return null;
		}
	}
}
