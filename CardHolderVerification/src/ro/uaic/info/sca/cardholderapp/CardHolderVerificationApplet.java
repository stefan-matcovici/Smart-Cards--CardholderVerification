/**
 * 
 */
package ro.uaic.info.sca.cardholderapp;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;
import javacardx.annotations.*;
import javacardx.crypto.Cipher;

import static ro.uaic.info.sca.cardholderapp.CardHolderVerificationAppletStrings.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "ro.uaic.info.sca.cardholderapp"),
		@StringDef(name = "AppletName", value = "CardHolderVerificationApplet") },
		// Insert your strings here
		name = "CardHolderVerificationAppletStrings")
public class CardHolderVerificationApplet extends Applet {


	// code of CLA byte in the command APDU header
	final static byte Wallet_CLA = (byte) 0x80;

	// codes of INS byte in the command APDU header
	final static byte VERIFY_NONE = (byte) 0x20;
	final static byte VERIFY_PLAINTEXT = (byte) 0x21;
	final static byte VERIFY_ENCRYPTED = (byte) 0x22;
	final static byte CREDIT = (byte) 0x30;
	final static byte DEBIT = (byte) 0x40;
	final static byte GET_BALANCE = (byte) 0x50;
	final static byte CVM_LIST = (byte) 0x70;

	// maximum balance
	final static short MAX_BALANCE = 0x2710; // 10000
	// maximum transaction amount
	final static short MAX_TRANSACTION_AMOUNT = 0x3E8; // 1000
	// maximum amount of points
	final static short MAX_POINTS_AMOUNT = 0x12C;

	// maximum number of incorrect tries before the
	// PIN is blocked
	final static byte PIN_TRY_LIMIT = (byte) 0x03;
	// maximum size PIN
	final static byte MAX_PIN_SIZE = (byte) 0x08;

	// signal that the PIN verification failed
	final static short SW_VERIFICATION_FAILED = 0x6300;
	// signal the the PIN validation is required
	// for a credit or a debit transaction
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	// signal invalid transaction amount
	// amount > MAX_TRANSACTION_AMOUNT or amount < 0
	final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

	// signal that the balance exceed the maximum
	final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
	// signal the the balance becomes negative
	final static short SW_NEGATIVE_BALANCE = 0x6A85;

	final static short CVR_1 = 0x1F06; // for payments less than $10, NO
										// CVM REQUIRED // 0001 1111
										// 0000 0110
	final static short CVR_2 = 0x0108; // for payments between $10 and
										// $50, then plaintext PIN
										// verification is required //
										// 0000 0001 0000 1000
	final static short CVR_3 = 0x0409; // for payments above $50, then
										// enciphered PIN verification
										// is required // 0000 0100 0000
										// 1001

	final static int lowAmount = 0x32;
	final static int highAmount = 0x64;

	/* instance variables declaration */
	OwnerPIN pin;
	short balance;
	short pinSize;
	boolean isValidated;

	/**
	 * Installs this applet.
	 * 
	 * @param bArray
	 *            the array containing installation parameters
	 * @param bOffset
	 *            the starting offset in bArray
	 * @param bLength
	 *            the length in bytes of the parameter data in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new CardHolderVerificationApplet(bArray, bOffset, bLength);
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected CardHolderVerificationApplet(byte[] bArray, short bOffset, byte bLength) {
		// It is good programming practice to allocate
		// all the memory that an applet needs during
		// its lifetime inside the constructor
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

		byte iLen = bArray[bOffset]; // aid length
		bOffset = (short) (bOffset + iLen + 1);
		byte cLen = bArray[bOffset]; // info length
		bOffset = (short) (bOffset + cLen + 1);
		byte aLen = bArray[bOffset]; // applet data length
		
		pinSize = aLen;

		// The installation parameters contain the PIN
		// initialization value
		pin.update(bArray, (short) (bOffset + 1), aLen);
		register();
	}

	/**
	 * Processes an incoming APDU.
	 * 
	 * @see APDU
	 * @param apdu
	 *            the incoming APDU
	 */
	@Override
	public void process(APDU apdu) {
		// Insert your code here
		byte[] buffer = apdu.getBuffer();
		// check SELECT APDU command

		if (apdu.isISOInterindustryCLA()) {
			if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
				return;
			}
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		// verify the reset of commands have the
		// correct CLA byte, which specifies the
		// command structure
		if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		case CVM_LIST:
			getCVMList(apdu);
			break;
		case GET_BALANCE:
			getBalance(apdu);
			break;
		case CREDIT:
			credit(apdu);
			break;
		case VERIFY_PLAINTEXT:
			verifyPlain(apdu);
			break;
		case DEBIT:
			debit(apdu);
			break;
		case VERIFY_NONE:
			verifyNone(apdu);
			break;
		case VERIFY_ENCRYPTED:
			verifyEncrypted(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void verifyEncrypted(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// retrieve the PIN data for validation.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());
		
		try {
			byte[] exponent = {(byte)0x21, (byte)0x4A, (byte)0x50, (byte)0xAA, (byte)0xA9, (byte)0x5A, (byte)0x9E, (byte)0xC5, (byte)0xAB, (byte)0xC2, (byte)0x62, (byte)0xC0, (byte)0x4C, (byte)0x20, (byte)0x18, (byte)0xD8, (byte)0x9C, (byte)0x59, (byte)0x4F, (byte)0x63, (byte)0xB9, (byte)0x40, (byte)0x9B, (byte)0xD9, (byte)0x96, (byte)0x59, (byte)0xDA, (byte)0xAB, (byte)0x3A, (byte)0x87, (byte)0x18, (byte)0x02, (byte)0x76, (byte)0xE7, (byte)0x02, (byte)0x00, (byte)0xD6, (byte)0xF6, (byte)0x2E, (byte)0xDB, (byte)0x59, (byte)0xBA, (byte)0xF2, (byte)0x7A, (byte)0x5D, (byte)0xCF, (byte)0x0E, (byte)0x77, (byte)0x07, (byte)0xDC, (byte)0xBB, (byte)0xE9, (byte)0x68, (byte)0xBD, (byte)0xCF, (byte)0x25, (byte)0x4B, (byte)0x75, (byte)0xA6, (byte)0x26, (byte)0x2F, (byte)0x60, (byte)0xA4, (byte)0x4D};
			byte[] modulus = {(byte)0xC7, (byte)0xBD, (byte)0xE3, (byte)0xFF, (byte)0xF8, (byte)0x1F, (byte)0xB8, (byte)0xA2, (byte)0x06, (byte)0x8E, (byte)0x50, (byte)0x81, (byte)0xC8, (byte)0xC0, (byte)0x95, (byte)0x13, (byte)0xAA, (byte)0x17, (byte)0xDC, (byte)0x56, (byte)0x57, (byte)0x83, (byte)0xA7, (byte)0x19, (byte)0x86, (byte)0x1B, (byte)0x20, (byte)0x03, (byte)0x5F, (byte)0x2A, (byte)0x90, (byte)0x10, (byte)0x8F, (byte)0x2F, (byte)0x8A, (byte)0x39, (byte)0x65, (byte)0xA3, (byte)0x6C, (byte)0x80, (byte)0x58, (byte)0x85, (byte)0xE9, (byte)0xE6, (byte)0x05, (byte)0x26, (byte)0x0B, (byte)0x46, (byte)0x85, (byte)0xD4, (byte)0xD1, (byte)0x0D, (byte)0x96, (byte)0x5A, (byte)0x40, (byte)0xCC, (byte)0x90, (byte)0xF2, (byte)0x7F, (byte)0xAB, (byte)0x42, (byte)0xAD, (byte)0x82, (byte)0x25};
			 
			RSAPrivateKey priKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
			priKey.setModulus(modulus, (short)0, (short)modulus.length);
			priKey.setExponent(exponent, (short)0, (short)exponent.length);
			 
			Cipher rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			rsaCipher.init(priKey, Cipher.MODE_DECRYPT);
			 
			byte[] pinBytes = new byte[byteRead];	
			 
			rsaCipher.doFinal(buffer, (short)ISO7816.OFFSET_CDATA, byteRead, pinBytes, (short)0);
			 
			if (pin.check(pinBytes, (short)0, (byte)pinSize) == false) {
				ISOException.throwIt(SW_VERIFICATION_FAILED);
			}
			
			isValidated = true;
			 
			 
	    } catch (CryptoException c) {
	        //this line will give you the reason of problem 
	        short reason = c.getReason();

		    ISOException.throwIt(reason);       // for check

	    }
	}

	private void credit(APDU apdu) {

		byte[] buffer = apdu.getBuffer();

		// Lc byte denotes the number of bytes in the
		// data field of the command APDU
		byte numBytes = buffer[ISO7816.OFFSET_LC];

		// indicate that this APDU has incoming data
		// and receive data starting from the offset
		// ISO7816.OFFSET_CDATA following the 5 header
		// bytes.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// it is an error if the number of data bytes
		// read does not match the number in Lc byte
		if ((numBytes != 2) || (byteRead != 2)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		// get debit amount
		byte byte1 = buffer[ISO7816.OFFSET_CDATA];
		byte byte2 = buffer[ISO7816.OFFSET_CDATA + 1];
		
		short creditAmount = (short)((byte1 << 8) + byte2);

		// check the credit amount
		if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}

		// check the new balance
		if ((short) (balance + creditAmount) > MAX_BALANCE) {
			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
		}

		// credit the amount
		balance = (short) (balance + creditAmount);

	} // end of deposit method

	private void getBalance(APDU apdu) {

		byte[] buffer = apdu.getBuffer();

		// inform system that the applet has finished
		// processing the command and the system should
		// now prepare to construct a response APDU
		// which contains data field
		short le = apdu.setOutgoing();

		if (le < 2) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// informs the CAD the actual number of bytes
		// returned
		apdu.setOutgoingLength((byte) 2);

		// move the balance data into the APDU buffer
		// starting at the offset 0
		buffer[0] = (byte) (balance >> 8);
		buffer[1] = (byte) (balance & 0xFF);

		// send the 2-byte balance at the offset
		// 0 in the apdu buffer
		apdu.sendBytes((short) 0, (short) 2);

	} // end of getBalance method

	private void getCVMList(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		short le;

		le = apdu.setOutgoing();

		if (le < 2) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		apdu.setOutgoingLength((byte) 14);

		byte[] lowAmountBytes = intToBytes(lowAmount, 4);
		byte[] highAmountBytes = intToBytes(highAmount, 4);

		buffer[0] = lowAmountBytes[3];
		buffer[1] = lowAmountBytes[2];
		buffer[2] = lowAmountBytes[1];
		buffer[3] = lowAmountBytes[0];

		buffer[4] = highAmountBytes[3];
		buffer[5] = highAmountBytes[2];
		buffer[6] = highAmountBytes[1];
		buffer[7] = highAmountBytes[0];

		buffer[8] = (byte) (CVR_1 >> 8);
		buffer[9] = (byte) (CVR_1 & 0xFF);

		buffer[10] = (byte) (CVR_2 >> 8);
		buffer[11] = (byte) (CVR_2 & 0xFF);

		buffer[12] = (byte) (CVR_3 >> 8);
		buffer[13] = (byte) (CVR_3 & 0xFF);

		apdu.sendBytes((short) 0, (short) 14);

	}
	
	private void debit(APDU apdu) {
		
		if (!isValidated) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		
		byte[] buffer = apdu.getBuffer();

		byte numBytes = (buffer[ISO7816.OFFSET_LC]);

		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		if ((numBytes != 2) || (byteRead != 2)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// get debit amount
		byte byte1 = buffer[ISO7816.OFFSET_CDATA];
		byte byte2 = buffer[ISO7816.OFFSET_CDATA + 1];
		
		short debitAmount = (short)((byte1 << 8) + byte2);

		// check debit amount
		if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}

		// check the new balance
		if ((short) (balance - debitAmount) < (short) 0) {
			ISOException.throwIt(SW_NEGATIVE_BALANCE);
		}

		balance = (short) (balance - debitAmount);
		
		isValidated = false;

	} // end of debit method
	
	private void verifyNone(APDU apdu) {
		isValidated = true;
	}

	private void verifyPlain(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// retrieve the PIN data for validation.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// check pin
		// the PIN data is read into the APDU buffer
		// at the offset ISO7816.OFFSET_CDATA
		// the PIN data length = byteRead
		if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
			ISOException.throwIt(SW_VERIFICATION_FAILED);
		}
		
		isValidated = true;
	}
	
	public static byte[] intToBytes(int x, int n) {
		byte[] bytes = new byte[(byte) n];
		for (byte i = 0; i < n; i++, x >>>= 8)
			bytes[i] = (byte) (x & 0xFF);
		return bytes;
	}
}
