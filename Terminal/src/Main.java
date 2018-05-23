import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadClientInterface;
import com.sun.javacard.apduio.CadDevice;
import com.sun.javacard.apduio.CadTransportException;

import javax.crypto.Cipher;

public class Main {
    private static final String PUBLIC_KEY_FILENAME = "public.txt";

    public static String installPath = "E:\\eclipse-workspace\\CardHolderVerification\\apdu_scripts\\cap-ro.uaic.info.sca.cardholderapp.script";
    public static String initPath = "E:\\eclipse-workspace\\CardHolderVerification\\apdu_scripts\\init.script";
    private static int lowerLimit;
    private static int upperLimit;

    public static List<Short> CVMs = new ArrayList<>();
    public static byte[] TERMINAL_CVM_LIST = {0x1F, 0x01, 0x04};


    public static void runScripts(CadClientInterface cad, String filePath) {
        try (Stream<String> stream = Files.lines(Paths.get(filePath))) {
            stream
                    .filter(s -> {
                        if (s.isEmpty())
                            return false;
                        if (Character.isLetter(s.charAt(0)))
                            return false;
                        return !s.startsWith("/");
                    })
                    .map(line -> Arrays.stream(line.replace(";", "").split(" ")).map(x -> {
                        char first = x.charAt(2);
                        char second = x.charAt(3);

                        return (byte) (((Integer.parseInt(String.valueOf(first), 16)) * 16) + Integer.parseInt(String.valueOf(second), 16));
                    })
                            .collect(Collectors.toList()))
                    .forEach(bytes -> {
                        Apdu apdu = new Apdu();
                        apdu.command = new byte[]{bytes.get(0), bytes.get(1), bytes.get(2), bytes.get(3)};
                        byte[] data = new byte[bytes.size() - 6];
                        for (int i = 5; i < bytes.size() - 1; i++) {
                            data[i - 5] = bytes.get(i);
                        }
                        apdu.setDataIn(data, bytes.get(4));
                        apdu.setLe(bytes.get(bytes.size() - 1));
//                        System.out.println("raw: " +bytes);
                        System.out.println("command: " + apdu);

                        try {
                            cad.exchangeApdu(apdu);
                        } catch (IOException | CadTransportException e) {
                            e.printStackTrace();
                        }

                        System.out.println("response: " + apdu);
                    });
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] params) {
        try {
            CadClientInterface cad;
            Socket sock;

            sock = new Socket("localhost", 9025);
            InputStream is = sock.getInputStream();
            OutputStream os = sock.getOutputStream();

            cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);
            System.out.println("Before power up");
            byte[] atr = cad.powerUp();
            for (int i = 0; i < atr.length; i++) {
                System.out.println(atr[i]);
            }

            System.out.println("After power up");

            runScripts(cad, installPath);
            System.out.println("init");
            runScripts(cad, initPath);
            System.out.println("cvm list");
            getCVMList(cad);

            label_1:
            while (true) {
                try {
                    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

                    System.out.println("Insert method (balance/credit/debit/hardcoded/close): ");
                    String method = br.readLine().toLowerCase();

                    switch (method) {
                        case "balance":
                            getBalance(cad);
                            break;

                        case "credit":
                            credit(cad, getAmount(br));
                            break;

                        case "debit":
                            debit(br, cad, getAmount(br));
                            break;

                        case "hardcoded":
                            credit(cad, (short) 300);
                            getBalance(cad);
                            debit(br, cad, (short) 25);
                            getBalance(cad);
                            debit(br, cad, (short) 60);
                            getBalance(cad);
                            debit(br, cad, (short) 60);
                            getBalance(cad);
                            debit(br, cad, (short) 120);
                            getBalance(cad);
                            debit(br, cad, (short) 120);
                            getBalance(cad);
                            break;

                        case "close":
                            cad.powerDown();
                            sock.close();

                            break label_1;

                        default:
                            System.out.println("Invalid command: " + method);
                            continue;
                    }


                } catch (IOException | IllegalArgumentException e) {
                    System.out.println(e.getMessage());
                }

            }

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


    }

    private static void credit(CadClientInterface cad, short amount) throws IOException {

        byte firstByte = (byte) (amount & 0xff);
        byte secondByte = (byte) ((amount >>> 8) & 0xff);

        Apdu apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, 0x30, 0x00, 0x00};
        apdu.setDataIn(new byte[]{secondByte, firstByte}, 0x02);
        apdu.setLe(0x7f);

        System.out.println("command: " + apdu);
        try {
            cad.exchangeApdu(apdu);
        } catch (IOException | CadTransportException e) {
            e.printStackTrace();
        }

        System.out.println("response: " + apdu);
    }

    private static void debit(BufferedReader br, CadClientInterface cad, short amount) throws IOException, GeneralSecurityException {

        byte firstByte = (byte) (amount & 0xff);
        byte secondByte = (byte) ((amount >>> 8) & 0xff);

        byte currentCase;
        if (amount < lowerLimit) {
            currentCase = 0x06;
        } else if (amount < upperLimit) {
            currentCase = 0x08;
        } else {
            currentCase = 0x09;
        }

        byte CVMCode = 0x00;
        for (short CVR : CVMs) {
            if ((CVR & 0xFF) == currentCase) { // the current element in list
                CVMCode = (byte) (CVR >> 8);
            }
        }

        String PIN;
        switch (CVMCode) {
            case 0x1F: // no CVM required
                verifyNone(cad);
                break;
            case 0x01:
                PIN = promptForPin(br);
                verifyPlaintextPIN(PIN, cad);
                break;
            case 0x04:
                PIN = promptForPin(br);
                verifyEncryptedPIN(PIN, cad);
                break;
            default:
                System.out.println("Unrecognized CVM code: " + CVMCode);
        }

        Apdu apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, 0x40, 0x00, 0x00};
        apdu.setDataIn(new byte[]{secondByte, firstByte}, 2);
        apdu.setLe(0x7f);

        System.out.println("command: " + apdu);
        try {
            cad.exchangeApdu(apdu);
        } catch (IOException | CadTransportException e) {
            e.printStackTrace();
        }

        System.out.println("response: " + apdu);
    }

    private static short getAmount(BufferedReader br) throws IOException {
        System.out.println("Insert amount: ");
        short amount = 0;
        try {
            amount = Short.parseShort(br.readLine());
        } catch (NumberFormatException e) {
            throw new IOException("Amount is invalid");
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(amount);
        return amount;
    }

    private static void verifyNone(CadClientInterface cad) {
        Apdu apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, 0x20, 0x00, 0x00};
        apdu.setDataIn(null, 0);
        apdu.setLe(0x7f);

        System.out.println("command: " + apdu);
        try {
            cad.exchangeApdu(apdu);
        } catch (IOException | CadTransportException e) {
            e.printStackTrace();
        }

        System.out.println("response: " + apdu);
    }

    private static String promptForPin(BufferedReader br) throws IOException {
        System.out.println("Transaction requires pin: ");
        String PIN = br.readLine();

        boolean valid = true;
        for (int i = 0; i < PIN.length(); ++i) {
            if (PIN.charAt(i) < '0' || PIN.charAt(i) > '9') {
                System.out.println("Invalid PIN: " + PIN);
                valid = false;
                break;
            }
        }

        return PIN;
    }

    private static void verifyPlaintextPIN(String pin, CadClientInterface cad) {
        byte[] PINBytes = new byte[pin.length()];
        for (int i = 0; i < pin.length(); ++i) {
            PINBytes[i] = (byte) (pin.charAt(i) - '0');
        }

        Apdu apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, 0x21, 0x00, 0x00};
        apdu.setDataIn(PINBytes, PINBytes.length);
        apdu.setLe(0x7f);

        System.out.println("command: " + apdu);
        try {
            cad.exchangeApdu(apdu);
        } catch (IOException | CadTransportException e) {
            e.printStackTrace();
        }

        System.out.println("response: " + apdu);
    }

    private static void verifyEncryptedPIN(String pin, CadClientInterface cad) throws GeneralSecurityException, IOException {
        Cipher cipher;
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        BufferedReader br = new BufferedReader(new FileReader(PUBLIC_KEY_FILENAME));
        String encodedPublicKey = br.readLine();
        RSAPublicKey publicKey = (RSAPublicKey) loadPublicKey(encodedPublicKey);

        // Hardcode the RSA key
        String modulusString = "C7BDE3FFF81FB8A2068E5081C8C09513AA17DC565783A719861B20035F2A90108F2F8A3965A36C805885E9E605260B4685D4D10D965A40CC90F27FAB42AD8225";
        String publicExponentString = "3";

        // Load the key into BigIntegers
        BigInteger modulus = new BigInteger(modulusString, 16);
        BigInteger pubExponent = new BigInteger(publicExponentString);
        RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubExponent);

        // Create a key factory
        KeyFactory factory = KeyFactory.getInstance("RSA");

        // Create the RSA private and public keys
        PublicKey pub = factory.generatePublic(publicSpec);

        cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);

        byte[] PINBytes = new byte[pin.length()];
        for (int i = 0; i < pin.length(); ++i) {
            PINBytes[i] = (byte) (pin.charAt(i) - '0');
        }

        byte[] encrypted = cipher.doFinal(PINBytes);

        Apdu apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, 0x22, 0x00, 0x00};
        apdu.setDataIn(encrypted, encrypted.length);
        apdu.setLe(0x7f);

        System.out.println("command: " + apdu);
        try {
            cad.exchangeApdu(apdu);
        } catch (IOException | CadTransportException e) {
            e.printStackTrace();
        }

        System.out.println("response: " + apdu);

    }

    private static void getBalance(CadClientInterface cad) {
        Apdu apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, 0x50, 0x00, 0x00};
        apdu.setDataIn(null, 0);
        apdu.setLe(0x02);

        System.out.println("command: " + apdu);
        try {
            cad.exchangeApdu(apdu);
        } catch (IOException | CadTransportException e) {
            e.printStackTrace();
        }

        System.out.println("response: " + apdu);

    }

    private static void getCVMList(CadClientInterface cad) throws Exception {
        Apdu apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, 0x70, 0x00, 0x00};
        apdu.setDataIn(null, 0);
        apdu.setLe(0x7f);

        System.out.println("command: " + apdu);
        try {
            cad.exchangeApdu(apdu);
        } catch (IOException | CadTransportException e) {
            e.printStackTrace();
        }

        System.out.println("response: " + apdu);

        byte[] response = apdu.getDataOut();

        byte[] lowerLimitBytes = Arrays.copyOfRange(response, 0, 4);
        lowerLimit = bytesToInt(lowerLimitBytes);

        byte[] upperLimitBytes = Arrays.copyOfRange(response, 4, 8);
        upperLimit = bytesToInt(upperLimitBytes);

        for (int i = 8; i < response.length; i += 2) {
            short newCVR = (short) (response[i] << 8 | response[i + 1] & 0xFF);
            CVMs.add(newCVR);
        }


        for (Short cvm : CVMs) {
            boolean ok = false;
            for (byte terminalCVMRule : TERMINAL_CVM_LIST) {
                if ((byte)((cvm >> 8) & 0xff) == terminalCVMRule) {
                    ok = true;
                }
            }

            if (!ok) {
                throw new Exception("Rule not supported " + cvm);
            }
        }
    }

    public static int bytesToInt(byte[] x) {
        return (x[0] << 24) & 0xff000000 |
                (x[1] << 16) & 0x00ff0000 |
                (x[2] << 8) & 0x0000ff00 |
                (x[3] << 0) & 0x000000ff;
    }

    private static PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(stored);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }

}
