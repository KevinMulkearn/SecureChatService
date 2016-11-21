package clientchatform;

/**
 * Imports necessary for application execution
 */
import static java.awt.Component.LEFT_ALIGNMENT;
import static java.awt.Component.RIGHT_ALIGNMENT;
import static clientchatform.ClientChatForm.conn;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FileUtils;
import org.apache.commons.codec.binary.Base64;

/**
 * Imports necessary for application GUI
 */
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import static javax.swing.JFrame.EXIT_ON_CLOSE;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/**
 * Application to conduct secure transfer of information between 2 entities The
 * Chat Application GUI Activity
 *
 * @author Andrew Nelson 11131977
 * @author David Hayes 11127511
 * @author Kevin Mulkearn 11124725
 *
 * @since : 8-2-'16
 *
 * @version : 1.2
 */
public class ClientChatForm extends JFrame implements ActionListener {

    // Declaration of member variables
    static Socket conn;
    static ServerSocket server;
    static Random rnd = new Random();
    private static String contactIP = "127.0.0.1"; // localhost
    private static boolean isNextFile = false;
    private static boolean isNextKeyGen = false;
    private static boolean isGenKey = false;
    private static int encryptType = 0;
    private static int decryptType = 0;
    private static int keyGenStage = 0;
    private static int fileSize = 0;
    private static long myNonce = 0;
    private static long theirNonce = 0;
    private static long fullNonce = 0;
    private static String fileName = null;

    // DEFINED STRINGS
    final static String TEXTPRE = "$TextSta$";
    final static String TEXTPOS = "$TextEnd$";
    final static String PUBKEYPRE = "$RSAPubK$";
    final static String PUBKEYPOS = "$RSAKEnd$";
    final static String DHKEYPRE = "$DHKeySt$";
    final static String DHKEYPOS = "$DHKeyEn$";
    final static String AESPRE = "$AESKSta$";
    final static String AESPOS = "$AESKEnd$";
    final static String FILEPRE = "$FILETra$";
    final static String FILEPOS = "$FILETrE$";
    final private static String fileLocation = "C:\\Users\\AndyN\\Pictures";
    final private static String fileOutLocation = "C:\\Users\\AndyN\\Downloads\\";
    final private static String userID = "Server"; // other userID
    final private static String[] encTypes = {"No Encryption Applied", "RSA Encryption Applied", "Session Key Encryption Applied", "DigSign"};
    final private static String[] decTypes = {"No Decryption Applied", "RSA Decryption Applied", "Session Key Decryption Applied", "DigSign"};

    // DEFINED INTEGERS
    final static int PORT_NO = 50001;
    final static int SENT = 76;
    final static int RECEIVED = 87;
    final static int MSG_ERR = 345;
    final static int NOTIFIC = 456;
    final static int RSA_KEY_SIZE = 1024;
    final static int AES_KEY_SIZE = 128;
    final static int TXT_MSG = 2040;
    final static int RSA_PUB_KEY = 2141;
    final static int DH_KEY = 2343;
    final static int IMG_FIL = 2545;
    final static int AES_KEY = 2747;
    final static int ID_SIZE = 9;

    // Two 512 bit prime/pseudoprimes & private Key
    final static private BigInteger PRIME_P = new BigInteger("22837294458471714553998748415353263434210234926264171553788191230824512654187858377117799323113858489930634523730787629833216548848684392696261906041111899");
    final static private BigInteger PRIME_Q = new BigInteger("11983610456886663666927752977985787235321702116074322498190680353757443240103757420849209419364910055387034931807318397297508757944522736309273423325368559");
    final static BigInteger PRIV_KEY = BigInteger.probablePrime(256, rnd);

    // Declare RSA/AES Key variables
    static KeyPairGenerator kpg;
    static Key publicKey;
    static Key privateKey;
    static Key otherPublicKey;
    static BigInteger clientDHKey;
    static BigInteger serverDHKey;
    static SecretKey sharedDHKey;
    static SecretKey sharedKey;
    static byte[] iv = new byte[16];
    static SecureRandom secRand = new SecureRandom();
    static IvParameterSpec ivParameterSpec;

    // Declaration of GUI variables
    static JFrame chatFrame;
    static JPanel chatPanel;
    static JPanel infoBar;
    static JLabel encTypeLabel;
    static JTextField newMsg;
    static JTextArea messageDisplay;
    static JButton sendButton;
    static JButton settingsButton;
    static JButton keyGenButton;
    static JButton browseButton;

    /**
     * Default Constructor for Client Chat Form
     *
     * @throws UnknownHostException
     * @throws IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public ClientChatForm() throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // Initialisation of Member Variable
        chatFrame = new JFrame();
        chatPanel = new JPanel();
        newMsg = new JTextField();
        messageDisplay = new JTextArea();
        sendButton = new JButton("Send");
        infoBar = new JPanel();
        encTypeLabel = new JLabel("No Encryption Applied");
        settingsButton = new JButton("Settings");
        keyGenButton = new JButton("Gen Session Key");
        browseButton = new JButton("Browse");

        // Initialisation of GUI variables
        chatFrame.setSize(500, 500);
        chatFrame.setVisible(true);
        chatFrame.setDefaultCloseOperation(EXIT_ON_CLOSE);
        chatPanel.setLayout(null);
        chatFrame.add(chatPanel);
        infoBar.setBounds(20, 10, 450, 40);
        encTypeLabel.setBounds(20, 0, 200, 20);
        encTypeLabel.setAlignmentX(LEFT_ALIGNMENT);
        settingsButton.setBounds(300, 0, 50, 20);
        settingsButton.setAlignmentX(RIGHT_ALIGNMENT);
        keyGenButton.setBounds(350, 0, 100, 20);
        keyGenButton.setAlignmentX(RIGHT_ALIGNMENT);
        infoBar.add(encTypeLabel);
        infoBar.add(settingsButton);
        infoBar.add(keyGenButton);
        chatPanel.add(infoBar);
        messageDisplay.setBounds(20, 60, 450, 320);
        chatPanel.add(messageDisplay);
        newMsg.setBounds(20, 400, 340, 30);
        chatPanel.add(newMsg);
        sendButton.setBounds(375, 390, 95, 30);
        chatPanel.add(sendButton);
        browseButton.setBounds(375, 425, 95, 30);
        chatPanel.add(browseButton);
        chatFrame.setTitle("Chat Client");
        /**
         * ###############* END GUI PAINT *################
         */

        /**
         * ###############* ACTIONLISTENERS *################
         */
        sendButton.addActionListener((ActionEvent e) -> {
            String message = newMsg.getText();
            if ((e.getSource() == sendButton) && (!"".equals(message))) {
                try {
                    sendMessage(message, TXT_MSG);
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(ClientChatForm.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        newMsg.addActionListener((ActionEvent e) -> {
            String message = newMsg.getText();
            if ((!"".equals(message))) {
                try {
                    sendMessage(message, TXT_MSG);
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(ClientChatForm.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        settingsButton.addActionListener((ActionEvent e) -> {
            SettingsClass sett;
            try {
                sett = new SettingsClass();
                sett.isVisible();
            } catch (UnknownHostException ex) {
                Logger.getLogger(ClientChatForm.class.getName()).log(Level.SEVERE, null, ex);
            }
        });

        keyGenButton.addActionListener((ActionEvent e) -> {
            String passPhrase = JOptionPane.showInputDialog(null, "Please Enter a password/phrase 8 chars or shorter.");
            try {
                mutualGenKey(passPhrase);
            } catch (UnsupportedEncodingException | NoSuchAlgorithmException ex) {
                Logger.getLogger(ClientChatForm.class.getName()).log(Level.SEVERE, null, ex);
            }
            isNextKeyGen = true;
        });

        browseButton.addActionListener((ActionEvent e) -> {
            JFileChooser fc = new JFileChooser(fileLocation);
            fc.showOpenDialog(null);
            File myFile = fc.getSelectedFile();
            try {
                String fileNameSize = myFile.getName() + "::" + myFile.length();
                sendMessage(fileNameSize, IMG_FIL);
                displayMessage(myFile.getName(), SENT);
                sendFile(myFile);
            } catch (Exception e1) {
                displayMessage(e1.toString(), NOTIFIC);
            }
        });

        connect();

        while (true) {
            pollForData();
        }
    }

    /**
     * Main method of Class ClientChatForm
     *
     * @param args
     * @throws UnknownHostException
     * @throws IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public static void main(String[] args) throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ClientChatForm chatForm = new ClientChatForm();
    }

    /**
     * Method to open Server Socket and allow connections
     *
     */
    private static void connect() throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        conn = new Socket(InetAddress.getByName(contactIP), PORT_NO);
        displayMessage("Connected to Server", NOTIFIC);
        BigInteger intA = generateMyDHKeyPart(PRIME_P, PRIME_Q, PRIV_KEY);
        sendMessage(intA.toString(), DH_KEY);
    }

    /**
     *
     * Method to generate Diffie-Hellman key for secure key exchange Calculated
     * using key = q^a mod p
     *
     * @param p 512 bit prime number not secret
     * @param q 511 bit prime number not secret
     * @param a private key secret
     * @return key used to mutually generate a shared secret key for RSA
     * exchange
     */
    private static BigInteger generateMyDHKeyPart(BigInteger p, BigInteger q, BigInteger a) {
        BigInteger key = q.modPow(a, p);
        return key;
    }

    /**
     * Method to generate a shared Diffie-Hellman Key for initial RSA key
     * exchange
     *
     * @param clientDH
     * @param privateKey
     * @param p
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    private static void generateSharedDHKey(BigInteger clientDH, BigInteger privateKey, BigInteger p) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        BigInteger k = clientDH.modPow(privateKey, p);
        byte[] hashedKey = hashFunction(k.toString(), "MD5");
        sharedDHKey = new SecretKeySpec(hashedKey, 0, hashedKey.length, "AES");
    }

    /**
     * Method to generate RSA public and private keys
     *
     * @throws NoSuchAlgorithmException
     */
    private static void generateRSAKeys() throws NoSuchAlgorithmException {
        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        publicKey = kp.getPublic();
        privateKey = kp.getPrivate();
    }

    /**
     * Method to invoke the mutual AES key generation
     */
    private static void mutualGenKey(String msg) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        byte[] hashPass = null;
        byte[] digSignBytes;
        byte[] nonceBytes;
        byte[] responseBytes;
        byte[] signCipher64;
        byte[] nonceCipher64;
        byte[] responseCipher64;
        byte[] authSign;
        byte[] authSign64;
        byte[] nonHash;
        byte[] nonceDec;
        String signCipherText;
        String nonceCipherText;
        String responseCipherText;
        String fullMsg;
        String fullNonStr;
        String str2int = "";
        String[] parts;
        long secLong = secRand.nextInt();

        switch (keyGenStage) {
            case 0:
                if (msg.length() > 8) {
                    displayMessage("Invalid pass phrase length, must be 8 characters or less", NOTIFIC);
                    break;
                }
                for (int i = 0; i < msg.length(); i++) {
                    str2int = str2int + Character.getNumericValue(msg.charAt(i));
                }
                myNonce = secLong + Long.parseLong(str2int);
                try {
                    hashPass = hashFunction(Long.toString(myNonce), "SHA-256");
                } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
                    Logger.getLogger(ClientChatForm.class.getName()).log(Level.SEVERE, null, ex);
                }
                setEncryptionType(3); // setup digSign encryption
                digSignBytes = encrypt(hashPass);
                signCipher64 = Base64.encodeBase64(digSignBytes);
                signCipherText = new String(signCipher64);
                setEncryptionType(1); // set up RSA encryption
                nonceBytes = encrypt(Long.toString(myNonce).getBytes());
                nonceCipher64 = Base64.encodeBase64(nonceBytes);
                nonceCipherText = new String(nonceCipher64);
                fullMsg = nonceCipherText + "::" + signCipherText;
                setEncryptionType(0);
                sendMessage(fullMsg, AES_KEY);
                keyGenStage += 2;
                isNextKeyGen = true;
                break;
            case 1:
                String passPhrase = JOptionPane.showInputDialog(null, "Please Enter a password/phrase 8 chars or shorter.");
                if (passPhrase.length() > 8) {
                    displayMessage("Invalid pass phrase length, must be 8 characters or less", NOTIFIC);
                    break;
                }
                for (int i = 0; i < passPhrase.length(); i++) {
                    str2int = str2int + Character.getNumericValue(passPhrase.charAt(i));
                }
                myNonce = secLong + Long.parseLong(str2int);
                try {
                    hashPass = hashFunction(Long.toString(myNonce), "SHA-256");
                } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
                    Logger.getLogger(ClientChatForm.class.getName()).log(Level.SEVERE, null, ex);
                }

                parts = msg.split("::");
                setDecryptionType(3);
                authSign64 = Base64.decodeBase64(parts[1].getBytes());
                authSign = decrypt(authSign64);
                setDecryptionType(1);
                nonceDec = decrypt(Base64.decodeBase64(parts[0].getBytes()));
                String nonceDecStr = new String(nonceDec, "UTF-8");
                byte[] hash = hashFunction(nonceDecStr, "SHA-256");
                if (Arrays.equals(authSign, hash)) {
                    theirNonce = Long.parseLong(nonceDecStr);
                    displayMessage("Nonce successfully recieved", NOTIFIC);
                    fullNonce = myNonce + theirNonce;
                    fullNonStr = Long.toString(fullNonce);
                    nonHash = hashFunction(fullNonStr, "MD5");
                    sharedKey = new SecretKeySpec(nonHash, 0, nonHash.length, "AES");
                    isGenKey = true;
                    displayMessage(sharedKey.toString(), NOTIFIC);

                } else {
                    sendMessage("Your Nonce was NOT decrypted successfully", TXT_MSG);
                    displayMessage("The other Nonce was NOT decrypted successfully", NOTIFIC);
                }

                setEncryptionType(3); // setup digSign encryption
                digSignBytes = encrypt(hashPass);
                signCipher64 = Base64.encodeBase64(digSignBytes);
                signCipherText = new String(signCipher64);
                setEncryptionType(1); // set up RSA encryption
                nonceBytes = encrypt(Long.toString(myNonce).getBytes());
                nonceCipher64 = Base64.encodeBase64(nonceBytes);
                nonceCipherText = new String(nonceCipher64);
                setEncryptionType(2);
                responseBytes = encrypt(nonceDecStr.getBytes());
                responseCipher64 = Base64.encodeBase64(responseBytes);
                responseCipherText = new String(responseCipher64);
                fullMsg = responseCipherText + "::" + nonceCipherText + "::" + signCipherText;
                setEncryptionType(0);
                sendMessage(fullMsg, AES_KEY);
                keyGenStage += 2;
                break;

            case 2:
                msg = msg.substring(ID_SIZE, msg.length() - ID_SIZE);
                parts = msg.split("::");
                setDecryptionType(3);
                authSign64 = Base64.decodeBase64(parts[2].getBytes());
                authSign = decrypt(authSign64);
                setDecryptionType(1);
                byte[] nonceDec2 = decrypt(Base64.decodeBase64(parts[1].getBytes()));
                String nonceDecStr2 = new String(nonceDec2, "UTF-8");
                byte[] hash2 = hashFunction(nonceDecStr2, "SHA-256");

                if (Arrays.equals(authSign, hash2)) {
                    theirNonce = Long.parseLong(nonceDecStr2);
                    displayMessage("Nonce successfully recieved", NOTIFIC);
                    fullNonce = myNonce + theirNonce;
                    fullNonStr = Long.toString(fullNonce);
                    nonHash = hashFunction(fullNonStr, "MD5");
                    sharedKey = new SecretKeySpec(nonHash, 0, nonHash.length, "AES");
                    isGenKey = true;
                    isNextKeyGen = false;
                    setEncryptionType(2);
                    responseBytes = encrypt(nonceDecStr2.getBytes());
                    responseCipher64 = Base64.encodeBase64(responseBytes);
                    responseCipherText = new String(responseCipher64);
                    setEncryptionType(0);
                    sendMessage(responseCipherText, AES_KEY);
                    displayMessage(sharedKey.toString(), NOTIFIC);
                } else {
                    sendMessage("Your Nonce was NOT decrypted successfully", TXT_MSG);
                    displayMessage("The other Nonce was NOT decrypted successfully", NOTIFIC);
                }
                setDecryptionType(2);
                if (Arrays.equals(decrypt(Base64.decodeBase64(parts[0].getBytes())), Long.toString(myNonce).getBytes())) {
                    displayMessage("Challenge Response received.", NOTIFIC);
                    isNextKeyGen = false;
                } else {
                    displayMessage("Challenge Response Not Recieved, Process terminated.", NOTIFIC);
                    isNextKeyGen = false;
                }
                break;
            case 3:
                msg = msg.substring(ID_SIZE, msg.length() - ID_SIZE);
                setDecryptionType(2);
                authSign64 = Base64.decodeBase64(msg.getBytes());
                authSign = decrypt(authSign64);
                if (Arrays.equals(authSign, Long.toString(myNonce).getBytes())) {
                    displayMessage("Challenge Response received.", NOTIFIC);
                    isNextKeyGen = false;
                } else {
                    displayMessage("Challenge Response Not Recieved, Process terminated.", NOTIFIC);
                    isNextKeyGen = false;

                }
            default:
                break;
        }
    }

    /**
     * Method to transfer public key to client/server
     */
    private static void sendPubKey() {
        setEncryptionType(2); // use DH key for encryption
        try {
            generateRSAKeys();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ClientChatForm.class.getName()).log(Level.SEVERE, null, ex);
        }
        byte[] pubKeyByte = publicKey.getEncoded();
        String encodedKey = java.util.Base64.getEncoder().encodeToString(pubKeyByte);
        displayMessage("Public Key Sent", NOTIFIC);
        try {
            sendMessage(encodedKey, RSA_PUB_KEY);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(ClientChatForm.class.getName()).log(Level.SEVERE, null, ex);
        }
        setEncryptionType(0); // set encryption back to none
    }

    /**
     * Method to send the text in the JTextField to the Client/Server
     *
     * @param input - String representation of whats being sent
     * @param messageType - Integer code of message type
     *
     * 2040 - Message 2141 - RSA Public Key 2343 - AES Key
     */
    private static void sendMessage(String input, int messageType) throws UnsupportedEncodingException {
        String strSent;
        switch (messageType) {
            case TXT_MSG:
                displayMessage(input, SENT);
                strSent = TEXTPRE + input + TEXTPOS;
                break;
            case RSA_PUB_KEY:
                strSent = PUBKEYPRE + input + PUBKEYPOS;
                break;
            case DH_KEY:
                strSent = DHKEYPRE + input + DHKEYPOS;
                break;
            case IMG_FIL:
                strSent = FILEPRE + input + FILEPOS;
                break;
            case AES_KEY:
                strSent = AESPRE + input + AESPOS;
                break;
            default:
                strSent = "Error in sending";
                break;
        }
        byte[] plainByte = strSent.getBytes();
        byte[] cipherBytes = encrypt(plainByte);
        byte[] cipher64 = Base64.encodeBase64(cipherBytes);
        String cipherText = new String(cipher64);
        try {
            DataOutputStream dos = new DataOutputStream(conn.getOutputStream());
            dos.writeUTF(Integer.toString(encryptType));
            dos.writeUTF(cipherText);
        } catch (Exception e1) {
            try {
                Thread.sleep(3000);
                System.exit(0);
            } catch (InterruptedException e2) {
            }
        }
        newMsg.setText("");
    }

    /**
     * Method to send the file chosen by the "Browse" JButton over a socket
     *
     * @param file - file to be sent
     * @throws IOException
     */
    private void sendFile(File file) throws IOException {

        ServerSocket servsock = new ServerSocket(PORT_NO + 1);
        try {
            Socket sock = servsock.accept();
            DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
            byte[] byteArray = FileUtils.readFileToByteArray(file);
            //byte[] encByteArray = encrypt(byteArray);

            dos.write(byteArray, 0, byteArray.length); //write bytes to output stream

            dos.close(); //close data ouput stream 
            sock.close(); // close socket
            servsock.close(); // close server socket    
        } catch (IOException io) {
            System.err.println(io);
        }
    }

    /**
     * Method to receive file from socket once isNextFile is set
     *
     * @throws IOException
     */
    private static void receiveFile() throws IOException {
        try {
            
            Socket sock = new Socket(contactIP, PORT_NO + 1);
            String outputLocation = fileOutLocation + fileName;
            byte[] mybytearray = new byte[fileSize];
            FileOutputStream fos = new FileOutputStream(outputLocation);
            DataInputStream dis = new DataInputStream(sock.getInputStream());

            int count;
            while ((count = dis.read(mybytearray)) > 0) {
                fos.write(mybytearray, 0, count);
            }
            byte[] encFile = FileUtils.readFileToByteArray(new File(outputLocation));
            byte[] decodedValue = new Base64().decode(encFile);
            byte[] decFile = decrypt(decodedValue);
            FileUtils.writeByteArrayToFile(new File(outputLocation), decFile);
            
            fos.flush(); // flush file output stream
            fos.close(); //close file output stream 
            sock.close(); // close the socket
            displayMessage("File Received Successfuly.", NOTIFIC);
            
        } catch (IOException io) {
            System.err.println(io);
        }
    }

    /**
     * Method to continuously poll for incoming data.
     */
    private static void pollForData() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            if (isNextFile == true) {
                receiveFile();
                isNextFile = false;
                fileSize = 0;
            } else {
                DataInputStream dis = new DataInputStream(conn.getInputStream());
                String stringReceived = dis.readUTF();

                if (isNextKeyGen == true) {
                    if (!stringReceived.equals("0")) {
                        byte[] cipherText = stringReceived.getBytes();
                        byte[] cipher64 = Base64.decodeBase64(cipherText);
                        byte[] plainBytes = decrypt(cipher64);
                        String plainText = new String(plainBytes, "UTF-8");
                        mutualGenKey(plainText);
                    } else {
                        setDecryptionType(0);
                    }
                } else if (("0".equals(stringReceived) || "1".equals(stringReceived) || "2".equals(stringReceived)) && (isNextFile == false)) {
                    int newType = Integer.parseInt(stringReceived);
                    if (decryptType != newType) {
                        decryptType = newType;
                        displayMessage(decTypes[Integer.parseInt(stringReceived)], NOTIFIC);
                    }
                } else {
                    byte[] cipherText = stringReceived.getBytes();
                    byte[] cipher64 = Base64.decodeBase64(cipherText);
                    byte[] plainBytes = decrypt(cipher64);
                    String plainText = new String(plainBytes, "UTF-8");
                    String formatOfString = plainText.substring(0, ID_SIZE);
                    String succesfulSend = plainText.substring((plainText.length() - ID_SIZE), plainText.length());
                    String actualString = plainText.substring(ID_SIZE, (plainText.length() - ID_SIZE));
                    switch (formatOfString) {
                        case TEXTPRE:
                            if (succesfulSend.equals(TEXTPOS)) {
                                displayMessage(actualString, RECEIVED);
                            } else {
                                displayMessage("Full Message Not Recieved", MSG_ERR);
                            }
                            break;
                        case PUBKEYPRE:
                            if (succesfulSend.equals(PUBKEYPOS)) {
                                displayMessage("Public Key Received and Saved", NOTIFIC);
                                byte[] decodedKey = java.util.Base64.getDecoder().decode(actualString);
                                otherPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedKey));
                            } else {
                                displayMessage("Full Message Not Recieved", MSG_ERR);
                            }
                            break;
                        case DHKEYPRE:
                            if (succesfulSend.equals(DHKEYPOS)) {
                                generateSharedDHKey(new BigInteger(actualString), PRIV_KEY, PRIME_P);
                                displayMessage("Shared Key Generated and Stored.", NOTIFIC);
                                sendPubKey();
                            } else {
                                displayMessage("DH Key Not Exchanged Properly", MSG_ERR);
                            }
                            break;
                        case FILEPRE:
                            if (succesfulSend.equals(FILEPOS)) {
                                isNextFile = true;
                                String[] parts = actualString.split("::");
                                fileName = parts[0]; // filename
                                fileSize = Integer.parseInt(parts[1]); // string to int
                                displayMessage("File Incoming :" + fileName, NOTIFIC);
                            } else {
                                displayMessage("Full Message Not Recieved", MSG_ERR);
                            }
                            break;
                        case AESPRE:
                            if (succesfulSend.equals(AESPOS)) {
                                isNextKeyGen = true;
                                keyGenStage++;
                                mutualGenKey(actualString);
                            } else {
                                displayMessage("AES Key Not Exchanged Properly", MSG_ERR);
                            }
                            break;
                        default:
                            displayMessage("Incorrect Format Sent", MSG_ERR);
                            break;
                    }
                }
            }
        } catch (IOException | NoSuchAlgorithmException e1) {
            displayMessage("Disconnected from Server", MSG_ERR);
            try {
                Thread.sleep(5000);
                connect();
            } catch (InterruptedException e) {
            }
        }
    }

    /**
     * Displays message on the JTextArea
     *
     * @param message - String to be added to JTextarea
     * @param messageDirection - Direction of message transport
     *
     * 76 - SENT 87 - RECEIVED 34 - MSG_ERR
     *
     */
    private static void displayMessage(String message, int messageDirection) {
        switch (messageDirection) {
            case SENT:
                messageDisplay.setText(messageDisplay.getText() + "\n" + "Me: " + message);
                break;
            case RECEIVED:
                messageDisplay.setText(messageDisplay.getText() + "\n" + userID + ": " + message);
                break;
            case MSG_ERR:
                messageDisplay.setText(messageDisplay.getText() + "\n" + "ERROR: " + message);
                break;
            case NOTIFIC:
                messageDisplay.setText(messageDisplay.getText() + "\nNOTIFICATION: " + message);
                break;
            default:
                break;
        }
    }

    /**
     * Default ActionListener Method (unused)
     *
     * @param e
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        throw new UnsupportedOperationException("Action Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Getter/Accessor for the Server IP Address
     *
     * @return contactIP
     */
    public static String getServerIP() {
        return contactIP;
    }

    /**
     * Setter/Mutator for the Server IP Address
     *
     * @param ip - String representation of Server IP Address
     * @throws java.io.IOException
     */
    public static void setServerIP(String ip) throws IOException {
        contactIP = ip;
        //connect();
    }

    /**
     * Setter/Mutator for the Encryption Type
     *
     * @param encCode - Integer representation of Encryption Type
     *
     * 0 - No Encryption 1 - RSA Encryption 2 - Session Key Encryption 3 -
     * Digitally Sign
     *
     */
    public static void setEncryptionType(int encCode) {
        encryptType = encCode;
        encTypeLabel.setText(encTypes[encryptType]);
        encTypeLabel.repaint();
    }

    /**
     * Setter/Mutator for the Decryption Type
     *
     * @param decCode - Integer representation of Encryption Type
     *
     * 0 - No Decryption 1 - RSA Decryption 2 - Session Key Decryption 3 -
     * Digital Signature Authentication
     *
     */
    public static void setDecryptionType(int decCode) {
        decryptType = decCode;
    }

    /**
     * Method to encrypt a byte[] and export as a UTF8 String
     *
     * @param plain - byte[] to be encrypted
     * @return - UTF8 String equivalent of the encrypted byte[]
     * @throws UnsupportedEncodingException
     */
    private static byte[] encrypt(byte[] plain) throws UnsupportedEncodingException {
        byte[] cipherText;
        String algorithm;
        String cipherT = null;
        Key encKey = null;
        switch (encryptType) {
            case 0:
                algorithm = "None";
                break;
            case 1:
                algorithm = "RSA";
                encKey = otherPublicKey;
                break;
            case 2:
                algorithm = "AES";
                if (isGenKey == true) {
                    displayMessage("Mutual Key in use ENC", NOTIFIC);
                    encKey = sharedKey;
                } else {
                    encKey = sharedDHKey;
                }
                secRand.nextBytes(iv);
                ivParameterSpec = new IvParameterSpec(iv);
                break;
            case 3:
                algorithm = "RSA";
                encKey = privateKey;
                break;
            default:
                algorithm = "None";
                break;
        }
        if (!algorithm.equals("None")) {
            try {
                final Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.ENCRYPT_MODE, encKey);
                cipherText = cipher.doFinal(plain);
                return cipherText;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                displayMessage(e.toString(), NOTIFIC);
            }
        } else {
            return plain;
        }
        return ("Error Encrypting").getBytes();
    }

    /**
     * Method to decrypt an encrypted byte[] and returns a UTF8 String
     *
     * @param cipherText - encrypted byte[]
     * @return - UTF8 String equivalent of unencrypted byte[]
     * @throws UnsupportedEncodingException
     */
    private static byte[] decrypt(byte[] cipherText) throws UnsupportedEncodingException {
        byte[] plainText;
        String algorithm;
        Key decKey = null;
        switch (decryptType) {
            case 0:
                algorithm = "None";
                break;
            case 1:
                algorithm = "RSA";
                decKey = privateKey;
                break;
            case 2:
                algorithm = "AES";
                if (isGenKey == true) {
                    displayMessage("Mutual Key in use DEC", NOTIFIC);
                    decKey = sharedKey;
                } else {
                    decKey = sharedDHKey;
                }
                break;
            case 3:
                algorithm = "RSA";
                decKey = otherPublicKey;
                break;
            default:
                algorithm = "None";
                break;
        }

        if (!algorithm.equals("None")) {
            try {
                final Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.DECRYPT_MODE, decKey);
                plainText = cipher.doFinal(cipherText);
                return plainText;

            } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException e) {
                displayMessage(e.toString(), NOTIFIC);
            }
        } else {
            return cipherText;
        }
        return ("Error Decrypting").getBytes();
    }

    /**
     * Method to hash a String using a chosen Hash algorithm
     *
     * @param toBeHashed String to be hashed
     * @param algorithm hashing algorithm to be used eg. "MD5", "SHA-256" etc
     *
     * @return hashed byte[]
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    private static byte[] hashFunction(String toBeHashed, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest hash = MessageDigest.getInstance(algorithm);
        hash.update(toBeHashed.getBytes("UTF-8"));
        byte[] hashedBytes = hash.digest();

        return hashedBytes;
    }
}
