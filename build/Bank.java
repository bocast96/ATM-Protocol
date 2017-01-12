import javax.crypto.Cipher;
import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
public class Bank {
    private final static int FAIL_CODE = 255;
    private final static int DEFAULT_PORT = 3000;
    private final static String DEFAULT_AUTH = "bank.auth";
    private final static int PORT_MIN = 1024, PORT_MAX = 65535;
    private final static String ALGORITHM = "RSA";
    private ServerSocket bankServer;
    private Socket atmConnection;
    private BufferedReader input;
    private BufferedWriter output;
    private int portNum;
    private String authFile, salt, pepper;
    private HashMap<String, Double> accounts;
    private HashMap<String, String> cards;
    private SecureRandom random;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Signature signSig, verifySig;
    private Base64.Encoder encoder;
    private Base64.Decoder decoder;
    private String[] lastAction;
    private Bank() throws NoSuchAlgorithmException {
        this.portNum = DEFAULT_PORT;
        this.authFile = DEFAULT_AUTH;
        random = new SecureRandom();
        accounts = new HashMap<>();
        cards = new HashMap<>();
        signSig = Signature.getInstance("SHA256withRSA");
        verifySig = Signature.getInstance("SHA256withRSA");
        encoder = Base64.getEncoder();
        decoder = Base64.getDecoder();
    }
    private Bank(int portNum, String authFile) throws NoSuchAlgorithmException {
        this();
        this.portNum = portNum;
        this.authFile = authFile;
    }
    private Bank(int portNum) throws NoSuchAlgorithmException {
        this();
        this.portNum = portNum;
    }
    private Bank(String authFile) throws NoSuchAlgorithmException {
        this();
        this.authFile = authFile;
    }
    private void generateKeys() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(1024, random);
            KeyPair key1 = keyPairGenerator.generateKeyPair();
            KeyPair key2 = keyPairGenerator.generateKeyPair();
            privateKey = key1.getPrivate();
            PublicKey AtmPubKey = key1.getPublic();
            publicKey = key2.getPublic();
            PrivateKey AtmPrivateKey = key2.getPrivate();
            createAuthFile(AtmPrivateKey, AtmPubKey);
            signSig.initSign(privateKey);
            verifySig.initVerify(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            //logErr("Failed to Generate keys: " + e.toString());
            System.exit(FAIL_CODE);
        }
    }
    private void startBank() {
        setup();
        try {
            bankServer = new ServerSocket(portNum);
            try {
                while (true) {
                    waitForConnection();
                    setConnection();
                    String message = getMessage();
                    if (message.trim().equals("SIGTERM")) {
                        closeConnection();
                        break;
                    }
                    processMessage(message);
                    closeConnection();
                }
            } catch (IOException | SignatureException | NoSuchAlgorithmException e) {
                //logErr("Error in startup: " + e.toString());
                System.exit(1);
            } finally {
                bankServer.close();
            }
        } catch (IOException e) {
            System.exit(FAIL_CODE);
        }
    }
    private void setup() {
        salt = generateIV(random.nextInt(30));
        pepper = generateIV(random.nextInt(30));
        generateKeys();
    }
    private void createAuthFile(PrivateKey privateKey, PublicKey publicKey) {
        try {
            String privKey = encoder.encodeToString(privateKey.getEncoded());
            String pubKey = encoder.encodeToString(publicKey.getEncoded());
            PrintWriter writer = new PrintWriter(authFile);
            writer.println(privKey);
            writer.println(pubKey);
            writer.flush();
            writer.close();
            log("created");
        } catch (IOException e) {
            System.exit(FAIL_CODE);
        }
    }
    private void waitForConnection() throws IOException{
        //logErr("Bank waiting for connection");
        atmConnection = bankServer.accept();
        //logErr("CONNECTED");
    }
    private void setConnection() throws IOException{
        input = new BufferedReader(new InputStreamReader(atmConnection.getInputStream()));
        output = new BufferedWriter(new OutputStreamWriter(atmConnection.getOutputStream()));
        output.flush();
    }
    private String getMessage() throws IOException {
        String message = input.readLine();
        return message;
    }
    private void closeConnection() throws IOException{
        input.close();
        output.close();
    }
    private void processMessage(String message) throws SignatureException, NoSuchAlgorithmException {
        String[] parts = message.split(",");
        if (verify(parts[1], parts[0])) {
            String[] cmds = decrypt(parts[0]).split(",");
            String result, action, name;
            double amount = 0;
            switch (cmds[0].trim()){
                case "1": // New Account
                    lastAction = cmds;
                    amount =  Double.valueOf(cmds[4]);
                    result = createAccount(cmds[1], cmds[2], cmds[3], amount);
                    action = "initial_balance";
                    name = cmds[3];
                    break;
                case "2": // Deposit
                    lastAction = cmds;
                    amount =  Double.valueOf(cmds[3]);
                    result = deposit(cmds[1], cmds[2], amount, cmds[4]);
                    action = "deposit";
                    name = cmds[2];
                    break;
                case "3": // Withdraw
                    lastAction = cmds;
                    amount =  Double.valueOf(cmds[3]);
                    result = withdraw(cmds[1], cmds[2], amount, cmds[4]);
                    action = "withdraw";
                    name = cmds[2];
                    break;
                case "4": // Balance
                    lastAction = cmds;
                    result = balance(cmds[1], cmds[2], cmds[3]);
                    String[] tmp = result.split(",");
                    amount = Double.valueOf(tmp[1]);
                    action = "balance";
                    name = cmds[2];
                    break;
                case "5":
                    if (lastAction != null && cmds[1].equals(lastAction[0]) && cmds[2].equals(lastAction[1])) {
                        undo();
                        log("protocol_error");
                        return;
                    }
                default:
                    result = "fail";
                    name = "fail";
                    action = "fail";
            }
            String cipher = encrypt(result);
            signSig.update(decoder.decode(cipher));
            String sig = encoder.encodeToString(signSig.sign());
            String outMsg = cipher + "," + sig;
            try {
                output.write(outMsg);
                output.flush();
            } catch (IOException e) {
                //logErr("Error sending response: " + e.toString());
                log("protocol_error");
                result = "fail";
                undo();
            }
            if (result.startsWith("success")){
                String outout = "{\"account\":\"" + name + "\",\"" + action + "\":" + amount + "}";
                log(outout);
            } else {
                lastAction = null;
            }
        } else {
            //logErr("Signature could not be verified");
            log("protocol_error");
            try {
                output.write("fail," + generateIV(20));
                output.flush();
            } catch (IOException e) {
                //logErr("Error sending response: " + e.toString());
                log("protocol_error");
                undo();
            }
        }
    }
    private void undo(){
        double amount;
        switch (lastAction[0]){
            case "1": // New Account
                accounts.remove(lastAction[3]);
                cards.remove(lastAction[3]);
                break;
            case "2": // Deposit
                amount =  Double.valueOf(lastAction[3]);
                double tmp = accounts.get(lastAction[2]);
                accounts.replace(lastAction[2], tmp-amount);
                break;
            case "3": // Withdraw
                amount =  Double.valueOf(lastAction[3]);
                double tmp2 = accounts.get(lastAction[2]);
                accounts.replace(lastAction[2], tmp2+amount);
                break;
        }
        lastAction = null;
    }
    private boolean verify (String signature, String data) {
        try {
            verifySig.update(decoder.decode(data));
            return verifySig.verify(decoder.decode(signature));
        } catch (SignatureException e) {
            //logErr("Error verifying signature: " + e.toString());
            System.exit(FAIL_CODE);
        }
        return false;
    }
    private void log(String text) {
        System.out.println(text);
        System.out.flush();
    }
    private void logErr(String msg) {
        System.err.println(msg);
        System.err.flush();
    }
    private String createAccount(String authFile, String cardFile, String name, double amount){
        String pad = generateIV(random.nextInt(30));
        try {
            if (this.authFile.equals(authFile) && !accounts.containsKey(name) && amount > 10 && !cards.containsValue(cardFile)) {
                String key = hash(generateIV(random.nextInt(50)+1), false);
                accounts.put(name, amount);
                cards.put(name, cardFile);
                PrintWriter writer = new PrintWriter(cardFile);
                writer.println(key);
                writer.flush();writer.close();
                key = hash(key, true);
                return "success," + key + "," + pad;
            }
        } catch (Exception e) {
            log("protocol_error");
            return "fail," + pad;
        }
        log("protocol_error");
        return "fail," + pad;
    }
    private boolean verifyCard (String name, String cardName, String card) {
        if (cards.containsKey(name) && cards.get(name).equals(cardName)){
            try {
                String cardFile = new String(Files.readAllBytes(Paths.get(cardName)));
                String cardLocal = cardFile.trim();
                String hashCard = hash(cardLocal, true);
                return hashCard.equals(card);
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }
    private String hash(String key, boolean doSalt) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        String tmp = doSalt ? salt + key + pepper : key;
        digest.update(tmp.getBytes());
        byte[] hash = digest.digest();
        return encoder.encodeToString(hash);
    }
    private String deposit(String card, String name, double amount, String cardFile) throws NoSuchAlgorithmException {
        String pad = generateIV(random.nextInt(30));
        if (accounts.containsKey(name) && verifyCard(name, cardFile, card)) {
            double tmp = accounts.get(name);
            accounts.replace(name, tmp+amount);
            return "success," + pad;
        } else {
            log("protocol_error");
            return "fail," + pad;
        }
    }
    private String withdraw(String card, String name, double amount, String cardFile) throws NoSuchAlgorithmException {
        String pad = generateIV(random.nextInt(30));
        if (accounts.containsKey(name) && accounts.get(name) >= amount && verifyCard(name, cardFile, card)) {
            double tmp = accounts.get(name);
            accounts.replace(name, tmp - amount);
            return "success," + pad;
        } else {
            log("protocol_error");
            return "fail," + pad;
        }
    }
    private String balance(String card, String name, String cardFile) throws NoSuchAlgorithmException {
        String pad = generateIV(random.nextInt(30));
        if (accounts.containsKey(name) && verifyCard(name, cardFile, card)) {
            double tmp = accounts.get(name);
            return "success," + String.valueOf(tmp) + "," + pad;
        }
        log("protocol_error");
        return "fail," + pad;
    }
    private String decrypt (String message) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] original = cipher.doFinal(decoder.decode(message));
            return new String(original);
        } catch (Exception ex) {
            //logErr("Error decryption: " + ex.toString());
            System.exit(FAIL_CODE);
        }
        return null;
    }
    private String encrypt(String original){
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(original.getBytes());
            return encoder.encodeToString(encrypted);
        } catch (Exception ex) {
            //logErr("Error encryption: " + ex.toString());
            System.exit(FAIL_CODE);
        }
        return null;
    }
    private String  generateIV(int bound) {
        char[] chars = "abcdefghijklmnopqrstuvwxyz".toCharArray();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bound; i++) {
            char c = chars[random.nextInt(chars.length)];
            sb.append(c);
        }
        return sb.toString();
    }
    public static void main(String[] args) throws IOException {
        Bank bank;
        if (args.length > 0){
            int port = 0;
            String file = null;
            boolean prt = false, fn = false;
            try {
                for (int i = 0; i < args.length; i++) {
                    if (args[i].matches("^-p$") && args[i+1].matches("^[1-9][0-9]*$")) {
                        if (!prt) {
                            port = Integer.parseInt(args[i + 1]);
                            prt = true;
                            i++;
                        } else {
                            System.exit(Bank.FAIL_CODE);
                        }
                    } else if (args[i].matches("^-p[1-9][0-9]*$")) {
                        if (!prt) {
                            port = Integer.parseInt(args[i].substring(2));
                            prt = true;
                        } else {
                            System.exit(Bank.FAIL_CODE);
                        }
                    } else if (args[i].matches("^-s$") && args[i+1].matches("^[_\\-0-9a-z\\.]+$")) {
                        if (!fn) {
                            fn = true;
                            file = args[i + 1];
                            i++;
                        } else {
                            System.exit(Bank.FAIL_CODE);
                        }
                    } else if (args[i].matches("^-s[_\\-0-9a-z\\.]+$")) {
                        if (!fn) {
                            fn = true;
                            file = args[i].substring(2);
                        } else {
                            System.exit(Bank.FAIL_CODE);
                        }
                    } else {
                        System.exit(Bank.FAIL_CODE);
                    }
                }
            } catch (NumberFormatException | ArrayIndexOutOfBoundsException e){
                System.exit(Bank.FAIL_CODE);
            }
            if (fn) {
                if (file.length() > 255) { System.exit(Bank.FAIL_CODE); }

                File tmpFile = new File(file);
                if (!file.equals(Bank.DEFAULT_AUTH) && tmpFile.exists()) {
                    System.exit(Bank.FAIL_CODE);
                }
            }

            if (prt && (port < Bank.PORT_MIN || port > Bank.PORT_MAX)) { System.exit(Bank.FAIL_CODE); }

            try {
                if (prt && fn) {
                    bank = new Bank(port, file);
                } else if (prt) {
                    bank = new Bank(port);
                } else {
                    bank = new Bank(file);
                }
                bank.startBank();
            } catch (NoSuchAlgorithmException e){
                System.exit(Bank.FAIL_CODE);
            }
        } else {
            try {
                bank = new Bank();
                bank.startBank();
            } catch (NoSuchAlgorithmException e) {
                System.exit(Bank.FAIL_CODE);
            }
        }
    }
}