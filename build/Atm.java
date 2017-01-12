import java.io.*;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;

public class Atm {
	private static final String finalAuthFile = "bank.auth";
	private static final String finalIPAddress = "127.0.0.1";
	private static final int finalPortNum = 3000;
	private final static String ALGORITHM = "RSA";
	private static String authFileName;
	private static String IPAddress;
	private static int portNum;
	private String accountName;
	private double balance;
	private String cardFileName;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Signature signSig, verifySig;
	Socket socket = null;
	public Atm(String accountNameIn, String authFileIn, String IPIn, int portIn, String cardFileIn) {
		accountName = accountNameIn;
		authFileName = authFileIn;
		IPAddress = IPIn;
		portNum = portIn;
		cardFileName = cardFileIn;
		try {
			signSig = Signature.getInstance("SHA256withRSA");
			verifySig = Signature.getInstance("SHA256withRSA");
		} catch (NoSuchAlgorithmException e) {
			//logErr("Failed init Signatures");
		}
		try {
			getKeys();
			createSignatures();
		} catch (Exception e) {
			//logErr("Error getting keys");
			System.exit(63);
		}
		connectToBank();
	}
	public double newAccount(double amount) {
		try {
			String[] response = sendMessage("1," + authFileName + "," + cardFileName + ","+ accountName + "," + amount).split(",");
			if (response[0].equals("success")) {
				PrintWriter writer = new PrintWriter(cardFileName);
				writer.println(response[1]);
				writer.flush();
				writer.close();
				return amount;
			} else {
				//logErr("New account denied");
				System.exit(255);
				return -1;
			}
		} catch (Exception e) {
			//logErr("Error in new account: " + e.toString());
			System.exit(255);
			return -1;
		}
	}
	public double deposit(double amount) {
		try {
			String card = new String(Files.readAllBytes(Paths.get(cardFileName)));
			card = card.trim();
			String[] response = sendMessage("2," + card + "," + accountName + "," + amount+ "," +cardFileName).split(",");
			if (response[0].equals("success")) {
				return amount;
			} else {
				//logErr("Deposit denied");
				System.exit(255);
				return -1;
			}
		} catch (Exception e) {
			//logErr("Error in deposit: " + e.toString());
			System.exit(255);
			return -1;
		}
	}
	public double withdraw(double amount) {
		try {
			String card = new String(Files.readAllBytes(Paths.get(cardFileName))).trim();
			String[] response = sendMessage("3," + card + "," + accountName + "," + amount+","+ cardFileName).split(",");
			if (response[0].equals("success")) {
				return amount;
			} else {
				//logErr("Withdraw denied");
				System.exit(255);
				return -1;
			}
		} catch (Exception e) {
			//logErr("Error in withdraw: " + e.toString());
			System.exit(255);
			return -1;
		}
	}
	public double getBalance() {
		try {
			String card = new String(Files.readAllBytes(Paths.get(cardFileName)));
			card = card.trim();
			String[] response = sendMessage("4," + card + "," + accountName+","+ cardFileName).split(",");
			if (response[0].equals("success")) {
				return Double.valueOf(response[1]);
			} else {
				//logErr("Balance denied");
				System.exit(255);
				return -1;
			}
		} catch (Exception e) {
			//logErr("Error in balance: " + e.toString());
			System.exit(255);
			return -1;
		}
	}
	public void connectToBank(){
		try {
			socket = new Socket(IPAddress, portNum);
			//logErr("CONNECTION MADE");
		} catch (Exception e) {
			//logErr("CONNECTION ERROR - " +e.toString());
			System.exit(63);
		}
	}
	public String sendMessage(String message) {
		String response = null;
		try {
			//secure message
			String encrypted = encrypt(message);
			String signedMessage = signMessage(encrypted);
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			out.println(signedMessage);
			socket.setSoTimeout(10000);
			//logErr("Message sent to bank");
			//logErr("ATM - Awaiting response");
			InputStream is = socket.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			response = br.readLine();
			String[] parts = response.split(",");
			if (verify(parts[1], parts[0])) {
				response = decrypt(parts[0]);
			} else {
				//logErr("Failed to verify Message");
				response = "ERROR";
                socket.close();
                sendUndo("5,"+message);
			}
			socket.close();
			//logErr("CONNECTION CLOSED");
		} catch (SocketTimeoutException e) {
			//logErr("connection timed out");
			System.exit(63);
		} catch (Exception e) {
			//logErr(e.toString());
			System.exit(63);
		}
		return response;
	}

	private void sendUndo(String message) throws SignatureException, IOException {
        connectToBank();
        String msg = encrypt(message);
        String sig = signMessage(msg);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        out.println(sig);
        socket.close();
        System.exit(63);
    }

	private void getKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		BufferedReader br = new BufferedReader(new FileReader(authFileName));
		String privateK = br.readLine().trim();
		String publicK = br.readLine().trim();
		br.close();
		byte[] privateBytes = Base64.getDecoder().decode(privateK);
		byte[] publicBytes = Base64.getDecoder().decode(publicK);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));
	}
	private void createSignatures() throws InvalidKeyException {
		signSig.initSign(privateKey);
		verifySig.initVerify(publicKey);
	}
	private String encrypt(String original){
		try {
			Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encrypted = cipher.doFinal(original.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception ex) {
			//logErr("Error in encryption");
			System.exit(63);
		}
		return null;
	}
	private String decrypt (String message) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] original = cipher.doFinal(Base64.getDecoder().decode(message));
			return new String(original);
		} catch (Exception ex) {
			//logErr("Error in decryption");
			System.exit(63);
		}
		return null;
	}
	private String signMessage(String message) throws SignatureException {
		signSig.update(Base64.getDecoder().decode(message));
		String sig = Base64.getEncoder().encodeToString(signSig.sign());
		String outMsg = message + "," + sig;
		return outMsg;
	}
	private boolean verify (String signature, String data) {
		try {
			verifySig.update(Base64.getDecoder().decode(data));
			return verifySig.verify(Base64.getDecoder().decode(signature));
		} catch (SignatureException e) {
			//logErr("Error in verify");
			System.exit(63);
		}
		return false;
	}
	private void log(String text) {
		System.out.println(text);
		System.out.flush();
	}
	public static void main(String[] args) {
		int debug = 0;
		//Initialize arg variables
		String authFileName = "bank.auth";
		String cardFileName = null; //Default: <account name>.card
		String accountName = null; //Required
		String ip = "127.0.0.1";
		int port = 3000;
		boolean hasA=false,hasS=false,hasC=false,hasI=false,hasP=false;
		String operation = null;
		double operationAmnt = 0.00;
		int operations = 0;
		//Process args
		for (int i=0; i < args.length; i++) {
			if (args[i].length() > 4096) System.exit(255);
			if (args[i].charAt(0) == '-') {
				boolean optionWithArg = false; //Exit loop if we have to find an option-value for an arg
				for (int j=1; j<args[i].length() && !optionWithArg; j++) { //j=1 skips -
					if (args[i].charAt(j) == 's') {
						//Set Auth file
						optionWithArg = true;
						//Check for -s -s
						if (hasS) System.exit(255);
						hasS = true;
						if (args[i].length() != j+1) {
							//treat rest of args[i] as arg/option-value
							authFileName = args[i].substring(j+1);
						}
						else {
							boolean found = false;
							while (i < args.length && !found) {
								i++;
								if (!args[i].equals("") && !args[i].equals(" ")) { //skip whitespace
									found = true;
									authFileName = args[i];
								}
							}
							if (!found) System.exit(255);
						}
					}
					else if (args[i].charAt(j) == 'a') {
						//Set account name
						optionWithArg = true;
						//Check for -a -a
						if (hasA) System.exit(255);
						hasA = true;
						if (args[i].length() != j+1) {
							//treat rest of args[i] as arg/option-value
							accountName = args[i].substring(j+1);
						}
						else {
							boolean found = false;
							while (i < args.length && !found) {
								i++;
								if (!args[i].equals("") && !args[i].equals(" ")) {
									found = true;
									accountName = args[i];
								}
							}
							if (!found) System.exit(255);
						}
					}
					else if (args[i].charAt(j) == 'c') {
						//Set card file
						optionWithArg = true;
						if (hasC) System.exit(255);
						hasC = true;
						if (args[i].length() != j+1) {
							//treat rest of args[i] as arg/option-value
							cardFileName = args[i].substring(j+1);
						}
						else {
							boolean found = false;
							while (i < args.length && !found) {
								i++;
								if (!args[i].equals("") && !args[i].equals(" ")) {
									found = true;
									cardFileName = args[i];
									j = args[i].length();
								}
							}
							if (!found) System.exit(255);
						}
					}
					else if (args[i].charAt(j) == 'i') {
						//Set ip
						optionWithArg = true;
						if (hasI) System.exit(255);
						hasI = true;
						if (args[i].length() != j+1) {
							//treat rest of args[i] as arg/option-value
							ip = args[i].substring(j+1);
						}
						else {
							boolean found = false;
							while (i < args.length && !found) {
								i++;
								if (!args[i].equals("") && !args[i].equals(" ")) {
									found = true;
									ip = args[i];
								}
							}
							if (!found) System.exit(255);
						}
					}
					else if (args[i].charAt(j) == 'p') {
						//Set port
						optionWithArg = true;
						if (hasP) System.exit(255);
						hasP = true;
						if (args[i].length() != j+1) {
							//treat rest of args[i] as arg/option-value
							//Check valid port string
							if (!(args[i].substring(j+1)).matches("(0|[1-9][0-9]*)")) System.exit(255);
							port = Integer.parseInt(args[i].substring(j+1));
						}
						else {
							boolean found = false;
							while (i < args.length && !found) {
								i++;
								if (!args[i].equals("") && !args[i].equals(" ")) {
									found = true;
									try {
										if (!args[i].matches("(0|[1-9][0-9]*)")) System.exit(255);
										port = Integer.parseInt(args[i]);
									}
									catch(NumberFormatException e) {
										System.exit(255);
									}
								}
							}
							if (!found) System.exit(255);
						}
					}
					//Operation
					else if (args[i].charAt(j) == 'g') {
						operations++;
						operation = "getBalance";
					}
					else if (args[i].charAt(j) == 'n') {
						operations++;
						operation = "newAccount";
						optionWithArg = true;
						if (args[i].length() != j+1) {
							//treat rest of args[i] as arg/option-value
							try {
								if (!(args[i].substring(j+1)).matches("^(0|[1-9][0-9]*)\\.[0-9]{2}$") ) System.exit(255);
								operationAmnt = Double.parseDouble(args[i].substring(j+1));
							}
							catch(NumberFormatException e) {
								System.exit(255);
							}
						}
						else {
							boolean found = false;
							while (i < args.length && !found) {
								i++;
								if (!args[i].equals("") && !args[i].equals(" ")) {
									found = true;
									try {
										if (!(args[i]).matches("^(0|[1-9][0-9]*)\\.[0-9]{2}$") ) System.exit(255);
										operationAmnt = Double.parseDouble(args[i]);
									}
									catch(NumberFormatException e) {
										System.exit(255);
									}
								}
							}
							if (!found) System.exit(255);
						}
						if (operationAmnt < 10.00) System.exit(255);
					}
					else if (args[i].charAt(j) == 'd') {
						operations++;
						operation = "deposit";
						optionWithArg = true;
						if (args[i].length() != j+1) {
							//treat rest of args[i] as arg/option-value
							try {
								if (!(args[i].substring(j+1)).matches("^(0|[1-9][0-9]*)\\.[0-9]{2}$") ) System.exit(255);
								operationAmnt = Double.parseDouble(args[i].substring(j+1));
							}
							catch(NumberFormatException e) {
								System.exit(255);
							}
						}
						else {
							boolean found = false;
							while (i < args.length && !found) {
								i++;
								if (!args[i].equals("") && !args[i].equals(" ")) {
									found = true;
									try {
										if (!(args[i]).matches("^(0|[1-9][0-9]*)\\.[0-9]{2}$") ) System.exit(255);
										operationAmnt = Double.parseDouble(args[i]);
									}
									catch(NumberFormatException e) {
										System.exit(255);
									}
								}
							}
							if (!found) System.exit(255);
						}
						if (operationAmnt <= 0.00) System.exit(255);
					}
					else if (args[i].charAt(j) == 'w') {
						operations++;
						operation = "withdraw";
						optionWithArg = true;
						if (args[i].length() != j+1) {
							//treat rest of args[i] as arg/option-value
							try {
								if (!(args[i].substring(j+1)).matches("^(0|[1-9][0-9]*)\\.[0-9]{2}$") ) System.exit(255);
								operationAmnt = Double.parseDouble(args[i].substring(j+1));
							}
							catch(NumberFormatException e) {
								System.exit(255);
							}
						}
						else {
							boolean found = false;
							while (i < args.length && !found) {
								i++;
								if (!args[i].equals("") && !args[i].equals(" ")) {
									found = true;
									try {
										if (!(args[i]).matches("^(0|[1-9][0-9]*)\\.[0-9]{2}$") ) System.exit(255);
										operationAmnt = Double.parseDouble(args[i]);
									}
									catch(NumberFormatException e) {
										System.exit(255);
									}
								}
							}
							if (!found) System.exit(255);
						}
						if (operationAmnt <= 0.00) System.exit(255);
					}
					else {
						//invalid option
						System.exit(255);
					}
					//Fail if multiple operations
					if (operations > 1) System.exit(255);
				}
			}
			else {
				//Bug or invalid input (args without a - should be consumed when processing the previous arg)
				System.exit(255);
			}
		}
		//Validity check(s)
		if (operations != 1 || operation == null) System.exit(255);
		if (port < 1024 || port > 65535) System.exit(255);
		if (accountName.length() < 1 || accountName.length() > 250 || !accountName.matches("[_\\-\\.0-9a-z]+")) System.exit(255);
		if (operation != "getBalance") {
			if (operationAmnt < 0.00 || operationAmnt > 4294967295.99) System.exit(255);
		}
		if (cardFileName == null) {
			cardFileName = accountName+".card";
		}
		if (cardFileName.equals(".") || cardFileName.equals("..") || !cardFileName.matches("^[_\\-\\.0-9a-z]+$") || cardFileName.length() > 255 || cardFileName.length() < 1) System.exit(255);
		if (authFileName.equals(".") || authFileName.equals("..") || !authFileName.matches("^[_\\-\\.0-9a-z]+$") || authFileName.length() > 255 || authFileName.length() < 1) System.exit(255);
		//Check IP
		Pattern pattern = Pattern.compile("^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$");
		Matcher matcher = pattern.matcher(ip);
		if (!matcher.find()) System.exit(255); //Run the regex and exit if not a match
		for (int matches=1; matches < matcher.groupCount() + 1; matches++) { //0 is the whole string and is not included in groupCount
			try {
				if (Integer.parseInt(matcher.group(matches)) > 255) System.exit(255);
			}
			catch(NumberFormatException e) { //Should never be triggered because of the regex
				System.exit(255);
			}
		}
		//End Check IP
		if (debug >= 1) {
			System.err.println("DEBUG: arg parse results:---------");
			System.err.println(authFileName);
			System.err.println(cardFileName);
			System.err.println(accountName);
			System.err.println(ip);
			System.err.println(port);
			System.err.println(operation);
			System.err.println(operationAmnt);
			System.err.println(operations);
			System.err.println("----------------------------------");
		}
		//Set up ATM instance and run operation
		Atm atm = new Atm(accountName, authFileName, ip, port, cardFileName);
        switch (operation) {
            case "getBalance":
                atm.log("{\"account\":\"" + accountName + "\",\"balance\":" + atm.getBalance() + "}");
                break;
            case "newAccount":
                atm.log("{\"account\":\"" + accountName + "\",\"initial_balance\":" + atm.newAccount(operationAmnt) + "}");
                break;
            case "withdraw":
                atm.log("{\"account\":\"" + accountName + "\",\"withdraw\":" + atm.withdraw(operationAmnt) + "}");
                break;
            case "deposit":
                atm.log("{\"account\":\"" + accountName + "\",\"deposit\":" + atm.deposit(operationAmnt) + "}");
                break;
        }
	}
}