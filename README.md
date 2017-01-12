# ATM_Protocol


Action 1 - New Account, the message should look like [ActionNum, AuthFile, CardFile, accountName, amount]


Action 2 - Deposit, the message should look like [ActionNum, CardFileName, accountName, amount]


Action 3 - Withdraw, the message should look like [ActionNum, CardFileName, accountName, amount]


Action 4 - Get Balance, the message should look like [ActionNum, CardFileName, accountName]

Action 5 - undo [5, lastmessage]


KeyPair pair = keyGen.generateKeyPair();


PrivateKey priv = pair.getPrivate();


PublicKey pub = pair.getPublic();



Encryption Method for Card file

- Bank creates a key

- Bank double encrypts key

- Bank sends ATM double encryption

- ATM decrypts message once

- ATM creates a card file and stores the single encrypted message

- Anytime ATM sends card file it will essentially be sending over the single encrypted message which the bank will then decrypt to get the origal key. Bank compares the key that ATM sent over and the key that the bank originally created and gave to the ATM



Security Protocol for sending any kind of message (modified)

- use built in java api to create signature and to verify it

- encrypt with public key

- sign with private key



Security Attacks and counter attack methods


1. Input sanitization

2. Double Encryption of card file

3. Adding signature to message

4. Hashing Messages

5. Stack Overflow

6. Buffer Overflow

7. Heap Overflow

8. Asymmetric Keys

9. Add ramdomized integers to end of data but before signature to make sure the encrypted text always looks random




Security protocol steps

1. retrieve keys from auth file:
    the auth file will have this format:
        private key
        public key
        iv (you dont need this)


2. create signatures:
    two signatures needed, one for signing and one for verifying, initialize them.
    
- signingSignature.initSign(privateKey);  sign with PRIVATE key
    
- verifySignature.initVerify(publicKey);  verify with PUBLIC key


3. encrypting
    
- encrypting with public key
    
- create signature with signingSignature
    
- concat with ',' in between
    
- send


4. decrypting
    
- split(","); gives data at index 0, and signature at index 1
    
- verify with verifySignature
    
- if true, decrypt data with private key



Notes:
    
- the last part of the decrypted data is random string
    
- encrypting algorithm is "RSA" size 1024
    
- signing algorithm is "SHA256withRSA"


