package org.radix.card;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacard.security.KeyPair;
import javacardx.apdu.ExtendedLength;

/**
 * Basic implementation of a JavaCard applet that is compatible with Radix Atom stack and cryptographic policies.
 * <p>
 * It supports the generation / injection of keys derived from the Secp256k1 curve, signing, verification, hashing of messages and basic PIN functionality.
 * <p>
 * The applet is for demonstration purposes only and is not purposed for commercial deployments nor designed to meet the security rigours of EMV or other standards.
 * <p>
 * To install the applet onto cards, Global Platform Pro can be used using the default AID of - DEADBEEF7900
 * 
 * @author Dan Hughes
 */
public class Radix_Card_POC extends Applet implements ExtendedLength
{
    // EXTENDED ERROR CODES NOT PRESENT IN javacard.framework.ISO7816
    final static short  SW_INVALID_KEY_LENGTH = 0x6389;
    final static short  SW_PIN_VERIFICATION_FAILED_THREEPLUS = (short) 0x9704;
    final static short  SW_PIN_VERIFICATION_FAILED_TWO = (short) 0x9A04;
    final static short  SW_PIN_VERIFICATION_FAILED_ONE = (short) 0x9904;
    final static short  SW_PIN_BLOCKED = (short) 0x9F04;

    // APPLET SPECIFIC ERROR CODES
    final static short  SW_VERIFICATION_FAILED = 0x6300;
    final static short  SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    final static short  SW_SIGNATURE_CREATION_FAILED = 0x6302;
    final static short  SW_SIGNATURE_VERIFICATION_FAILED = 0x6303;
    final static short  SW_PIN_NOT_PROVIDED = 0x6304;
    final static short  SW_MASTER_PIN_INVALID_LENGTH = 0x6305;
    final static short  SW_USER_PIN_INVALID_LENGTH = 0x6306;
    
    // INSTRUCTIONS
    final static byte   RADIX_CLA 	= (byte) 0xB0;
    final static byte   AUTHORISE       = (byte) 0x20;
    final static byte   PUBLIC_KEY      = (byte) 0x30;
    final static byte   PRIVATE_KEY 	= (byte) 0x40;
    final static byte   SIGN_MESSAGE    = (byte) 0x50;
    final static byte   VERIFY_MESSAGE  = (byte) 0x60;
    final static byte   HASH_MESSAGE    = (byte) 0x70;
    final static byte   CONFIGURE_AUTH  = (byte) 0x80;
    final static byte   STATUS          = (byte) 0xF0;
    
    // PARAMETERS 
    final static byte   INSTALL_KEYS_NOT_PROVIDED = (byte) 0x00;
    final static byte   INSTALL_KEYS_PROVIDED = (byte) 0x01;
    final static byte   USER_PIN        = (byte) 0x00;
    final static byte   MASTER_PIN      = (byte) 0x01;
    final static byte   COMPRESSED_KEY  = (byte) 0x01;
    final static byte   UNCOMPRESSED_KEY  = (byte) 0x00;
	
    final static byte   PIN_TRY_LIMIT   = (byte)0x03;
    final static byte   MIN_PIN_SIZE 	= (byte)0x04;
    final static byte   MAX_PIN_SIZE 	= (byte)0x0A;
    
    // MEMBER VARIABLES //
    OwnerPIN            userPIN;
    OwnerPIN            masterPIN;
    KeyPair             key;
    
    // WORKING VARIABLES 
    byte[]              scratch;
    Signature           signer;
    MessageDigest       digester;

	
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
    public static void install(byte[] bArray, short bOffset, byte bLength) 
    {
    	byte aidLen = bArray[bOffset]; // aid length
    	bOffset = (short) (bOffset+aidLen+1);
    	byte infoLen = bArray[bOffset]; // info length
    	bOffset = (short) (bOffset+infoLen+1);
		
    	new Radix_Card_POC(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /**
     * Only this class's install method should create the applet object.
     * <p>
     * Install parameter format is as follows:
     * <ul>
     * <li>1 byte declaration of key provisioning type
     * <ul>
     * <li> 0 - delares keys are not provided and should be generated 
     * <li> 1 - delares keys are provided within install parameters
     * </ul>
     * <li>1 byte user PIN length
     * <li>n byte user PIN
     * <li>1 byte master PIN length
     * <li>n byte master PIN
     * <li>1 byte private key length
     * <li>n byte private key
     * <li>1 byte public key length
     * <li>n byte public key (uncompressed)
     * </ul>
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    protected Radix_Card_POC(byte[] bArray, short bOffset, byte bLength) 
    {
        try
        {
            boolean keysProvided = bArray[bOffset++] == INSTALL_KEYS_PROVIDED ? true : false;
            
            // Extract USER PIN length from parameters and assert
            byte userPinLength = (byte) bArray[bOffset++];
            if (userPinLength < MIN_PIN_SIZE || userPinLength > MAX_PIN_SIZE)
            	ISOException.throwIt(SW_USER_PIN_INVALID_LENGTH);
            
            // Create the USER PIN object
            this.userPIN = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
            this.userPIN.update(bArray, bOffset, userPinLength);
            bOffset += userPinLength;
            
            // Extract MASTER PIN length from parameters and assert
            byte masterPinLength = (byte)bArray[bOffset++];
            if (masterPinLength < MIN_PIN_SIZE || masterPinLength > MAX_PIN_SIZE)
            	ISOException.throwIt(SW_MASTER_PIN_INVALID_LENGTH);

            // Create the MASTER PIN object
            this.masterPIN = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
            this.masterPIN.update(bArray, bOffset, masterPinLength);
            bOffset += masterPinLength;
            
            // Initialize a ECPrivateKey with the secp256k1 curve
            ECPrivateKey privateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
            Secp256k1.setCommonCurveParameters(privateKey);
            
            // Initialize a ECPublicKey with the secp256k1 curve
            ECPublicKey publicKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 256, false);
            Secp256k1.setCommonCurveParameters(publicKey);
            
            // Construct a KeyPair containing the private and public keys
            this.key = new KeyPair(publicKey, privateKey);

            // If the keys are provided in the parameters then we wish to extract them
            if (keysProvided == true)
            {
                byte privLength = (byte)bArray[bOffset++];
                // Private key can not be larger than 32 bytes (256 bit)
                if (privLength > 32)
                    ISOException.throwIt(SW_INVALID_KEY_LENGTH);

                privateKey.setS(bArray, bOffset, privLength);
                bOffset += privLength;

                byte pubLength = (byte)bArray[bOffset++];
                // Uncompressed public keys only are supported, throw on compressed public keys
                if (bArray[bOffset] != 0x04)
                    ISOException.throwIt(SW_INVALID_KEY_LENGTH);
                
                publicKey.setW(bArray, bOffset, pubLength);
                bOffset += pubLength;
            }
            else
            {
                // Keys are NOT provided in the parameters, so generate them using the secure PRNG on the card
                this.key.genKeyPair();
            }

            // Construct a transient 256 byte scratch buffer
            this.scratch = JCSystem.makeTransientByteArray((short)256, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
            
            // Construct an ECDSA compatible signer using SHA256
            this.signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

            // Construct a SHA256 message digester
            this.digester = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        }
        catch (CryptoException cex)
	{
	    short reason = cex.getReason();
				
            if (reason != 0)
            	ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        
        register();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    public void process(APDU apdu) 
    {
    	if (selectingApplet())
            return;

    	byte[] APDUBuffer = apdu.getBuffer();

    	// check SELECT APDU command
    	if ((APDUBuffer[ISO7816.OFFSET_CLA] == 0) && (APDUBuffer[ISO7816.OFFSET_INS] == (byte) 0xA4)) 
            return;
			
    	// verify the rest of commands have the correct CLA byte, which specifies the command structure
    	if (APDUBuffer[ISO7816.OFFSET_CLA] != RADIX_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

    	// process the APDU instruction
    	switch (APDUBuffer[ISO7816.OFFSET_INS]) 
    	{
            case PUBLIC_KEY: 
        	getPublicKey(apdu);
        	return;
            case PRIVATE_KEY: 
                getPrivateKey(apdu);
        	return;
            case AUTHORISE: 
            	authorise(apdu);
            	return;
            case CONFIGURE_AUTH: 
            	configureAuth(apdu);
            	return;
            case SIGN_MESSAGE: 
            	signMessage(apdu);
            	return;
            case VERIFY_MESSAGE: 
            	verifyMessage(apdu);
            	return;
            case HASH_MESSAGE: 
            	hashMessage(apdu);
            	return;
            case STATUS: 
            	status(apdu);
            	return;
            default: 
            	ISOException.throwIt (ISO7816.SW_INS_NOT_SUPPORTED);
    	}
    }
   
    public boolean select() 
    {
        // If the master and user PINs have no tries remaining then the applet is blocked and unusable
    	if (this.masterPIN.getTriesRemaining() == 0 && this.userPIN.getTriesRemaining() == 0) 
            return false;
			
    	return true;
    }
	
    public void deselect() 
    {
        this.masterPIN.reset();
        this.userPIN.reset();
    }
    
    /**
     * Authorises use of the card via either the user or master PIN.
     * <p>
     * In the event that the number of attempts against the user PIN exceeds the retry limit, it can be unblocked via a successful authorisation 
     * of the master PIN.  Should the number of attempts against the master PIN exceeds the retry limit, the card becomes unusable.
     * <ul>
     * <li>APDU.P1 = 0 - declares a user PIN is provided
     * <li>APDU.P1 = 1 - declares a master PIN is provided
     * <li>APDU.P2 = UNUSED
     * <li>APDU.CDATA = the PIN
     * </ul>
     * @param apdu
     *            the APDU containing authorisation parameters and PIN
     *            
     * @throws ISOException
     *
     */
    private void authorise(APDU apdu) 
    {
        byte[] APDUBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        
        if (bytesRead == 0)
            ISOException.throwIt(Radix_Card_POC.SW_PIN_NOT_PROVIDED);          
        
        PIN PIN = null;
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] == USER_PIN)
            PIN = this.userPIN;
        else if (apdu.getBuffer()[ISO7816.OFFSET_P1] == MASTER_PIN)
            PIN = this.masterPIN;
        else
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        
        validatePIN(PIN, APDUBuffer, apdu.getOffsetCdata(), (byte) bytesRead);
    }
	
    /**
     * Configures authorisation parameters of the card.
     * <p>
     * Configuring the authorisation parameters of the card requires a successful authorisation of the master PIN.  The user or master PIN can then be modified to new values.
     * <ul>
     * <li>APDU.P1 = 0 - declares the user PIN is to be modified
     * <li>APDU.P1 = 1 - declares the master PIN is to be modified
     * <li>APDU.P2 = UNUSED
     * <li>APDU.CDATA = the master PIN and new value for the PIN declared in APDU.P1 in the format
     * <ul>
     * <li>1 byte master PIN length
     * <li>n byte master PIN
     * <li>1 bytes new PIN length
     * <li>n byte new PIN
     * </ul>
     * </ul>
     * @param apdu
     *            the APDU containing modification parameters, the master PIN and the new PIN
     *            
     * @throws ISOException
     *
     */
    private void configureAuth(APDU apdu) 
    {
        byte[] APDUBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        
        if (bytesRead == 0)
            ISOException.throwIt(Radix_Card_POC.SW_PIN_NOT_PROVIDED);          
        
        OwnerPIN PIN = null;
        if (APDUBuffer[ISO7816.OFFSET_P1] == USER_PIN)
            PIN = this.userPIN;
        else if (APDUBuffer[ISO7816.OFFSET_P1] == MASTER_PIN)
            PIN = this.masterPIN;
        else
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);          

        // Validate master PIN
        short PINStart = (short) (apdu.getOffsetCdata() + (short) 1);
        byte  PINLength = APDUBuffer[apdu.getOffsetCdata()];
        validatePIN(this.masterPIN, APDUBuffer, PINStart, PINLength);

        short newPINStart = (short) (apdu.getOffsetCdata() + APDUBuffer[apdu.getOffsetCdata()] + (short) 2);
        byte  newPINLength = APDUBuffer[(short) (apdu.getOffsetCdata() + APDUBuffer[apdu.getOffsetCdata()] + (short) 1)];
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] == USER_PIN && (newPINLength < MIN_PIN_SIZE || newPINLength > MAX_PIN_SIZE))
            ISOException.throwIt(SW_USER_PIN_INVALID_LENGTH);
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] == MASTER_PIN && (newPINLength < MIN_PIN_SIZE || newPINLength > MAX_PIN_SIZE))
            ISOException.throwIt(SW_MASTER_PIN_INVALID_LENGTH);

        // Update requested PIN
        PIN.update(APDUBuffer, newPINStart, newPINLength);
    }
    
    private void validatePIN(PIN PIN, byte[] buffer, short offset, byte length)
    {
        if (PIN.isValidated() == false)
        {
            if (PIN.check(buffer, offset, length) == false)
            {
                switch (PIN.getTriesRemaining())
                {
                    case 0:
                        ISOException.throwIt(Radix_Card_POC.SW_PIN_BLOCKED);
                    case 1:
                        ISOException.throwIt(Radix_Card_POC.SW_PIN_VERIFICATION_FAILED_ONE);
                    case 2:
                        ISOException.throwIt(Radix_Card_POC.SW_PIN_VERIFICATION_FAILED_TWO);
                    default:
                        ISOException.throwIt(Radix_Card_POC.SW_PIN_VERIFICATION_FAILED_THREEPLUS);
                }
            }
            else if (PIN == this.masterPIN)
                this.userPIN.resetAndUnblock();
        }
    }

    /**
     * Gets the public key from the card.
     * <ul>
     * <li>APDU.P1 = 0 - requests an uncompressed public key
     * <li>APDU.P1 = 1 - requests a compressed public key
     * <li>APDU.P2 = UNUSED
     * <li>APDU.CDATA = UNUSED
     * </ul>
     * @param apdu
     *            the APDU containing request parameters
     *            
     * @throws ISOException
     *
     */
    private void getPublicKey(APDU apdu) 
    {
        byte[] APDUBuffer = apdu.getBuffer();
        
        // Public keys are stored in their uncompressed form, convert it if compressed a public key is requested.
        if (APDUBuffer[ISO7816.OFFSET_P1] == COMPRESSED_KEY)
        {
            // Copy the uncompressed public key to the scratch buffer
            short pubLength = ((ECPublicKey)this.key.getPublic()).getW(this.scratch, (short) 0);
            
            // Set APDU to outgoing mode
            if (apdu.setOutgoing() < (short) ((pubLength / (short) 2) + (short) 1)) 
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            // Positive Y
            if ((this.scratch[(short) (pubLength-1)] & 0x01) == 0)
                APDUBuffer[0] = (byte) 0x02;
            // Negative Y
            else
                APDUBuffer[0] = (byte) 0x03;

            // Trim the uncompressed public key and copy to the APDU buffer
            Util.arrayCopy(this.scratch, (short) 1, APDUBuffer, (short) 1, (short) (pubLength / (short) 2));
            apdu.setOutgoingLength((short) ((pubLength / (short) 2) + (short) 1));
            apdu.sendBytes((short)0, (short) ((pubLength / (short) 2) + (short) 1));
        }
        else
        {
            // Copy the uncompressed public key to the APDU buffer and send
            short pubLength = ((ECPublicKey)this.key.getPublic()).getW(this.scratch, (short) 0);

            // Set APDU to outgoing mode
            if (apdu.setOutgoing() < pubLength) 
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            Util.arrayCopy(this.scratch, (short) 0, APDUBuffer, (short) 0, pubLength);
            apdu.setOutgoingLength((short)(pubLength));
            apdu.sendBytes((short)0, (short)(pubLength));
        }
    }

    /**
     * Gets the private key from the card.
     * <p>
     * Requires that a successful authorisation has been performed with the master PIN.
     * <ul>
     * <li>APDU.P1 = UNUSED
     * <li>APDU.P2 = UNUSED
     * <li>APDU.CDATA = UNUSED
     * </ul>
     * @param apdu
     *            the APDU containing request parameters
     *            
     * @throws ISOException
     *
     */
    private void getPrivateKey(APDU apdu) 
    {
    	// Ensure that the master PIN has been validated
        if (this.masterPIN.isValidated() == false) 
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);		

        byte[] APDUBuffer = apdu.getBuffer();

        // Copy the private key to the APDU buffer and send
        short privLength = ((ECPrivateKey)this.key.getPrivate()).getS(APDUBuffer, (short) 0);

        // Set APDU to outgoing mode
        if (apdu.setOutgoing() < privLength) 
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        apdu.setOutgoingLength(privLength);
        apdu.sendBytes((short) 0, privLength);
    }
    
    /**
     * Signs a message payload with the private key on the card.
     * <p>
     * Requires that a successful authorisation has been performed with either the master or user PIN.
     * <p>
     * The current standard API for JavaCards do not support the signing of a pre-computed message digest, and perform a hash internally of the message payload to be signed prior to signing.  Therefore we have to transfer the message payload to the card.
     * <p>
     * Large message payloads of up to 65KB will utilise the EXTENDED_APDU protocol.  If EXTENDED_APDU is not supported by the card, an ISOException will throw.
     * <p>
     * A further consideration is that we would like to have our message data "double hashed" to guard against pre-image attacks and other security concerns.  The message data 
     * undergoes a first round of hashing prior to signing, and the second round is performed by the signing functions taking advantage of the limitations of the standard API. 
     * <ul>
     * <li>APDU.P1 = UNUSED
     * <li>APDU.P2 = UNUSED
     * <li>APDU.CDATA = the message payload to sign
     * </ul>
     * @param apdu
     *            the APDU containing request parameters
     *            
     * @throws ISOException
     *
     */
    private void signMessage(APDU apdu)
    {
    	// Ensure that either the user PIN or master PIN has been validated
        if (this.userPIN.isValidated() == false && this.masterPIN.isValidated() == false) 
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);		
        
        byte[] APDUBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        
        // Reset the digester instance and update it with the message payload.
        // Message payloads that are larger than the card's internal data buffer will take advantage of 
        // the EXTENDED_APDU protocol to stream the message payload to the digetser in blocks
        //
        // NOTE: Not all cards support EXTENDED_APDU!
        this.digester.reset();
        while (apdu.getCurrentState() == APDU.STATE_PARTIAL_INCOMING)
        {
            this.digester.update(APDUBuffer, apdu.getOffsetCdata(), bytesRead);
            bytesRead = apdu.receiveBytes(apdu.getOffsetCdata());
        }
        
        // Signal to the hash instance that the message data is now final and store the digest in the scratch buffer
        short digestLength = this.digester.doFinal(APDUBuffer, apdu.getOffsetCdata(), bytesRead, this.scratch, (short) 0);

        // Prepare the signer instance to sign our message digest  
        signer.init(this.key.getPrivate(), Signature.MODE_SIGN);
        
        // Sign the message digest, performing a second hash round in the process.
        short signatureLength = signer.sign(this.scratch, (short) 0, digestLength, APDUBuffer, (short) 0);

        // Set APDU to outgoing mode
        if (apdu.setOutgoing() < signatureLength) 
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        apdu.setOutgoingLength(signatureLength);
        apdu.sendBytes((short) 0, signatureLength);
    }
    
    /**
     * Verifies that a message payload has been signed with the private key on the card.
     * <p>
     * The current standard API for JavaCards do not support the verification of a pre-computed message digest, and perform a hash internally of the message payload to be verified prior to verification.  Therefore we have to transfer the message payload to the card.
     * <p>
     * Large message payloads of up to 65KB will utilise the EXTENDED_APDU protocol.  If EXTENDED_APDU is not supported by the card, an ISOException will throw.
     * <p>
     * A further consideration is that message payloads are "double hashed" to guard against pre-image attacks and other security concerns.  The message payload 
     * undergoes a first round of hashing prior to verification, and the second round is performed by the verification functions taking advantage of the limitations of the standard API. 
     * <ul>
     * <li>APDU.P1 = UNUSED
     * <li>APDU.P2 = UNUSED
     * <li>APDU.CDATA = the signature and message payload to verify in the format
     * <ul>
     * <li>1 byte signature length
     * <li>n byte signature
     * <li>2 bytes message payload length
     * <li>n byte message payload
     * </ul>
     * </ul>
     * @param apdu
     *            the APDU containing request parameters
     *            
     * @throws ISOException
     *
     */
    private void verifyMessage(APDU apdu)
    {
        byte[]  APDUBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        // Copy the signature from APDU buffer to the start of the scratch buffer
        short signatureLength = Util.makeShort((byte) 0, APDUBuffer[apdu.getOffsetCdata()]);
        Util.arrayCopy(APDUBuffer, (short) (apdu.getOffsetCdata() + (short) 1), this.scratch, (short) 0, signatureLength);

        // Reset the digester instance
        this.digester.reset();
        
        // Update the digester with the initial message payload after the signature from the APDU buffer
        this.digester.update(APDUBuffer, (short) (apdu.getOffsetCdata() + (signatureLength + (short) 3)), (short) (bytesRead - (signatureLength + (short) 3)));
        bytesRead = apdu.receiveBytes(apdu.getOffsetCdata());

        // Update the digester with the remaining message payload from the APDU buffer
        // Message payloads that are larger than the card's internal data buffer will take advantage of 
        // the EXTENDED_APDU protocol to stream the message payload to the digetser in blocks
        //
        // NOTE: Not all cards support EXTENDED_APDU!
        while (apdu.getCurrentState() == APDU.STATE_PARTIAL_INCOMING)
        {
            this.digester.update(APDUBuffer, apdu.getOffsetCdata(), bytesRead);
            bytesRead = apdu.receiveBytes(apdu.getOffsetCdata());
        }
        
        // Signal to the disgester that the message payload is now final and store the digest in the scratch buffer mafter the signature
        short digestLength = this.digester.doFinal(APDUBuffer, apdu.getOffsetCdata(), bytesRead, this.scratch, (short) signatureLength);

        // Prepare the signer instance to verify our message digest  
        signer.init(this.key.getPublic(), Signature.MODE_VERIFY);
        
        // Verify the message digest, performing a second hash round in the process.
        boolean verifyResult = this.signer.verify(this.scratch, signatureLength, digestLength, this.scratch, (short) 0, signatureLength);
        if (verifyResult == false)
            ISOException.throwIt(SW_SIGNATURE_VERIFICATION_FAILED);
    }

    /**
     * Hashes a message payload.
     * <p>
     * The message payload is "double hashed" to guard against pre-image attacks and other security concerns.  The message digest produced from the first round is then used as the message payload for the second round.
     * <p>
     * Large message payloads of up to 65KB will utilise the EXTENDED_APDU protocol.  If EXTENDED_APDU is not supported by the card, an ISOException will throw.
     * <ul>
     * <li>APDU.P1 = UNUSED
     * <li>APDU.P2 = UNUSED
     * <li>APDU.CDATA = the message payload to hash
     * </ul>
     * @param apdu
     *            the APDU containing request parameters
     *            
     * @throws ISOException
     *
     */
    private void hashMessage(APDU apdu) 
    {
        byte[]  APDUBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        
        // Reset the digester instance and update it with the message payload.
        // Message payloads that are larger than the card's internal data buffer will take advantage of 
        // the EXTENDED_APDU protocol to stream the message payload to the digetser in blocks
        //
        // NOTE: Not all cards support EXTENDED_APDU!
        this.digester.reset();
        while (apdu.getCurrentState() == APDU.STATE_PARTIAL_INCOMING)
        {
            this.digester.update(APDUBuffer, apdu.getOffsetCdata(), bytesRead);
            bytesRead = apdu.receiveBytes(apdu.getOffsetCdata());
        }
        
        // Signal to the hash instance that the message payload is now final and store the message digest in the scratch buffer
        short digestLength = this.digester.doFinal(APDUBuffer, apdu.getOffsetCdata(), (short) bytesRead, this.scratch, (short)0);

        // Perform a second round on the message digest present in the scratch buffer from the first round and store in the APDU buffer
        digestLength = this.digester.doFinal(this.scratch, (short) 0, digestLength, APDUBuffer, (short) 0);

        // Set APDU to outgoing mode
        if (apdu.setOutgoing() < digestLength) 
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // Send the message digest
        apdu.setOutgoingLength(digestLength);
        apdu.sendBytes((short)0, digestLength);
    }

    /**
     * Gets the card version and memory status
     * 
     * <ul>
     * <li>APDU.P1 = UNUSED
     * <li>APDU.P2 = UNUSED
     * <li>APDU.CDATA = UNUSED
     * </ul>
     * @param apdu
     *            the APDU containing request parameters
     *            
     * @throws ISOException
     *
     */
    private void status(APDU apdu)
    {
        byte[]  APDUBuffer = apdu.getBuffer();

        // Set APDU to outgoing mode
        if (apdu.setOutgoing() < (short) 8) 
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        short bOffset = 0;
        
        Util.setShort(APDUBuffer, bOffset, JCSystem.getVersion());
        bOffset += 2;
        Util.setShort(APDUBuffer, bOffset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
        bOffset += 2;
        Util.setShort(APDUBuffer, bOffset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
        bOffset += 2;
        Util.setShort(APDUBuffer, bOffset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));

        apdu.setOutgoingLength((short) 8);
        apdu.sendBytes((short) 0, (short) 8);
    }
}
