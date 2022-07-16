using System.Diagnostics;
using PCSC;
using PCSC.Iso7816;
using Dahomey.Cbor;
using Dahomey.Cbor.ObjectModel;
using Jsbeautifier;
using Simulation;
using System.Security.Cryptography;
using System.Formats.Cbor;
using MySql.Data.MySqlClient;
using System.Data;
using System.Text;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Asn1.Nist;

namespace FidoReader
{
	public partial class Form1 : Form
	{
		Beautifier beautifier = new Beautifier();
		ISCardContext pcscContext;
		IsoReader pcscReader;
		string[] readers;
		byte[] Cx;

		public Form1()
		{
			InitializeComponent();
            pcscContext = ContextFactory.Instance.Establish(SCardScope.User);
            readers = pcscContext.GetReaders();
            pcscReader = new IsoReader(context: pcscContext, readerName: readers[0], mode: SCardShareMode.Shared, protocol: SCardProtocol.Any);
            dumpReaders(readers);
        }

		private void dumpReaders(string[] readers) {
			foreach (var item in readers) {
				Debug.WriteLine(item);
			}
			string readerName = readers[0];
			if (readerName == null) {
				Debug.WriteLine("no reader");
				return;
			}
			Debug.WriteLine(readerName);
		}

		private Response executecCommand(CommandApdu commandApdu) {
			string commandStirng = BitConverter.ToString(commandApdu.ToArray());
			Debug.WriteLine(commandStirng);
			APDUbox.Text += ">> " + commandStirng + "\r\n";

			Response commandResponse = pcscReader.Transmit(commandApdu);
			string statusWord = commandResponse.StatusWord.ToString("X");
			APDUbox.Text += "<< " + statusWord + "\r\n";
			Debug.WriteLine(statusWord);

            try {
				byte[] data = commandResponse.GetData();
				string dataHexString = BitConverter.ToString(data);
				APDUbox.Text += "<< " + dataHexString + "\r\n";
				Debug.WriteLine(dataHexString);

				if (data[0] == 0) 
					Array.Copy(data, 1, data, 0, data.Length - 1);
				string? jsonString = Cbor.ToJson(data);
				string beautyString = beautifier.Beautify(jsonString).Replace("\n", "\r\n").Replace(", ",", \r\n");
				CBORbox.Text += beautyString + "\r\n";
				Debug.WriteLine(beautyString);
            } catch (Exception e) {
				Debug.WriteLine(e.ToString());
            }
			CBORbox.Text += "\r\n";
			return commandResponse;
		}
        
		private void clearWindow_Click(object sender, EventArgs e)
		{
			APDUbox.Clear();
			CBORbox.Clear();
			paramBox.Clear();
		}

        private void selectFIDOApplet_Click(object sender, EventArgs e)
		{
			var selectingCommnad = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol)
			{
				CLA = 0x00, INS = 0xA4, P1P2 = 0x0400, Data = new byte[] {0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01}
			};
			executecCommand(selectingCommnad);
		}

		private void getInfo_click(object sender, EventArgs e)
		{
            selectFIDOApplet_Click(sender, e);
            var getInfoCommnad = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0x10,
				P1P2 = 0x0000,
				Data = new byte[] { 0x04 }
			};
			
			executecCommand(getInfoCommnad);
		}

		private void getAttestationPublicKey_Click(object sender, EventArgs e) {
			selectFIDOApplet_Click(sender, e);
			var getAttestationPublicKeyCommand = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0x10,
				P1P2 = 0x0000,
				Data = new byte[] { 0x44 }
			};
			executecCommand(getAttestationPublicKeyCommand);
		}

        private void dumpIDSecret_Click(object sender, EventArgs e) {
			selectFIDOApplet_Click(sender, e);
			var dumpIDSecretCommand = new CommandApdu(IsoCase.Case4Extended, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0x10,
				P1P2 = 0x0000,
				Data = new byte[] { 0x5F }
			};
			Response commandResponse = executecCommand(dumpIDSecretCommand);
			byte[] data = commandResponse.GetData();
			if (data == null)
				return;
			CborReader cborReader = new CborReader(data);
			int? length = cborReader.ReadStartMap();
			while (length > 0) {
				switch (cborReader.ReadTextString()) {
					case "Cx":
						this.Cx = cborReader.ReadByteString();
						break;
					case "PuKp":
						byte[] PuKp = cborReader.ReadByteString();
						Debug.WriteLine(BitConverter.ToString(PuKp));
						break;
					case "sharedSecret":
						byte[] sharedSecret = cborReader.ReadByteString();
						Debug.WriteLine(BitConverter.ToString(sharedSecret));
						break;
					case "TEMP":
						Debug.WriteLine("TEMP : "+BitConverter.ToString(cborReader.ReadByteString()).Replace("-",""));
						break;
					default:
						break;
				}
				length--;
			}

			//cborReader.ReadTextString(); // key
			//string IDx = cborReader.ReadTextString();
			//cborReader.ReadTextString(); // key
			//byte[] Rx = cborReader.ReadByteString();
			//cborReader.ReadTextString(); // key
			//byte[] Rp = cborReader.ReadByteString();
			//cborReader.ReadTextString(); // key
			//byte[] RxRp = cborReader.ReadByteString();
			//cborReader.ReadTextString(); // key
			//byte[] PuKp = cborReader.ReadByteString();
			//cborReader.ReadTextString(); // key
			//byte[] sharedSecrect = cborReader.ReadByteString();
			//cborReader.ReadTextString(); // key
			//byte[] aesRawKey = cborReader.ReadByteString();
			//cborReader.ReadTextString(); // key
			//byte[] Cx = cborReader.ReadByteString();
			//cborReader.ReadTextString(); // key
			//byte[] encryptedCx = cborReader.ReadByteString();

			//this.Cx = Cx;
			//Debug.WriteLine(BitConverter.ToString(PuKp));
			//Debug.WriteLine(BitConverter.ToString(sharedSecrect));
		}

        private void getPuKxRx_Click(object sender, EventArgs e) {
			selectFIDOApplet_Click(sender, e);
			var getPuKxRxCommand = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0x10,
				P1P2 = 0x0000,
				Data = new byte[] { 0x50 , (byte)'P', (byte)'R', (byte)'L', (byte)'a', (byte)'b' }
			};
			executecCommand(getPuKxRxCommand);
		}
		

		private void getCx_Click(object sender, EventArgs e) {
			//ECCurve curve = ECCurve.NamedCurves.nistP256;
			
		}


		private void getPuKxCx_Click(object sender, EventArgs e) {
			if (IDxBox.Text == "") {
				MessageBox.Show("IDx not set");
				return;
			}
            #region mysql connecting
            string connectString = "server=127.0.0.1;port=3306;user id=IDP;password=idppasswd;database=idp;charset=utf8;";
			MySqlConnection mySqlConnection = new MySqlConnection(connectString);
			if (mySqlConnection.State != ConnectionState.Open) {
                try {
					mySqlConnection.Open();
                } catch (Exception ex) {
					MessageBox.Show(ex.Message);
					Debug.WriteLine(ex.Message);
					return;
                }
			}
            #endregion

            selectFIDOApplet_Click(sender, e);

			string IDx = IDxBox.Text;

			ECDiffieHellmanCng ECDH = new ECDiffieHellmanCng();
			ECDH.HashAlgorithm = CngAlgorithm.Sha1;
			ECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
			ECDH.GenerateKey(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);// also named secp256r1
			byte[] publicKey = ECDH.PublicKey.ToByteArray();
			byte[] privateKey = ECDH.ExportECPrivateKey();
			
			paramBox.Text += "PuKp : " + BitConverter.ToString(publicKey) + "\r\n";
			
			Debug.WriteLine(BitConverter.ToString(publicKey));
			Debug.WriteLine(BitConverter.ToString(privateKey));

            #region construct cbor command
            CborWriter cborWriter = new CborWriter();
			cborWriter.WriteStartArray(2);
			cborWriter.WriteTextString(IDx);
			cborWriter.WriteByteString(publicKey);
			cborWriter.WriteEndArray();
			byte[] encodedCbor = cborWriter.Encode();
			Debug.WriteLine(BitConverter.ToString(encodedCbor));

			byte[] data = new byte[encodedCbor.Length+1];
			data[0] = 0x52;
			Array.Copy(encodedCbor, 0, data, 1, encodedCbor.Length);
			var getPuKxCxCommand = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0x10,
				P1P2 = 0x0000,
				Data = data
			};
            #endregion

            Response commandResponse = executecCommand(getPuKxCxCommand);

			data = commandResponse.GetData();
			if (data == null) {
				return;
			}

            #region extract public key x and Cx
            CborReader cborReader = new CborReader(data);
			cborReader.ReadStartArray();
			// magic||length(in little endian)
			byte[] keyHeader = new byte[]{ 0x45,0x43,0x4B,0x31,0x20,0x00,0x00,0x00};
			byte[] temp = cborReader.ReadByteString();
			byte[] PuKx = new byte[keyHeader.Length + temp.Length-1];
			Array.Copy(keyHeader, 0, PuKx, 0, keyHeader.Length);
			// the first byte of temp is 0x04, it is a flag that indicate the key is uncompressioned
			Array.Copy(temp, 1, PuKx, keyHeader.Length, temp.Length-1);

			byte[] encryptedCx = cborReader.ReadByteString();
            #endregion

            CngKey cngKey = CngKey.Import(PuKx, CngKeyBlobFormat.EccPublicBlob);
			byte[] eccFullpublicblob = cngKey.Export(CngKeyBlobFormat.EccPublicBlob);

			paramBox.Text += "PuKx : " + BitConverter.ToString(eccFullpublicblob) + "\r\n";
			// generate sharedSecrect
			byte[] sharedSecrect = ECDH.DeriveKeyMaterial(cngKey);
			paramBox.Text += "SharedSecret : " + BitConverter.ToString(sharedSecrect) + "\r\n";

			// generate hashedSharedsecrect
			SHA256 sha256 = SHA256.Create();
			byte[] hashedSharedSecrect = sha256.ComputeHash(sharedSecrect);
			paramBox.Text += "sha256 SharedSecret : " + BitConverter.ToString(hashedSharedSecrect) + "\r\n";
			
			// make AES cipher
			byte[] IV = new byte[16];
			Array.Fill(IV, (byte)0);
			AesCng aes = new AesCng();
			aes.KeySize = 256;
			aes.Key = hashedSharedSecrect;
			aes.BlockSize = 128;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.None;
			aes.IV = IV;

			// decrypt cx
			byte[] decryptedCx = aes.DecryptCbc(encryptedCx, IV, PaddingMode.None);
			paramBox.Text += "Encrypted Cx : " + BitConverter.ToString(encryptedCx) + "\r\n";
			paramBox.Text += "Decrypted Cx : " + BitConverter.ToString(decryptedCx) + "\r\n";

			// generate HMAC <- AES(hashedSharedSecrect, sha256(IDx||Cx))
			byte[] IDxAndCx = new byte[IDx.Length + decryptedCx.Length];
			Array.Copy(Encoding.ASCII.GetBytes(IDx), 0, IDxAndCx, 0, IDx.Length);
			Array.Copy(decryptedCx, 0, IDxAndCx, IDx.Length, decryptedCx.Length);
			Debug.WriteLine(BitConverter.ToString(IDxAndCx));
			byte[] hashedIDxAndCx = sha256.ComputeHash(IDxAndCx);
			paramBox.Text += "hashedIDxAndCx : " + BitConverter.ToString(hashedIDxAndCx) + "\r\n";
			byte[] hmac = aes.EncryptCbc(hashedIDxAndCx, IV, PaddingMode.None);
			paramBox.Text += "hmac : " + BitConverter.ToString(hmac) + "\r\n";

			String hmacBase64 = Convert.ToBase64String(hmac);

            #region insert identity

            try {
				MySqlCommand insertNewIdentity = new MySqlCommand();
				insertNewIdentity.Connection = mySqlConnection;
				insertNewIdentity.CommandText = "INSERT INTO identities VALUES(default, @idx, @hmac, @hmacbase64, @cx, @hashedSharedSecrect,  @pukx, @pukp, @prkp )";
				insertNewIdentity.CommandType = CommandType.Text;
				insertNewIdentity.Parameters.Add("@idx", MySqlDbType.VarChar).Value = IDxBox.Text;
				insertNewIdentity.Parameters.Add("@hmac", MySqlDbType.VarBinary).Value = hmac;
				insertNewIdentity.Parameters.Add("@hmacbase64", MySqlDbType.VarChar).Value = hmacBase64; // for web api transmission
				insertNewIdentity.Parameters.Add("@cx", MySqlDbType.VarBinary).Value = decryptedCx;
				insertNewIdentity.Parameters.Add("@hashedSharedSecrect", MySqlDbType.VarBinary).Value = hashedSharedSecrect;
				insertNewIdentity.Parameters.Add("@pukx", MySqlDbType.VarBinary).Value = PuKx;
				insertNewIdentity.Parameters.Add("@pukp", MySqlDbType.VarBinary).Value = publicKey;
				insertNewIdentity.Parameters.Add("@prkp", MySqlDbType.VarBinary).Value = privateKey;
				int rowAffected = insertNewIdentity.ExecuteNonQuery();
				MessageBox.Show("row affected : "+rowAffected);
			} catch (Exception ex) {
				Debug.WriteLine(ex.ToString());
			} finally {
				if (mySqlConnection.State != ConnectionState.Closed)
					mySqlConnection.Close();
			}
            #endregion
        }

        protected override void OnFormClosing(FormClosingEventArgs e) {
            base.OnFormClosing(e);
			Debug.WriteLine("Form Closing");
			if(pcscContext != null)
				pcscContext.Dispose();
			if(pcscReader != null)
				pcscReader.Dispose();
        }

        private void getFreeSpace_Click(object sender, EventArgs e) {
			var getFreeSpaceCommand = new CommandApdu(IsoCase.Case2Short, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0xCA,
				P1P2 = 0xFF21
			};
			executecCommand(getFreeSpaceCommand);
		}

        private void getCredentialCount_Click(object sender, EventArgs e) {
			selectFIDOApplet_Click(sender, e);
			var command = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0x10,
				P1P2 = 0x0000,
				Data = new byte[] {0x45}
			};
			executecCommand(command);
		}

        private void resetCredentials_Click(object sender, EventArgs e) {
			selectFIDOApplet_Click(sender, e);
			var command = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0x10,
				P1P2 = 0x0000,
				Data = new byte[] { 0x07 }
			};
			executecCommand(command);
		}

        private void ClientPIN_getRetries_Click(object sender, EventArgs e) {
			selectFIDOApplet_Click(sender, e);

			CborWriter cborWriter = new CborWriter();
			cborWriter.WriteStartMap(2);
			// key : 0x01 : pinUvAuthProtocol
			cborWriter.WriteUInt32(1);
			// value : 0x01 : pinUvAuthProtocol 1
			cborWriter.WriteUInt32(1);
			// key : 0x02 : subCommand
			cborWriter.WriteUInt32(2);
			// value : 0x01 : getPinRetries
			cborWriter.WriteUInt32(1);
			cborWriter.WriteEndMap();
			byte[] commandCbor = cborWriter.Encode();
			byte[] commandData = new byte[commandCbor.Length + 1];
			commandData[0] = 0x06;
			Array.Copy(commandCbor, 0, commandData, 1, commandCbor.Length);
			Debug.WriteLine(BitConverter.ToString(commandData).Replace("-", " "));

            var command = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
                CLA = 0x80,
                INS = 0x10,
                P1P2 = 0x0000,
                Data = commandData
            };

			executecCommand(command);
        }

        private void ClientPIN_getKeyAgreement_Click(object sender, EventArgs e) {
			selectFIDOApplet_Click(sender, e);
			getKeyagreement_wrapping();
		}

		private CngKey getKeyagreement_wrapping() {

			CborWriter cborWriter = new CborWriter();
			cborWriter.WriteStartMap(2);
			// key : 0x01 : pinUvAuthProtocol
			cborWriter.WriteUInt32(1);
			// value : 0x01 : pinUvAuthProtocol 1
			cborWriter.WriteUInt32(1);
			// key : 0x02 : subCommand
			cborWriter.WriteUInt32(2);
			// value : 0x02 : getKeyAgreement
			cborWriter.WriteUInt32(2);
			cborWriter.WriteEndMap();
			byte[] commandCbor = cborWriter.Encode();
			byte[] commandData = new byte[commandCbor.Length + 1];
			commandData[0] = 0x06;
			Array.Copy(commandCbor, 0, commandData, 1, commandCbor.Length);
			Debug.WriteLine("get key agreement command data : "+BitConverter.ToString(commandData).Replace("-", ""));

			var command = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
				CLA = 0x80,
				INS = 0x10,
				P1P2 = 0x0000,
				Data = commandData
			};

			Response commandResponse = executecCommand(command);

			byte[] data = commandResponse.GetData();
			byte[] cborData = new byte[data.Length - 1];
			Array.Copy(data, 1, cborData, 0, cborData.Length);

			CborReader cborReader = new CborReader(cborData);
			cborReader.ReadStartMap();
			cborReader.ReadUInt32();
			cborReader.ReadStartMap();

			cborReader.ReadUInt32();
			cborReader.ReadUInt32();

			cborReader.ReadUInt32();
			cborReader.ReadInt32();

			cborReader.ReadInt32();
			cborReader.ReadUInt32();

			cborReader.ReadInt32();
			byte[] x = cborReader.ReadByteString();

			cborReader.ReadInt32();
			byte[] y = cborReader.ReadByteString();

			Debug.WriteLine("x.Length + y.Length : " + (x.Length + y.Length));


			// magic||length(in little endian)
			byte[] keyHeader = new byte[] { 0x45, 0x43, 0x4B, 0x31, 0x20, 0x00, 0x00, 0x00 };
			byte[] keyByteString = new byte[keyHeader.Length + x.Length + y.Length];
			Array.Copy(keyHeader, 0, keyByteString, 0, keyHeader.Length);
			Array.Copy(x, 0, keyByteString, keyHeader.Length, x.Length);
			Array.Copy(y, 0, keyByteString, keyHeader.Length + x.Length, y.Length);

			Debug.WriteLine(BitConverter.ToString(keyByteString).Replace('-', ' ')) ;

			CngKey cngKey = CngKey.Import(keyByteString, CngKeyBlobFormat.EccPublicBlob);

			return cngKey;
		}

        private void SetPIN_Click(object sender, EventArgs e) {
			if (pinBox.Text == "") {
				MessageBox.Show("pinBox is empty");
				return;
			}
			if (pinBox.Text.Length > 63) {
				MessageBox.Show("PIN length is too long");
				return;
			}
			if (pinBox.Text.Length < 4) {
				MessageBox.Show("PIN length is too short");
				return;
			}

            selectFIDOApplet_Click(sender, e);

            #region get sharedKey

            byte[] pinByteString = Encoding.UTF8.GetBytes(pinBox.Text);
			byte[] paddedPinByteString= new byte[64];
			Array.Fill<byte>(paddedPinByteString, 0x00);
			Array.Copy(pinByteString, 0, paddedPinByteString, 0, pinByteString.Length);
			Debug.WriteLine("padded pin byte string : " + BitConverter.ToString(paddedPinByteString));

			ECDiffieHellmanCng ECDH = new ECDiffieHellmanCng();
			ECDH.HashAlgorithm = CngAlgorithm.Sha256;
			ECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
			ECDH.GenerateKey(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

			CngKey peerKey = getKeyagreement_wrapping();

			#region bouncy castle testing
			//bouncyCastleTesting();
            #endregion

            byte[] sharedKey = ECDH.DeriveKeyMaterial(peerKey);

			Debug.WriteLine("Client PIN : sharedKey from pc : "+BitConverter.ToString(sharedKey).Replace("-",""));
			#endregion

			byte[] selfPublicKey = ECDH.PublicKey.ToByteArray();
			Debug.WriteLine("self public key : " + BitConverter.ToString(selfPublicKey).Replace("-",""));

			byte[] x = new byte[32];
			byte[] y = new byte[32];

			Array.Copy(selfPublicKey, 8, x, 0, x.Length);
			Array.Copy(selfPublicKey, 8+x.Length, y, 0, y.Length);
			Debug.WriteLine("self x : " + BitConverter.ToString(x).Replace("-", ""));
			Debug.WriteLine("self y : " + BitConverter.ToString(y).Replace("-", ""));


            #region encrypt the padded pin byte string

            byte[] newPinEnc = new byte[64];

			// make AES cipher
			byte[] IV = new byte[16];
			Array.Fill(IV, (byte)0);
			AesCng aes = new AesCng();
			aes.KeySize = 256;
			aes.Key = sharedKey;
			aes.BlockSize = 128;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.None;
			aes.IV = IV;

			newPinEnc =  aes.EncryptCbc(paddedPinByteString, IV, PaddingMode.None);

			Debug.WriteLine("newPinEnc from pc : " + BitConverter.ToString(newPinEnc).Replace("-", "")) ;

			#endregion

			byte[] commandCbor = clientPin_SetPin_cbor_generator(x, y, new byte[] { }, newPinEnc);

            byte[] commandData = new byte[commandCbor.Length + 1];
            commandData[0] = 0x06;
            Array.Copy(commandCbor, 0, commandData, 1, commandCbor.Length);
            Debug.WriteLine("command Data : " + BitConverter.ToString(commandData).Replace("-",""));

            var command = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
                CLA = 0x80,
                INS = 0x10,
                P1P2 = 0x0000,
                Data = commandData
            };

            executecCommand(command);

        }

		private byte[] GetKeyAgreementBC(X9ECParameters ecParams, System.Security.Cryptography.ECPoint publicKey, byte[] privateKey) {
			ECDomainParameters eCDomainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N);
			Org.BouncyCastle.Math.EC.ECCurve curve = eCDomainParameters.Curve;

			Org.BouncyCastle.Math.EC.ECPoint pubKey = curve.CreatePoint(new BigInteger(1, publicKey.X), new BigInteger(1, publicKey.Y));
			BigInteger privKey = new BigInteger(1, privateKey);

			ECPublicKeyParameters ecPubKeyParams = new ECPublicKeyParameters("ECDH", pubKey, SecObjectIdentifiers.SecP256r1);
			ECPrivateKeyParameters ecPrivKeyParams = new ECPrivateKeyParameters(privKey, eCDomainParameters);

			IBasicAgreement basicAgreement = AgreementUtilities.GetBasicAgreement("ECDH");
			basicAgreement.Init(ecPrivKeyParams);
			byte[] keyAgreement = basicAgreement.CalculateAgreement(ecPubKeyParams).ToByteArrayUnsigned();
			return keyAgreement;
		}

		private byte[] GetKeyAgreementExplicit(X9ECParameters ecParams, System.Security.Cryptography.ECPoint publicKey, byte[] privateKey) {
			ECDomainParameters eCDomainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N);
			Org.BouncyCastle.Math.EC.ECCurve curve = eCDomainParameters.Curve;

			Org.BouncyCastle.Math.EC.ECPoint pubKey = curve.CreatePoint(new BigInteger(1, publicKey.X), new BigInteger(1, publicKey.Y));
			BigInteger privKey = new BigInteger(1, privateKey);

			Org.BouncyCastle.Math.EC.ECPoint keyAgreementECPoint = pubKey.Multiply(privKey).Normalize();

			// get the x-coordernate to be key agreement
			byte[] keyAgreement = keyAgreementECPoint.XCoord.ToBigInteger().ToByteArrayUnsigned();
			return keyAgreement;
		}

		private void bouncyCastleTesting() {

			
            using (var ecdhAlice = new ECDiffieHellmanCng())
			using (var ecdhBob = new ECDiffieHellmanCng()) {
				// Generate Alice's private and public key
				ecdhAlice.HashAlgorithm = CngAlgorithm.Sha256;
				ecdhAlice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
				ecdhAlice.GenerateKey(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
				byte[] privateKeyAlice = ecdhAlice.ExportParameters(true).D;
				System.Security.Cryptography.ECPoint publicKeyAlice = ecdhAlice.ExportParameters(false).Q;

				// Generate Bob's private and public key
				ecdhBob.HashAlgorithm = CngAlgorithm.Sha256;
				ecdhBob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
				ecdhBob.GenerateKey(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
				byte[] privateKeyBob = ecdhBob.ExportParameters(true).D;
				System.Security.Cryptography.ECPoint publicKeyBob = ecdhBob.ExportParameters(false).Q;

				// Alice's key agreement
				byte[] keyAgreementAlice = GetKeyAgreementBC(NistNamedCurves.GetByName("P-256"), publicKeyBob, privateKeyAlice);
				byte[] keyAgreementSHA256Alice = SHA256.Create().ComputeHash(keyAgreementAlice);
				byte[] keyAgreementCngAlice = ecdhAlice.DeriveKeyMaterial(ecdhBob.PublicKey);
				Debug.WriteLine("Alice's raw key agreement (BC):        " + Hex.ToHexString(keyAgreementAlice));
				Debug.WriteLine("Alice's hashed key agreement (BC):     " + Hex.ToHexString(keyAgreementSHA256Alice));
				Debug.WriteLine("Alice's key agreement (.NET):          " + Hex.ToHexString(keyAgreementCngAlice));
				Debug.WriteLine("");

				// Bob's key agreement
				byte[] keyAgreementBob = GetKeyAgreementExplicit(NistNamedCurves.GetByName("P-256"), publicKeyAlice, privateKeyBob);
				byte[] keyAgreementSHA256Bob = SHA256.Create().ComputeHash(keyAgreementBob);
				byte[] keyAgreementCngBob = ecdhBob.DeriveKeyMaterial(ecdhAlice.PublicKey);
				Debug.WriteLine("Bob's raw key agreement (explicit):    " + Hex.ToHexString(keyAgreementBob));
				Debug.WriteLine("Bob's hashed key agreement (explicit): " + Hex.ToHexString(keyAgreementSHA256Bob));
				Debug.WriteLine("Bob's key agreement (.NET):            " + Hex.ToHexString(keyAgreementCngBob));
				Debug.WriteLine("");
			}
			
		}

		private byte[] clientPin_SetPin_cbor_generator(byte[] x, byte[] y, byte[] authParam, byte[] newPinEnc) {
			CborWriter cborWriter = new CborWriter();
			cborWriter.WriteStartMap(5);
			// key : 0x01 : pinUvAuthProtocol
			cborWriter.WriteUInt32(1);
			// value : 0x01 : pinUvAuthProtocol One
			cborWriter.WriteUInt32(1);

			// key : 0x02 : subCommand
			cborWriter.WriteUInt32(2);
			// value : 0x03 : setPIN
			cborWriter.WriteUInt32(3);

			// key : 0x03 : COSE Key
			cborWriter.WriteUInt32(3);
			// value : map : COSE Key
			cborWriter.WriteStartMap(5);
			#region cose key
			// key : 0x01 : kty
			cborWriter.WriteUInt32(1);
			// value : 0x02 : EC2
			cborWriter.WriteUInt32(2);

			// key : 0x03 : alg
			cborWriter.WriteInt32(3);
			// value : -7 : ES256
			// value : -25 : ECDH-ES + HKDF-256
			cborWriter.WriteInt32(-25);

			// key : -1 : crv
			cborWriter.WriteInt32(-1);
			// value : 0x01 : 
			cborWriter.WriteInt32(1);

			// key : -2 : x-coordinate
			cborWriter.WriteInt32(-2);
			// value : byteStirng
			cborWriter.WriteByteString(x);

			// key : -3 : y-coordinate
			cborWriter.WriteInt32(-3);
			// value : byteString
			cborWriter.WriteByteString(y);

			#endregion
			cborWriter.WriteEndMap();

			// key : 0x04 : pinUvAuthParam
			cborWriter.WriteUInt32(4);
			// value : byteString
			cborWriter.WriteByteString(authParam);

			// key : 0x05 : newPinEnc
			cborWriter.WriteUInt32(5);
			cborWriter.WriteByteString(newPinEnc);

			cborWriter.WriteEndMap();

			return cborWriter.Encode();
		}
    }
}