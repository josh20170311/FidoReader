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
			pcscReader = new IsoReader(context: pcscContext,readerName: readers[0],mode: SCardShareMode.Shared,protocol: SCardProtocol.Any);
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
			Response  responseCommand = executecCommand(getInfoCommnad);

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
			var dumpIDSecretCommand = new CommandApdu(IsoCase.Case4Short, pcscReader.ActiveProtocol) {
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
			int? length = cborReader.ReadStartArray();
			string IDx = cborReader.ReadTextString();
			byte[] Rx = cborReader.ReadByteString();
			byte[] Rp = cborReader.ReadByteString();
			byte[] RxRp = cborReader.ReadByteString();
			byte[] PuKp = cborReader.ReadByteString();
			byte[] sharedSecrect = cborReader.ReadByteString();
			byte[] aesRawKey = cborReader.ReadByteString();
			byte[] Cx = cborReader.ReadByteString();
			byte[] encryptedCx = cborReader.ReadByteString();
			this.Cx = Cx;
			Debug.WriteLine(BitConverter.ToString(PuKp));
			Debug.WriteLine(BitConverter.ToString(sharedSecrect));
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

			selectFIDOApplet_Click(sender, e);

			string IDx = IDxBox.Text;

			ECDiffieHellmanCng ECDH = new ECDiffieHellmanCng();
			ECDH.HashAlgorithm = CngAlgorithm.Sha1;
			ECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
			ECDH.GenerateKey(ECCurve.NamedCurves.nistP256);// also named secp256r1
			byte[] publicKey = ECDH.PublicKey.ToByteArray();
			byte[] privateKey = ECDH.ExportECPrivateKey();
			
			paramBox.Text += "PuKp : " + BitConverter.ToString(publicKey) + "\r\n";
			
			Debug.WriteLine(BitConverter.ToString(publicKey));
			Debug.WriteLine(BitConverter.ToString(privateKey));

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

            Response commandResponse = executecCommand(getPuKxCxCommand);

			data = commandResponse.GetData();
			if (data == null) {
				return;
			}
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

			try {
				MySqlCommand insertNewIdentity = new MySqlCommand();
				insertNewIdentity.Connection = mySqlConnection;
				insertNewIdentity.CommandText = "INSERT INTO identities VALUES(default, @idx, @hmac, @cx, @hashedSharedSecrect,  @pukx, @pukp, @prkp )";
				insertNewIdentity.CommandType = CommandType.Text;
				insertNewIdentity.Parameters.Add("@idx", MySqlDbType.VarChar).Value = IDxBox.Text;
				insertNewIdentity.Parameters.Add("@hmac", MySqlDbType.VarBinary).Value = hmac;
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
		}

        protected override void OnFormClosing(FormClosingEventArgs e) {
            base.OnFormClosing(e);
			Debug.WriteLine("Form Closing");
			pcscContext.Dispose();
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
    }
}