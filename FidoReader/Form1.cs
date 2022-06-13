using System.Diagnostics;
using PCSC;
using PCSC.Iso7816;
using Dahomey.Cbor;
using Dahomey.Cbor.ObjectModel;
using Jsbeautifier;
using Simulation;
using System.Security.Cryptography;
using System.Formats.Cbor;

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
			selectFIDOApplet_Click(sender, e);

			string IDx = "PRLab";

			ECDiffieHellmanCng ECDH = new ECDiffieHellmanCng();
			ECDH.HashAlgorithm = CngAlgorithm.Sha1;
			ECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
			ECDH.GenerateKey(ECCurve.NamedCurves.nistP256);// also named secp256r1
			byte[] publicKey = ECDH.PublicKey.ToByteArray();
			byte[] privateKey = ECDH.ExportECPrivateKey();
			
			paramBox.Text += "PuKp : " + BitConverter.ToString(publicKey) + "\r\n";
			
			Debug.WriteLine(BitConverter.ToString(publicKey));
			Debug.WriteLine(BitConverter.ToString(privateKey));
			Debug.WriteLine(BitConverter.ToString(ECDH.ExportPkcs8PrivateKey()));

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
			byte[] sharedSecrect = ECDH.DeriveKeyMaterial(cngKey);
			paramBox.Text += "SharedSecret : " + BitConverter.ToString(sharedSecrect) + "\r\n";

			SHA256 sha256 = SHA256.Create();
			byte[] hashedSharedSecrect = sha256.ComputeHash(sharedSecrect);
			paramBox.Text += "sha256 SharedSecret : " + BitConverter.ToString(hashedSharedSecrect) + "\r\n";
			
			byte[] IV = new byte[16];
			Array.Fill(IV, (byte)0);
			AesCng aes = new AesCng();
			aes.KeySize = 256;
			aes.BlockSize = 128;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.None;
			aes.IV = IV;
			aes.Key = hashedSharedSecrect;

			byte[] decryptedCx = aes.DecryptCbc(encryptedCx, IV, PaddingMode.None);
			paramBox.Text += "Encrypted Cx : " + BitConverter.ToString(encryptedCx) + "\r\n";
			paramBox.Text += "Decrypted Cx : " + BitConverter.ToString(decryptedCx) + "\r\n";
		}

        protected override void OnFormClosing(FormClosingEventArgs e) {
            base.OnFormClosing(e);
			Debug.WriteLine("Form Closing");
			pcscContext.Dispose();
			pcscReader.Dispose();
        }
    }
}